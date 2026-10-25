"""The RSS feed: alerts and their stand-downs.

What goes out is what a notice board would carry -- the event, the instruction text
and the time. Who the order was addressed to, who signed it and who acknowledged stay
behind the signed-request gate: the audience is the roster, and the roster is personal
data. Canaries are never in the feed. Drills are in it only in RSS-only delivery
(``ALERTING_DELIVERY=rss``), where the feed is the only output, and then every drill
title starts with «УЧЕНИЕ». A stand-down names the guid of the alert it ends in
``alerting:cancels``. The structure is described in docs/17-rss-feed.md.

The feed is a view of orders that already dispatched, built per request from the
database. It is not a delivery channel and carries no promise about latency: a
reader polls it like any other feed.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from email.utils import formatdate
from typing import Any

from fastapi import APIRouter, Query, Request, Response

router = APIRouter(prefix="/v1", tags=["public"])

#: Atom, for the channel's link to itself -- what feed validators and readers expect.
ATOM_NS = "http://www.w3.org/2005/Atom"
#: This system's own elements. ``alerting:cancels`` on a stand-down carries the guid of
#: the alert it ends: the title alone cannot tell two events of one scenario apart.
ALERTING_NS = "urn:x-alerting:rss:1"
ET.register_namespace("atom", ATOM_NS)
ET.register_namespace("alerting", ALERTING_NS)

#: Items in the feed. Readers keep what they have already seen; a stand-down that
#: scrolled out still closed its event in every reader that polled meanwhile.
DEFAULT_ITEMS = 50
MAX_ITEMS = 200


def _describe(app: Any, scenario: str) -> str:
    rule = app.state.policy().scenario(scenario)
    return rule.description if rule and rule.description else scenario


def _item(app: Any, row: dict[str, Any]) -> dict[str, str]:
    payload = json.loads(row["envelope_json"])["payload"]
    text = payload.get("text", "")
    # A drill is in the feed only in RSS-only mode, and it must not be mistaken for
    # the real thing by anyone reading a headline.
    mark = "УЧЕНИЕ. " if row["drill"] else ""
    if row["cancels"]:
        target = app.repo.order(row["cancels"])
        what = _describe(app, target["scenario"]) if target else row["cancels"]
        title = f"{mark}ОТБОЙ: {what}"
        body = text or "Оповещение отменено."
    else:
        rule = app.state.policy().scenario(row["scenario"])
        title = f"{mark}{_describe(app, row['scenario'])}"
        body = "\n\n".join(part for part in (text, rule.card if rule else "") if part)
    return {
        "title": title,
        "description": body,
        "guid": row["order_id"],
        "pubDate": formatdate(row["dispatched_at"], usegmt=True),
        "category": row["scenario"],
        "cancels": row["cancels"] or "",
    }


def render(app: Any, limit: int, self_url: str) -> bytes:
    """``self_url``: the feed's absolute address, which the channel links to."""
    settings = app.settings
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    # ElementTree escapes every value: order text is free text typed by a person.
    for tag, value in (
        ("title", f"{settings.org_label}: оповещения"),
        # RSS wants an absolute URL here; "/v1/feed.rss" was refused by readers.
        ("link", self_url),
        (
            "description",
            "Оповещения и отбои; учения помечены «УЧЕНИЕ»."
            if settings.rss_only
            else "Боевые оповещения и отбои. Учения в ленту не попадают.",
        ),
        ("language", "ru"),
    ):
        ET.SubElement(channel, tag).text = value
    ET.SubElement(
        channel, f"{{{ATOM_NS}}}link", href=self_url, rel="self", type="application/rss+xml"
    )
    rows = app.repo.public_orders(limit, drills=settings.rss_only)
    if rows:
        latest = formatdate(rows[0]["dispatched_at"], usegmt=True)
        ET.SubElement(channel, "lastBuildDate").text = latest
    for row in rows:
        item = ET.SubElement(channel, "item")
        fields = _item(app, row)
        for tag in ("title", "description", "category", "pubDate"):
            ET.SubElement(item, tag).text = fields[tag]
        ET.SubElement(item, "guid", isPermaLink="false").text = fields["guid"]
        if fields["cancels"]:
            ET.SubElement(item, f"{{{ALERTING_NS}}}cancels").text = fields["cancels"]
    data: bytes = ET.tostring(rss, encoding="utf-8", xml_declaration=True)
    return data


def feed_url(request: Request) -> str:
    """Where readers fetch this feed: ALERTING_PUBLIC_URL if set, else this request's
    own host -- which behind a proxy that rewrites the scheme reads http://."""
    public = request.app.state.alerting.settings.public_url
    return f"{public}/v1/feed.rss" if public else str(request.url_for("feed"))


@router.get("/feed.rss")
async def feed(request: Request, limit: int = Query(DEFAULT_ITEMS, ge=1, le=MAX_ITEMS)) -> Response:
    body = render(request.app.state.alerting, limit, feed_url(request))
    return Response(body, media_type="application/rss+xml")
