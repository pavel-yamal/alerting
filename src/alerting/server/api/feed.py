"""The public RSS feed: real alerts and their stand-downs, for anyone to read.

What goes out is what a notice board would carry -- the event, its severity, the
instruction text and the time. Who the order was addressed to, who signed it and who
acknowledged stay behind the signed-request gate: the audience is the roster, and
the roster is personal data. Drills and canaries are never in the feed, so a reader
does not have to know about them to read it right.

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

#: Items in the feed. Readers keep what they have already seen; a stand-down that
#: scrolled out still closed its event in every reader that polled meanwhile.
DEFAULT_ITEMS = 50
MAX_ITEMS = 200

SEVERITY = {
    "info": "информация",
    "warning": "предупреждение",
    "critical": "критическая",
    "catastrophic": "катастрофическая",
}


def _describe(app: Any, scenario: str) -> str:
    rule = app.state.policy().scenario(scenario)
    return rule.description if rule and rule.description else scenario


def _item(app: Any, row: dict[str, Any]) -> dict[str, str]:
    payload = json.loads(row["envelope_json"])["payload"]
    severity = SEVERITY.get(row["severity"], row["severity"])
    text = payload.get("text", "")
    if row["cancels"]:
        target = app.repo.order(row["cancels"])
        what = _describe(app, target["scenario"]) if target else row["cancels"]
        title = f"ОТБОЙ: {what}"
        body = text or "Оповещение отменено."
    else:
        rule = app.state.policy().scenario(row["scenario"])
        title = f"{_describe(app, row['scenario'])} — {severity}"
        body = "\n\n".join(part for part in (text, rule.card if rule else "") if part)
    return {
        "title": title,
        "description": body,
        "guid": row["order_id"],
        "pubDate": formatdate(row["dispatched_at"], usegmt=True),
        "category": row["scenario"],
    }


def render(app: Any, limit: int) -> bytes:
    settings = app.settings
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    # ElementTree escapes every value: order text is free text typed by a person.
    for tag, value in (
        ("title", f"{settings.org_label}: оповещения"),
        ("link", "/v1/feed.rss"),
        ("description", "Боевые оповещения и отбои. Учения в ленту не попадают."),
        ("language", "ru"),
    ):
        ET.SubElement(channel, tag).text = value
    rows = app.repo.public_orders(limit)
    if rows:
        latest = formatdate(rows[0]["dispatched_at"], usegmt=True)
        ET.SubElement(channel, "lastBuildDate").text = latest
    for row in rows:
        item = ET.SubElement(channel, "item")
        fields = _item(app, row)
        for tag in ("title", "description", "category", "pubDate"):
            ET.SubElement(item, tag).text = fields[tag]
        ET.SubElement(item, "guid", isPermaLink="false").text = fields["guid"]
    data: bytes = ET.tostring(rss, encoding="utf-8", xml_declaration=True)
    return data


@router.get("/feed.rss")
async def feed(request: Request, limit: int = Query(DEFAULT_ITEMS, ge=1, le=MAX_ITEMS)) -> Response:
    return Response(render(request.app.state.alerting, limit), media_type="application/rss+xml")
