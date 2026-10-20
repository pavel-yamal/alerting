"""The trust decision.

Every client and the server run this same function over the same bytes. It returns a
``Decision`` whose two lists *are* the fail-closed/fail-open policy of the threat model,
expressed as a type:

* ``reasons``  — refuse. The order is not actionable.
* ``warnings`` — act, but show it loudly. Something is off, and a human decides.

The rule the split encodes: **verification never degrades open; delivery never degrades
closed.** A bad signature is never "probably fine". An expired TTL on an otherwise
valid order is never silently dropped, because silence is indistinguishable from no
emergency — and that is the failure mode that gets people hurt.

``verify_envelope`` does not mutate the replay window. The caller commits the sequence
number only after deciding to act, so a rejected envelope cannot poison the window.
"""

from __future__ import annotations

from collections.abc import Container
from dataclasses import dataclass, field

from pydantic import ValidationError

from alerting.core.canonical import canonicalize
from alerting.core.clock import SKEW_TOLERANCE_S, Clock
from alerting.core.directory import Directory, KeyEntry
from alerting.core.envelope import ENVELOPE_VERSION, OrderPayload, SignedEnvelope
from alerting.core.errors import CanonicalizationError, Reason
from alerting.core.policy import Policy
from alerting.core.quorum import QuorumResult, evaluate_quorum
from alerting.core.replay import ReplayChecker, ReplayVerdict


@dataclass(frozen=True)
class Decision:
    """The outcome of verification. ``accepted`` alone is never the whole story:
    an accepted order carrying warnings must be rendered differently."""

    accepted: bool
    reasons: tuple[Reason, ...] = ()
    warnings: tuple[Reason, ...] = ()
    valid_signers: tuple[str, ...] = ()
    signer_persons: tuple[str, ...] = ()
    is_drill: bool | None = None
    payload: OrderPayload | None = None
    quorum: QuorumResult | None = None
    detail: dict[str, object] = field(default_factory=dict)

    @property
    def rejected(self) -> bool:
        return not self.accepted


def _reject(*reasons: Reason, **kwargs: object) -> Decision:
    return Decision(accepted=False, reasons=tuple(dict.fromkeys(reasons)), **kwargs)  # type: ignore[arg-type]


def verify_envelope(
    envelope: SignedEnvelope,
    *,
    directory: Directory,
    policy: Policy,
    clock: Clock,
    replay: ReplayChecker,
    org_id: str,
    seen_order_ids: Container[str] = (),
    cancel_target: OrderPayload | None = None,
) -> Decision:
    """Verify a signed order or cancel end to end.

    Args:
        envelope: the wire object, payload exactly as received.
        directory: an already root-verified key directory.
        policy: an already root-verified policy.
        clock: injected time source.
        replay: per-stream window; inspected, never mutated here.
        org_id: the organisation this client belongs to.
        seen_order_ids: order ids already processed, for exact-duplicate
            suppression. Only ``in`` is used, so the server passes an object that
            answers it with one indexed query rather than a set of recent ids.
        cancel_target: the original order, when this is a cancel and we hold it.
            Needed to enforce that a drill envelope can never cancel a real order.
    """
    now = clock.now()

    # --- 1. structure, version, and canonical round-trip ---------------------
    try:
        payload = envelope.parse_payload()
    except ValidationError as exc:
        missing_drill = any(
            error["loc"] == ("drill",) and error["type"] == "missing" for error in exc.errors()
        )
        reason = Reason.DRILL_FLAG_MISSING if missing_drill else Reason.MALFORMED
        return _reject(reason, detail={"errors": exc.error_count()})

    if payload.v != ENVELOPE_VERSION:
        return _reject(Reason.UNKNOWN_VERSION)

    try:
        if canonicalize(envelope.payload) != payload.canonical_bytes():
            # The bytes we verified would not be the bytes we parsed.
            return _reject(Reason.NOT_CANONICAL)
    except CanonicalizationError:
        return _reject(Reason.NOT_CANONICAL)

    reasons: list[Reason] = []
    warnings: list[Reason] = []

    # --- 2. organisation -----------------------------------------------------
    if payload.org_id != org_id or directory.org_id != org_id:
        return _reject(Reason.ORG_MISMATCH, payload=payload, is_drill=payload.drill)

    # --- 3. directory freshness (warn only) ----------------------------------
    if directory.is_stale(now):
        warnings.append(Reason.W_STALE_DIRECTORY)

    # --- 4. policy binding ---------------------------------------------------
    if payload.policy_id != policy.policy_id:
        reasons.append(Reason.POLICY_ID_MISMATCH)
    if policy.is_expired(now):
        reasons.append(Reason.POLICY_EXPIRED)

    # --- 5. signatures -------------------------------------------------------
    valid_entries: list[KeyEntry] = []
    seen_key_ids: set[str] = set()
    if not envelope.signatures:
        reasons.append(Reason.NO_SIGNATURES)
    for signature in envelope.signatures:
        if signature.key_id in seen_key_ids:
            reasons.append(Reason.DUPLICATE_SIGNER)
            continue
        seen_key_ids.add(signature.key_id)

        status = directory.signer_status(signature.key_id, payload.issued_at)
        if status is not None:
            reasons.append(status)
            continue
        entry = directory.lookup(signature.key_id)
        assert entry is not None  # signer_status returned None, so it exists
        from alerting.core.signing import DOMAIN_ORDER, verify_signature

        if not verify_signature(DOMAIN_ORDER, envelope.payload, signature.sig, entry.public()):
            reasons.append(Reason.BAD_SIGNATURE)
            continue
        valid_entries.append(entry)

    # --- 6. quorum -----------------------------------------------------------
    rule = policy.rule_for(payload.severity, is_cancel=payload.is_cancel)
    quorum: QuorumResult | None = None
    if rule is None:
        reasons.append(Reason.QUORUM_NOT_MET)
    else:
        quorum = evaluate_quorum(
            valid_entries,
            rule,
            issued_at=payload.issued_at,
            approver_roles=policy.approver_roles,
        )
        if not quorum.met:
            reasons.extend(quorum.reasons)

    # --- 7. replay and duplicate suppression ---------------------------------
    verdict = replay.check(payload.stream_id, payload.seq)
    if verdict is ReplayVerdict.DUPLICATE:
        reasons.append(Reason.REPLAYED)
    elif verdict is ReplayVerdict.OUT_OF_WINDOW:
        # Too old to judge. Dropping it here would be a suppression primitive.
        warnings.append(Reason.W_OUT_OF_REPLAY_WINDOW)
    if payload.order_id in seen_order_ids:
        reasons.append(Reason.DUPLICATE_ORDER_ID)

    # --- 8. freshness --------------------------------------------------------
    if payload.issued_at > now + SKEW_TOLERANCE_S:
        reasons.append(Reason.NOT_YET_VALID)
    elif payload.issued_at > now:
        warnings.append(Reason.W_CLOCK_SKEW)
    if now > payload.not_valid_after + SKEW_TOLERANCE_S:
        # Degrade OPEN: show it with a loud banner, let the human verify by voice.
        warnings.append(Reason.W_EXPIRED)

    # --- 9. drill semantics --------------------------------------------------
    if payload.is_cancel:
        if cancel_target is None:
            warnings.append(Reason.CANCEL_TARGET_MISSING)
        elif cancel_target.drill != payload.drill:
            # A drill envelope must never stand down a real order, or vice versa.
            reasons.append(Reason.DRILL_MISMATCH)

    # --- 10. scenario and severity bounds ------------------------------------
    scenario = policy.scenario(payload.scenario)
    if scenario is None:
        reasons.append(Reason.UNKNOWN_SCENARIO)
    else:
        if scenario.min_severity is not None and payload.severity.rank < scenario.min_severity.rank:
            reasons.append(Reason.SEVERITY_BELOW_SCENARIO_MINIMUM)
        if scenario.max_severity is not None and payload.severity.rank > scenario.max_severity.rank:
            reasons.append(Reason.SEVERITY_ABOVE_SCENARIO_MAXIMUM)

    deduped = tuple(dict.fromkeys(reasons))

    # Report who actually *counted*, not merely who produced a verifiable signature.
    # The executor client prints this as "подписали:", and listing someone whose role
    # may not approve would tell the reader an executor authorised the order.
    if quorum is not None:
        counted_keys = quorum.signer_key_ids
        counted_persons = quorum.signer_person_ids
    else:
        counted_keys = tuple(entry.key_id for entry in valid_entries)
        counted_persons = tuple(dict.fromkeys(e.person_id for e in valid_entries))

    return Decision(
        accepted=not deduped,
        reasons=deduped,
        warnings=tuple(dict.fromkeys(warnings)),
        valid_signers=counted_keys,
        signer_persons=counted_persons,
        is_drill=payload.drill,
        payload=payload,
        quorum=quorum,
        detail={
            # Signatures that verified but whose role may not approve.
            "verified_but_not_counted": tuple(
                entry.key_id for entry in valid_entries if entry.key_id not in counted_keys
            )
        },
    )
