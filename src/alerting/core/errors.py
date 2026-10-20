"""Typed rejection and warning reasons.

One member per check in the verification pipeline. Reasons are data, not prose: the
client renders them, the audit log stores them, and tests assert on them.
"""

from __future__ import annotations

from enum import StrEnum


class Reason(StrEnum):
    """Why an envelope was rejected, or why it was accepted with a warning."""

    # --- structural ---------------------------------------------------------
    MALFORMED = "malformed"
    UNKNOWN_VERSION = "unknown_version"
    NOT_CANONICAL = "not_canonical"
    ORG_MISMATCH = "org_mismatch"

    # --- trust anchors ------------------------------------------------------
    DIRECTORY_UNSIGNED = "directory_unsigned"
    DIRECTORY_ROLLBACK = "directory_rollback"
    REVOCATIONS_UNSIGNED = "revocations_unsigned"
    REVOCATIONS_ROLLBACK = "revocations_rollback"
    POLICY_UNSIGNED = "policy_unsigned"
    POLICY_ROLLBACK = "policy_rollback"
    POLICY_ID_MISMATCH = "policy_id_mismatch"
    POLICY_EXPIRED = "policy_expired"

    # --- signatures and quorum ---------------------------------------------
    NO_SIGNATURES = "no_signatures"
    UNKNOWN_SIGNER = "unknown_signer"
    REVOKED_SIGNER = "revoked_signer"
    BAD_SIGNATURE = "bad_signature"
    DUPLICATE_SIGNER = "duplicate_signer"
    QUORUM_NOT_MET = "quorum_not_met"
    NOT_DISTINCT_PERSONS = "not_distinct_persons"
    ROLE_REQUIREMENT_UNMET = "role_requirement_unmet"
    UNAUTHORIZED_SIGNER_ROLE = "unauthorized_signer_role"
    SIGNATURE_SPREAD_EXCEEDED = "signature_spread_exceeded"

    # --- freshness ----------------------------------------------------------
    REPLAYED = "replayed"
    DUPLICATE_ORDER_ID = "duplicate_order_id"
    NOT_YET_VALID = "not_yet_valid"

    # --- semantics ----------------------------------------------------------
    DRILL_FLAG_MISSING = "drill_flag_missing"
    DRILL_MISMATCH = "drill_mismatch"
    UNKNOWN_SCENARIO = "unknown_scenario"
    SEVERITY_BELOW_SCENARIO_MINIMUM = "severity_below_scenario_minimum"
    SEVERITY_ABOVE_SCENARIO_MAXIMUM = "severity_above_scenario_maximum"
    CANCEL_TARGET_MISSING = "cancel_target_missing"
    CANCEL_TARGET_UNEXPECTED = "cancel_target_unexpected"

    # --- warnings (degrade OPEN: show loudly, but let the human act) --------
    W_EXPIRED = "warn_expired"
    W_OUT_OF_REPLAY_WINDOW = "warn_out_of_replay_window"
    W_STALE_DIRECTORY = "warn_stale_directory"
    W_CLOCK_SKEW = "warn_clock_skew"


class CanonicalizationError(ValueError):
    """The value cannot be canonicalized deterministically, so it must not be signed."""


class VerificationError(Exception):
    """Raised only by helpers that cannot return a Decision (bundle loading)."""
