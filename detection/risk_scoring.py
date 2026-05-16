"""
risk_scoring.py — Unified final risk calculation.

Combines Rule-Based engine + ML-Based prediction per Step 3 spec:

  IF rule HIGH OR ML HIGH  ->  HIGH
  ELIF ML MEDIUM           ->  MEDIUM
  ELSE                     ->  LOW

CRITICAL escalation:
  If same IP has >= 5 failed/denied events in DB -> final = CRITICAL

New inputs (Step 1):
  ip_change : 'yes' | 'no' | 'unknown'
  hours     : float | None  — time window in hours
"""

from .rule_engine import rule_based_detect
from .ml_detector  import ml_detect


def calculate_risk(
    attempts: int,
    failed: int,
    event: str = "",
    repeated_ip: bool = False,
    ip_fail_count: int = 0,
    ip_change: str = "unknown",
    hours: float = None,
) -> dict:
    """
    Run Rule-Based + ML detection and return unified result.

    Args:
        attempts:      total login attempts
        failed:        failed login attempts
        event:         raw event string (used by rule engine; empty OK)
        repeated_ip:   True if this IP has been seen before
        ip_fail_count: number of failed events for this IP in DB
        ip_change:     'yes' | 'no' | 'unknown'
        hours:         optional time window in hours (float or None)

    Returns:
        {
            "risk":        str,
            "attack_type": str,
            "score":       int,
            "ml_used":     bool,
            "ml_label":    int or None,
        }
    """
    attempts = max(0, int(attempts or 0))
    failed   = max(0, int(failed   or 0))
    failed   = min(failed, attempts)

    rule_result = rule_based_detect(attempts, failed, event)
    ml_result   = ml_detect(
        attempts=attempts,
        failed=failed,
        repeated_ip=repeated_ip,
        ip_change=ip_change,
        hours=hours,
    )

    rule_risk = rule_result["risk"]
    ml_risk   = ml_result["risk"]

    # Step 3 combination logic
    if rule_risk == "HIGH" or ml_risk == "HIGH":
        final_risk = "HIGH"
    elif ml_risk == "MEDIUM":
        final_risk = "MEDIUM"
    else:
        final_risk = "LOW"

    # CRITICAL escalation
    if ip_fail_count >= 5:
        final_risk = "CRITICAL"

    if final_risk == "CRITICAL":
        attack_type = "Brute Force Attack"
    else:
        attack_type = rule_result["attack_type"]

    return {
        "risk":        final_risk,
        "attack_type": attack_type,
        "score":       ml_result["score"],
        "ml_used":     ml_result["ml_used"],
        "ml_label":    ml_result["ml_label"],
    }
