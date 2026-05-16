"""
rule_engine.py — Rule-based threat classification.

Rules:
  attempts > 20 AND failed > 10  ->  HIGH  / Brute Force Attack
  failed > 5                     ->  MEDIUM / Suspicious Activity
  else                           ->  LOW   / Normal Activity
"""


def rule_based_detect(attempts: int, failed: int, event: str = "") -> dict:
    attempts = int(attempts or 0)
    failed   = int(failed   or 0)

    if attempts > 20 and failed > 10:
        return {"risk": "HIGH", "attack_type": "Brute Force Attack"}
    elif failed > 5:
        return {"risk": "MEDIUM", "attack_type": "Suspicious Activity"}
    else:
        return {"risk": "LOW", "attack_type": "Normal Activity"}
