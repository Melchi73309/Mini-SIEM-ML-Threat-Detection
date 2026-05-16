"""
ml_detector.py — ML-based detection using the trained RandomForest model.

The model was trained with 7 features:
  login_attempts, access_hour, requests_per_min, ip_risk,
  device_change, geo_change, failed_logins

Feature mapping from Mini SIEM inputs:
  login_attempts   = attempts
  failed_logins    = failed
  access_hour      = current hour (0-23)
  requests_per_min = attempts (approximation)
  ip_risk          = 1 if repeated IP, else 0
  device_change    = 0 (not available from log)
  geo_change       = 1 if ip_change == 'yes', else 0

Scoring formula (Step 2 spec):
  score += attempts // 10 * 2
  score += failed // 5 * 3
  if ip_change == 'yes': score += 3
  if hours <= 1:  score += 3
  elif hours <= 3: score += 2

Model output: 0 = Normal, 1 = Suspicious/Threat
  prediction == 1 -> HIGH
  prediction == 0 -> LOW (rule-based handles MEDIUM)
"""

import os
import sys
from datetime import datetime

_MODEL_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model.pkl")
_model       = None
_model_error = None


def _load_model():
    global _model, _model_error
    if _model is not None:
        return _model
    try:
        import joblib
        _model = joblib.load(_MODEL_PATH)
    except Exception as e:
        _model_error = str(e)
        _model = None
    return _model


def ml_detect(
    attempts: int,
    failed: int,
    repeated_ip: bool = False,
    ip_change: str = "unknown",
    hours: float = None,
) -> dict:
    """
    Run ML prediction and return a risk dict.

    Args:
        attempts:    total login/connection attempts
        failed:      number of failed attempts
        repeated_ip: True if this IP has been seen before (risk indicator)
        ip_change:   'yes' | 'no' | 'unknown'  — whether IP changed recently
        hours:       optional time window in hours (float/int or None)

    Returns:
        {
          "risk":        "HIGH" | "MEDIUM" | "LOW",
          "score":       int,
          "ml_used":     bool,
          "ml_label":    int or None,
        }
    """
    attempts = max(0, int(attempts or 0))
    failed   = max(0, int(failed   or 0))
    failed   = min(failed, attempts)

    ip_change = (ip_change or "unknown").strip().lower()
    if ip_change not in ("yes", "no", "unknown"):
        ip_change = "unknown"

    if hours is not None:
        try:
            hours = float(hours)
            if hours < 0:
                hours = None
        except (TypeError, ValueError):
            hours = None

    access_hour      = datetime.now().hour
    requests_per_min = attempts
    ip_risk          = 1 if repeated_ip else 0
    device_change    = 0
    geo_change       = 1 if ip_change == "yes" else 0

    model    = _load_model()
    ml_label = None
    ml_risk  = None
    ml_used  = False

    if model is not None:
        try:
            import warnings
            import numpy as np
            features_arr = np.array([[
                attempts,
                access_hour,
                requests_per_min,
                ip_risk,
                device_change,
                geo_change,
                failed,
            ]])
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                prediction = int(model.predict(features_arr)[0])
            ml_label = prediction
            ml_used  = True

            if prediction == 1:
                ml_risk = "HIGH"
            else:
                ml_risk = "LOW"
        except Exception as e:
            print(f"ml_detect prediction error: {e}", file=sys.stderr)
            ml_risk = None

    if ml_risk is None:
        if attempts > 20 and failed > 10:
            ml_risk = "HIGH"
        elif failed > 5:
            ml_risk = "MEDIUM"
        else:
            ml_risk = "LOW"

    score = _compute_score(attempts, failed, ip_change, hours)

    return {
        "risk":     ml_risk,
        "score":    score,
        "ml_used":  ml_used,
        "ml_label": ml_label,
    }


def _compute_score(
    attempts: int,
    failed: int,
    ip_change: str = "unknown",
    hours: float = None,
) -> int:
    """
    Numeric risk score per Step 2 specification.

    score  = (attempts // 10) * 2
           + (failed   //  5) * 3
           + 3  if ip_change == 'yes'
           + 3  if hours <= 1
           + 2  if 1 < hours <= 3
    """
    score = 0
    score += (attempts // 10) * 2
    score += (failed   //  5) * 3

    if ip_change == "yes":
        score += 3

    if hours is not None:
        if hours <= 1:
            score += 3
        elif hours <= 3:
            score += 2

    return score
