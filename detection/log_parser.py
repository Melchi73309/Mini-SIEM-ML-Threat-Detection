"""
log_parser.py — Parse raw log lines into structured events.

Supports two formats:
  Format 1: IP,STATUS
             e.g.  192.168.1.1,failed
  Format 2: Full log line (timestamp optional, IP auto-extracted)
             e.g.  [2024-01-15 10:23:45] 192.168.1.100 Failed SSH login attempt
"""

import re
from datetime import datetime


_IP_REGEX = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_TS_REGEX = re.compile(r'\[([^\]]+)\]')


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _extract_ip(text):
    m = _IP_REGEX.search(text)
    return m.group(1) if m else "0.0.0.0"


def _extract_timestamp(text):
    m = _TS_REGEX.search(text)
    return m.group(1) if m else _now()


def parse_line(line):
    """
    Parse a single log line into a dict:
      {
        "ip":       str,
        "event":    str,
        "attempts": int,
        "failed":   int,
      }
    Returns None for blank lines or comment lines.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if ',' in line and line.count(',') == 1:
        parts = [p.strip() for p in line.split(',', 1)]
        ip_part, status_part = parts[0], parts[1]
        if _IP_REGEX.fullmatch(ip_part):
            return {
                "ip":       ip_part,
                "event":    status_part,
                "attempts": 0,
                "failed":   0,
            }

    ip = _extract_ip(line)
    return {
        "ip":       ip,
        "event":    line,
        "attempts": 0,
        "failed":   0,
    }


def parse_log_content(content):
    """
    Parse a complete log file (string) into a list of event dicts.
    """
    results = []
    for line in content.splitlines():
        parsed = parse_line(line)
        if parsed:
            results.append(parsed)
    return results
