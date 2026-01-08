import json
import os
from datetime import datetime
from typing import List, Dict, Any


def print_banner():
    banner = """
========================================
  Suspicious Login Detector
  Log Analyzer & Alert Engine
========================================
"""
    print(banner)


def save_results(alerts: List[Dict[str, Any]], output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"alerts_{timestamp}.json")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4)

    return output_file


def print_summary(alerts: List[Dict[str, Any]]):
    print("\n========== Summary ==========")

    if not alerts:
        print("✅ No suspicious activity detected.")
        return

    counts = {}
    for alert in alerts:
        alert_type = alert.get("type", "UNKNOWN")
        counts[alert_type] = counts.get(alert_type, 0) + 1

    for alert_type, count in counts.items():
        print(f"{alert_type}: {count}")

    print("=============================\n")
