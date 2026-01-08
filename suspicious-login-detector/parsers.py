import os
import pandas as pd
from typing import List


def parse_log_file(path: str) -> pd.DataFrame:
    logs: List[dict] = []

    if os.path.isdir(path):
        for file in os.listdir(path):
            full_path = os.path.join(path, file)
            if os.path.isfile(full_path):
                logs.extend(_parse_single_file(full_path))
    else:
        logs.extend(_parse_single_file(path))

    if not logs:
        return pd.DataFrame()

    df = pd.DataFrame(logs)

    if 'timestamp' in df.columns:
        df['timestamp_parsed'] = pd.to_datetime(df['timestamp'], errors='coerce')

    return df


def _parse_single_file(file_path: str) -> List[dict]:
    entries = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Expected test log format:
            # timestamp ip method path status user_agent
            # Example:
            # 2024-01-01T10:00:00 192.168.1.10 POST /login 401 Mozilla/5.0

            parts = line.split(maxsplit=5)

            if len(parts) < 6:
                continue

            timestamp, ip, method, path, status, user_agent = parts

            try:
                status = int(status)
            except ValueError:
                continue

            entries.append({
                "timestamp": timestamp,
                "ip": ip,
                "method": method,
                "path": path,
                "status": status,
                "user_agent": user_agent
            })

    return entries
