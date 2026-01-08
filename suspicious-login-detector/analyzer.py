import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from typing import List, Dict, Any

import config
from parsers import parse_log_file
from detectors import SuspiciousLoginDetector


class LogAnalyzer:
    def __init__(self):
        self.results: Dict[str, Any] = {}

    def analyze_directory(self, log_dir: Path) -> Dict[str, Any]:
        all_data = []

        for log_file in log_dir.glob("*.log"):
            print(f"Analyzing {log_file.name}...")
            df = parse_log_file(str(log_file))
            if not df.empty:
                all_data.append(df)

        if not all_data:
            return {}

        combined_df = pd.concat(all_data, ignore_index=True)
        self.results["combined_df"] = combined_df
        return self._run_full_analysis(combined_df)

    def _run_full_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        detector = SuspiciousLoginDetector(df)
        alerts = detector.run_all_detections()

        stats = {
            "total_requests": len(df),
            "unique_ips": df["ip"].nunique(),
            "error_rate": (
                len(df[df["status"] >= 400]) / len(df) * 100 if len(df) else 0
            ),
            "top_ips": df["ip"].value_counts().head(10).to_dict(),
            "top_paths": df["path"].value_counts().head(10).to_dict(),
            "alerts": alerts,
        }

        self.results["stats"] = stats
        self._generate_visualizations(df, alerts)
        return stats

    def _generate_visualizations(self, df: pd.DataFrame, alerts: List[Dict[str, Any]]):
        output_dir = Path(config.Config.OUTPUT_DIR)
        output_dir.mkdir(parents=True, exist_ok=True)

        plt.style.use("dark_background")
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle("Suspicious Login Activity Dashboard", fontsize=16)

        # Requests over time
        if "timestamp_parsed" in df.columns:
            (
                df.set_index("timestamp_parsed")
                .resample("5min")
                .size()
                .plot(ax=axes[0, 0])
            )
            axes[0, 0].set_title("Requests Over Time")

        # Status codes
        df["status"].value_counts().plot(kind="bar", ax=axes[0, 1])
        axes[0, 1].set_title("HTTP Status Codes")

        # Top IPs
        df["ip"].value_counts().head(10).plot(kind="bar", ax=axes[1, 0])
        axes[1, 0].set_title("Top 10 IPs")

        # Alerts by type
        if alerts:
            alert_types = pd.Series([a["type"] for a in alerts]).value_counts()
            alert_types.plot(kind="pie", ax=axes[1, 1], autopct="%1.1f%%")
            axes[1, 1].set_title("Alert Types")
        else:
            axes[1, 1].axis("off")

        plt.tight_layout()
        plt.savefig(output_dir / "dashboard.png", dpi=300, bbox_inches="tight")
        plt.close()
