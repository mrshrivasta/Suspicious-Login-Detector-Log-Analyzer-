import sys
import pandas as pd

from parsers import parse_log_file
from detectors import SuspiciousLoginDetector
from utils import print_banner, save_results, print_summary


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <log_file_or_directory>")
        sys.exit(1)

    log_path = sys.argv[1]

    print_banner()

    df = parse_log_file(log_path)

    if df.empty:
        print("No log entries found.")
        sys.exit(0)

    detector = SuspiciousLoginDetector(df)
    alerts = detector.run_all_detections()

    print_summary(alerts)

    output_file = save_results(alerts)
    print(f"\nAnalysis complete! Check '{output_file}' for details.")


if __name__ == "__main__":
    main()
