#!/usr/bin/env python3
"""
Console reporting utilities for anomaly detection results.
"""

from __future__ import annotations

from typing import Any, Dict, List


def print_summary(anomalies: List[Dict[str, Any]]) -> None:
    """
    Print a formatted table summary of anomalies.

    Columns: timestamp | src_ip | dst_ip | bytes | z_score
    """
    if not anomalies:
        print("No anomalies detected.")
        return

    header = f"{'timestamp':<20} | {'src_ip':<15} | {'dst_ip':<15} | {'bytes':>10} | {'z_score':>8}"
    separator = "─" * len(header)

    print(separator)
    print(header)
    print(separator)

    for record in anomalies:
        timestamp = str(record.get("timestamp", ""))
        src_ip = str(record.get("src_ip", ""))
        dst_ip = str(record.get("dst_ip", ""))
        bytes_val = record.get("bytes", 0)
        z_score = record.get("z_score", 0.0)

        print(
            f"{timestamp:<20} | "
            f"{src_ip:<15} | "
            f"{dst_ip:<15} | "
            f"{bytes_val:>10} | "
            f"{z_score:>8.2f}"
        )

    print(separator)
    print(f"Total anomalies: {len(anomalies)}")
