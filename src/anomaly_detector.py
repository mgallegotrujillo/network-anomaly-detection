#!/usr/bin/env python3
"""
Baseline anomaly detector for network traffic using simple z-score logic.
"""

from __future__ import annotations

import csv
import math
from typing import Any, Dict, List
import json
from datetime import datetime


def load_traffic_data(filepath: str) -> list[dict[str, Any]]:
    """
    Load network traffic records from a CSV file.
    Expected columns: timestamp, src_ip, dst_ip, protocol, bytes, duration
    """
    traffic: list[dict[str, Any]] = []

    with open(filepath, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            traffic.append(
                {
                    "timestamp": row["timestamp"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "protocol": row["protocol"],
                    "bytes": float(row["bytes"]),
                    "duration": float(row["duration"]),
                }
            )

    return traffic


def compute_baseline(traffic: list[dict[str, Any]]) -> dict[str, float]:
    """
    Compute baseline statistics for the bytes field.
    Returns mean_bytes and std_bytes.
    """
    if not traffic:
        return {"mean_bytes": 0.0, "std_bytes": 0.0}

    byte_values = [float(record["bytes"]) for record in traffic]
    mean_bytes = sum(byte_values) / len(byte_values)

    variance = sum((value - mean_bytes) ** 2 for value in byte_values) / len(byte_values)
    std_bytes = math.sqrt(variance)

    return {"mean_bytes": mean_bytes, "std_bytes": std_bytes}


def detect_anomalies(
    traffic: list[dict[str, Any]],
    baseline: dict[str, float],
    threshold: float = 2.0,
) -> list[dict[str, Any]]:
    """
    Detect anomalous traffic records where:
    bytes > mean_bytes + threshold * std_bytes
    """
    mean_bytes = baseline.get("mean_bytes", 0.0)
    std_bytes = baseline.get("std_bytes", 0.0)

    if std_bytes == 0:
        return []

    limit = mean_bytes + threshold * std_bytes
    anomalies = [record for record in traffic if float(record["bytes"]) > limit]

    return anomalies

def export_results(
    anomalies: List[Dict[str, Any]],
    output_path: str,
    metadata: Dict[str, Any] | None = None,
) -> None:
    """
    Export anomaly detection results to a JSON file.

    The output structure is:
    {
        "generated_at": "<ISO timestamp>",
        "total_anomalies": N,
        "metadata": {...},
        "anomalies": [...]
    }
    """
    payload: Dict[str, Any] = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "total_anomalies": len(anomalies),
        "metadata": metadata or {},
        "anomalies": anomalies,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
