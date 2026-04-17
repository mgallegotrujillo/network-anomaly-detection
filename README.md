# network-anomaly-detection

> Statistical anomaly detection for industrial and IoT network traffic using Python.

![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![ML](https://img.shields.io/badge/ML-scikit--learn-orange)
![Status](https://img.shields.io/badge/status-active-brightgreen)

## Overview

Python framework for detecting anomalies in network traffic using statistical baselines and machine learning. Designed for industrial OT/IoT environments where traditional signature-based detection falls short.

Detects: port scans, volume spikes, new device pairs, protocol violations, and data exfiltration patterns.

## Features

- Statistical baseline with Welford online algorithm
- 5 built-in detection rules for OT/IoT traffic
- Isolation Forest (scikit-learn) for unsupervised anomaly detection
- Demo mode with synthetic traffic generator
- Modular — add custom detection rules easily

## Project Structure


## Author

**Mateo Gallego** — Mechatronic Engineer & OT Security Specialist

## License

MIT — see [LICENSE](LICENSE) for details.
