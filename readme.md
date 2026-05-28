# WebAutoSec

WebAutoSec is a lightweight SOC-oriented web application security observability platform designed to automate vulnerability scanning, security telemetry collection, and attack visibility using containerized security tooling.

The platform integrates OWASP ZAP, Flask, Prometheus, and Grafana to simulate a centralized web application security monitoring environment capable of performing automated security assessment and telemetry visualization.

---

# Main Features

* Automated web vulnerability scanning using OWASP ZAP daemon API
* Containerized deployment architecture using Docker Compose
* Web-based security orchestration dashboard built with Flask
* Automated security telemetry collection and visualization
* Vulnerability classification based on:

  * Severity
  * Confidence level
  * Alert category
* Security findings visualization using:

  * Severity metrics
  * Vulnerability distribution charts
  * Scan history tracking
  * Top vulnerability statistics
* Prometheus metrics exporter integration
* Grafana-ready observability architecture
* Automated scan result processing using Python orchestration scripts
* JSON-based security report generation
* Detection visibility for common web security issues such as:

  * Cross-Site Scripting (XSS)
  * Security Misconfiguration
  * Missing Security Headers
  * Information Disclosure
  * Cross-Origin Misconfiguration
* Modular architecture designed for future integration with:

  * Grafana
  * Prometheus
  * Elasticsearch
  * Loki
  * Kafka

---

# Main Objective

The main objective of this project is to simulate a lightweight SOC-style web application security monitoring platform capable of:

* automating vulnerability scanning workflows
* centralizing security findings
* improving attack visibility
* visualizing security telemetry
* supporting faster security triage and investigation

---

# Use Cases

This platform can help security teams and students:

* reduce manual vulnerability assessment effort
* centralize vulnerability findings
* improve visibility of web application security issues
* monitor scan telemetry and security metrics
* experiment with security observability pipelines
* simulate basic AppSec and SOC monitoring workflows

---

# Technology Stack

* Python
* Flask
* OWASP ZAP
* Docker Compose
* Prometheus
* Grafana
* Chart.js

---

# Architecture

```text
Browser
   |
   v
WebAutoSec Dashboard (Flask)
   |
   +---- OWASP ZAP API
   |          |
   |          v
   |     Vulnerable Web Application
   |
   +---- Prometheus Metrics Exporter
              |
              v
         Prometheus
              |
              v
           Grafana
```

---

# Current Capabilities

* Automated OWASP ZAP spider scanning
* Passive vulnerability scanning
* Security findings aggregation
* Severity-based vulnerability metrics
* Scan history tracking
* Security telemetry export for Prometheus
* Dashboard visualization for security observability

---

# Future Improvements

* Active vulnerability scanning
* Real-time scan progress monitoring
* WebSocket-based live telemetry updates
* Multi-target scanning
* Authentication-aware scanning
* Database-backed scan history
* Kafka-based security event streaming
* Grafana dashboard embedding
* AI-assisted security triage
* Attack surface visualization
* SIEM integration support

---
