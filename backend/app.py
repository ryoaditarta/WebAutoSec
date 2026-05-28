from flask import Flask, render_template, jsonify
from prometheus_client import Counter, Histogram, generate_latest
from zapv2 import ZAPv2
from collections import Counter as DictCounter
import time
import datetime

app = Flask(__name__)

SCAN_COUNTER = Counter(
    'webautosec_scans_total',
    'Total scans performed'
)

HIGH_COUNTER = Counter(
    'webautosec_high_findings_total',
    'High severity findings'
)

SCAN_DURATION = Histogram(
    'webautosec_scan_duration_seconds',
    'Scan duration'
)

TARGET = 'http://juice-shop:3000'

zap = ZAPv2(
    apikey='',
    proxies={
        'http': 'http://zap:8080',
        'https': 'http://zap:8080'
    }
)

scan_history = []

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {
        'Content-Type': 'text/plain'
    }

@app.route("/scan")
def scan():

    try:

        start_time = time.time()

        print("[*] Starting spider")

        scan_id = zap.spider.scan(TARGET)

        while int(zap.spider.status(scan_id)) < 100:

            print(
                f"Spider progress: {zap.spider.status(scan_id)}%"
            )

            time.sleep(1)

        print("[+] Spider completed")

        alerts = zap.core.alerts()

        severity_counter = DictCounter()
        confidence_counter = DictCounter()
        alert_counter = DictCounter()
        endpoint_counter = DictCounter()

        findings = []

        for alert in alerts:

            risk = alert.get("risk", "Informational")
            confidence = alert.get("confidence", "Low")
            alert_name = alert.get("alert", "Unknown")
            url = alert.get("url", "Unknown")

            severity_counter[risk] += 1
            confidence_counter[confidence] += 1
            alert_counter[alert_name] += 1
            endpoint_counter[url] += 1

            findings.append({
                "alert": alert_name,
                "risk": risk,
                "confidence": confidence,
                "url": url,
                "cweid": alert.get("cweid", "N/A")
            })

        duration = round(time.time() - start_time, 2)

        history_entry = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "total_alerts": len(alerts),
            "duration": duration
        }

        scan_history.append(history_entry)
        high_count = severity_counter.get("High", 0)
        SCAN_COUNTER.inc()
        HIGH_COUNTER.inc(high_count)
        SCAN_DURATION.observe(duration)

        return jsonify({

            "success": True,

            "summary": {
                "total_alerts": len(alerts),
                "scan_duration": duration,
                "severity": severity_counter,
                "confidence": confidence_counter
            },

            "charts": {
                "top_alerts": dict(alert_counter.most_common(5)),
                "top_endpoints": dict(endpoint_counter.most_common(5))
            },

            "history": scan_history,

            "findings": findings[:20]
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
