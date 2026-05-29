from flask import Flask, render_template, jsonify
from prometheus_client import Counter, Histogram, generate_latest
from zapv2 import ZAPv2
from collections import Counter as DictCounter
import time
import datetime

app = Flask(__name__)

# ==========================================
# CONFIGURATION
# ==========================================

TARGETS = {
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "url": "http://juice-shop:3000"
    },
    "dvwa": {
        "name": "DVWA",
        "url": "http://dvwa"
    }
}

# ==========================================
# PROMETHEUS METRICS
# ==========================================

SCAN_COUNTER = Counter(
    "webautosec_scans_total",
    "Total scans performed"
)

HIGH_COUNTER = Counter(
    "webautosec_high_findings_total",
    "High severity findings"
)

SCAN_DURATION = Histogram(
    "webautosec_scan_duration_seconds",
    "Scan duration"
)

# ==========================================
# ZAP CLIENT
# ==========================================

zap = ZAPv2(
    apikey="",
    proxies={
        "http": "http://zap:8080",
        "https": "http://zap:8080"
    }
)

# ==========================================
# MEMORY STORAGE
# ==========================================

scan_history = []

# ==========================================
# HELPERS
# ==========================================

def calculate_priority(alert):

    risk = alert.get("risk", "Informational")
    confidence = alert.get("confidence", "Low")

    risk_score = {
        "High": 100,
        "Medium": 60,
        "Low": 20,
        "Informational": 5
    }

    confidence_score = {
        "High": 30,
        "Medium": 20,
        "Low": 10,
        "User Confirmed": 40
    }

    return (
        risk_score.get(risk, 0)
        + confidence_score.get(confidence, 0)
    )


def build_recommendation(alert_name):

    recommendations = {

        "Content Security Policy (CSP) Header Not Set":
            "Configure a Content Security Policy header.",

        "Cross-Domain Misconfiguration":
            "Restrict cross-origin access policies.",

        "Timestamp Disclosure - Unix":
            "Avoid exposing internal timestamps.",

        "Dangerous JS Functions":
            "Review and remove unsafe JavaScript functions.",

        "Information Disclosure - Suspicious Comments":
            "Remove sensitive comments from source code."
    }

    return recommendations.get(
        alert_name,
        "Review and remediate this finding."
    )

# ==========================================
# ROUTES
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/metrics")
def metrics():

    return generate_latest(), 200, {
        "Content-Type": "text/plain"
    }


@app.route("/targets")
def targets():

    return jsonify(TARGETS)


@app.route("/scan/<target_name>")
def scan(target_name):

    if target_name not in TARGETS:

        return jsonify({
            "success": False,
            "error": "Unknown target"
        }), 400

    target = TARGETS[target_name]["url"]
    zap.core.new_session()
    scan_id = zap.spider.scan(target)

    try:

        print(f"[*] Starting assessment for {target_name}")

        start_time = time.time()

        # ==================================
        # NEW SESSION
        # ==================================

        print("[*] Creating new session")

        zap.core.new_session()

        # ==================================
        # SPIDER
        # ==================================

        print("[*] Starting spider")

        scan_id = zap.spider.scan(target)

        while int(zap.spider.status(scan_id)) < 100:

            progress = zap.spider.status(scan_id)

            print(f"[Spider] {progress}%")

            time.sleep(1)

        print("[+] Spider completed")

        # ==================================
        # ACTIVE SCAN
        # ==================================

        print("[*] Starting active scan")

        ascan_id = zap.ascan.scan(target)

        while int(zap.ascan.status(ascan_id)) < 100:

            progress = zap.ascan.status(ascan_id)

            print(f"[Active Scan] {progress}%")

            time.sleep(2)

        print("[+] Active scan completed")

        alerts = zap.core.alerts(baseurl=target)
        # ==================================
        # AGGREGATION
        # ==================================

        grouped_findings = {}

        severity_counter = DictCounter()
        confidence_counter = DictCounter()
        alert_counter = DictCounter()
        endpoint_counter = DictCounter()

        findings = []

        for alert in alerts:

            alert_name = alert.get(
                "alert",
                "Unknown"
            )

            risk = alert.get(
                "risk",
                "Informational"
            )

            confidence = alert.get(
                "confidence",
                "Low"
            )

            url = alert.get(
                "url",
                "Unknown"
            )

            priority = calculate_priority(alert)

            severity_counter[risk] += 1
            confidence_counter[confidence] += 1
            alert_counter[alert_name] += 1
            endpoint_counter[url] += 1

            findings.append({

                "alert": alert_name,

                "risk": risk,

                "confidence": confidence,

                "url": url,

                "cweid": alert.get(
                    "cweid",
                    "N/A"
                ),

                "priority": priority
            })

            if alert_name not in grouped_findings:

                grouped_findings[
                    alert_name
                ] = {

                    "alert":
                        alert_name,

                    "risk":
                        risk,

                    "confidence":
                        confidence,

                    "priority":
                        priority,

                    "affected_urls":
                        set(),

                    "recommendation":
                        build_recommendation(
                            alert_name
                        )
                }

            grouped_findings[
                alert_name
            ][
                "affected_urls"
            ].add(url)

        # ==================================
        # TRIAGE
        # ==================================

        triage_findings = []

        for finding in grouped_findings.values():

            urls = list(
                finding["affected_urls"]
            )

            triage_findings.append({

                "alert":
                    finding["alert"],

                "risk":
                    finding["risk"],

                "confidence":
                    finding["confidence"],

                "priority":
                    finding["priority"],

                "count":
                    len(urls),

                "affected_urls":
                    sorted(urls),

                "recommendation":
                    finding["recommendation"]
            })

        triage_findings.sort(

            key=lambda x: (
                x["priority"],
                x["count"]
            ),

            reverse=True
        )

        findings.sort(

            key=lambda x:
                x["priority"],

            reverse=True
        )

        # ==================================
        # METRICS
        # ==================================

        duration = round(
            time.time() - start_time,
            2
        )

        high_count = severity_counter.get(
            "High",
            0
        )

        SCAN_COUNTER.inc()

        HIGH_COUNTER.inc(
            high_count
        )

        SCAN_DURATION.observe(
            duration
        )

        # ==================================
        # HISTORY
        # ==================================

        history_entry = {

            "timestamp":
                datetime.datetime.now()
                .strftime("%H:%M:%S"),

            "target":
                target_name,

            "total_alerts":
                len(alerts),

            "duration":
                duration
        }

        scan_history.append(
            history_entry
        )

        # Keep only latest 20 scans

        if len(scan_history) > 20:

            scan_history.pop(0)

        print(
            f"[+] Assessment completed ({duration}s)"
        )

        return jsonify({

            "success": True,

            "summary": {

                "target":
                    target_name,

                "total_alerts":
                    len(alerts),

                "scan_duration":
                    duration,

                "severity":
                    dict(
                        severity_counter
                    ),

                "confidence":
                    dict(
                        confidence_counter
                    )
            },

            "triage": {

                "top_findings":
                    triage_findings[:10]
            },

            "charts": {

                "top_alerts":
                    dict(
                        alert_counter.most_common(5)
                    ),

                "top_endpoints":
                    dict(
                        endpoint_counter.most_common(5)
                    )
            },

            "history":
                scan_history,

            "findings":
                findings[:20]
        })

    except Exception as e:

        print(
            f"[ERROR] {str(e)}"
        )

        return jsonify({

            "success": False,

            "error":
                str(e)

        }), 500


# ==========================================
# ENTRYPOINT
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
