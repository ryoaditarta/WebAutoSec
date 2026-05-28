from zapv2 import ZAPv2
import time
import json

TARGET = "http://juice-shop:3000"

zap = ZAPv2(
    apikey='',
    proxies={
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080'
    }
)

print("[*] Accessing target...")
zap.urlopen(TARGET)

time.sleep(2)

print("[*] Starting spider...")
scan_id = zap.spider.scan(TARGET)

while int(zap.spider.status(scan_id)) < 100:
    print(f"[Spider] Progress: {zap.spider.status(scan_id)}%")
    time.sleep(2)

print("[+] Spider completed")

print("[*] Waiting for passive scan...")
time.sleep(5)

alerts = zap.core.alerts()

print(f"[+] Total alerts: {len(alerts)}")

with open("zap_alerts.json", "w") as f:
    json.dump(alerts, f, indent=4)

print("[+] Alerts saved to zap_alerts.json")


