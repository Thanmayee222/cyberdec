# Unit tests for honeypot
"""
Quick end-to-end test (run AFTER `python app.py` is live).
"""
import requests, json, random

sample_pkt = {
    "ip": f"10.0.0.{random.randint(2, 250)}",
    "url": "/admin",
    "payload": "DROP TABLE users;"
}

r = requests.post("http://127.0.0.1:5000/honeypot", json=sample_pkt, timeout=3)
print("Status:", r.status_code)
print(json.dumps(r.json(), indent=2))
