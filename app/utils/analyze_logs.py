# analyze_logs.py
import json
from collections import defaultdict

LOG_FILE = "logs/session_logs.jsonl"

def load_events():
    events = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events

def main():
    events = load_events()
    print(f"Total log lines: {len(events)}")

    sessions = defaultdict(lambda: {
        "ip": None,
        "user_agent": None,
        "page_visits": 0,
        "form_submissions": 0,
        "unauth_admin": 0,
        "activities": 0,
    })

    for e in events:
        sid = e.get("session_id", "unknown")
        ip = e.get("ip")
        ua = e.get("user_agent", "")
        activity = e.get("activity", {})
        atype = activity.get("type", "unknown")

        s = sessions[sid]
        if s["ip"] is None:
            s["ip"] = ip
        if not s["user_agent"]:
            s["user_agent"] = ua

        s["activities"] += 1
        if atype == "page_visit":
            s["page_visits"] += 1
        elif atype == "form_submission":
            s["form_submissions"] += 1
        elif atype == "unauthorized_admin_access":
            s["unauth_admin"] += 1

    print(f"Total sessions: {len(sessions)}")

    # Aggregate stats
    total_visits = sum(s["page_visits"] for s in sessions.values())
    total_forms = sum(s["form_submissions"] for s in sessions.values())
    total_unauth = sum(s["unauth_admin"] for s in sessions.values())

    print(f"Total page visits: {total_visits}")
    print(f"Total form submissions: {total_forms}")
    print(f"Total unauthorized admin attempts: {total_unauth}")

    if sessions:
        print(f"Avg page visits per session: {total_visits / len(sessions):.2f}")
        print(f"Avg form submissions per session: {total_forms / len(sessions):.2f}")

    # Optional: write CSV for your paper
    import csv
    with open("session_summary.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["session_id", "ip", "page_visits", "form_submissions", "unauthorized_admin_access"])
        for sid, s in sessions.items():
            writer.writerow([
                sid,
                s["ip"],
                s["page_visits"],
                s["form_submissions"],
                s["unauth_admin"],
            ])

    print("Wrote session_summary.csv (you can open this in Excel for tables/graphs).")

if __name__ == "__main__":
    main()
