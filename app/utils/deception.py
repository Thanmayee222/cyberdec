import json
import random
from datetime import datetime, timedelta

LEVELS = ["INFO", "WARN", "ERROR", "DEBUG"]
COMPONENTS = ["system", "auth", "db", "api", "scheduler", "cache"]
LOG_MESSAGES = [
    "Server started successfully",
    "Failed login attempt from {ip}",
    "Database connection established",
    "Rate limit exceeded for endpoint /api/users",
    "User {user} requested resource /admin/panel",
    "Background job 'sync_metrics' completed",
    "Unauthorized access attempt detected from {ip}",
    "Token expired for session {session_id}",
    "Connection timeout while reaching external service",
    "Cache miss for key user_profile:{user}",
]

def _fake_timestamp(base: datetime, i: int) -> str:
    """Generate a fake timestamp, each entry a few seconds apart."""
    ts = base + timedelta(seconds=i * random.randint(3, 40))
    return ts.strftime("%Y-%m-%d %H:%M:%S")

def _random_user(idx: int):
    names = ["admin", "jsmith", "mjones", "rkumar", "ali", "santos", "lee", "patel", "garcia", "nguyen"]
    domains = ["example.com", "corp.local", "internal.net"]
    username = random.choice(names) + str(random.randint(1, 99))
    email = f"{username}@{random.choice(domains)}"
    return {
        "id": str(idx),
        "username": username,
        "email": email,
        "role": random.choice(["administrator", "user", "auditor"])
    }

def _fake_hash():
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    return "$2a$12$" + "".join(random.choice(alphabet) for _ in range(22))

def generate_fake_content(content_type, context=None):
    """
    Generate fake content for deception WITHOUT external LLMs.

    Returned shapes:
      - 'admin_panel'   -> Python dict
      - 'system_logs'   -> list[str]
      - 'database_dump' -> str
    """
    if context is None:
        context = {}

    # ---------- ADMIN PANEL ----------
    if content_type == "admin_panel":
        username = context.get("username", "unknown")
        threat_level = float(context.get("threat_level", 0.0))

        users = []
        for i in range(1, random.randint(8, 15)):
            users.append(_random_user(i))

        panel = {
            "attacker": {
                "username": username,
                "estimated_threat_level": round(threat_level, 2),
            },
            "users": users,
            "system": {
                "version": "3.2." + str(random.randint(0, 9)),
                "last_backup": datetime.utcnow().isoformat() + "Z",
                "status": random.choice(["operational", "degraded", "maintenance"]),
                "active_tokens": random.randint(20, 100),
            }
        }
        return panel

    # ---------- SYSTEM LOGS ----------
    if content_type == "system_logs":
        ip = context.get("ip", "127.0.0.1")
        session_id = context.get("session_id", "sess-" + str(random.randint(1000, 9999)))
        base = datetime(2023, 4, 11, 8, 45, 23)

        logs = []
        n_lines = random.randint(15, 22)
        for i in range(n_lines):
            ts = _fake_timestamp(base, i)
            level = random.choice(LEVELS)
            component = random.choice(COMPONENTS)
            msg_template = random.choice(LOG_MESSAGES)
            msg = msg_template.format(ip=ip, session_id=session_id, user="user" + str(random.randint(1, 50)))
            logs.append(f"{ts} [{level}] {component}: {msg}")

        return logs

    # ---------- DATABASE DUMP ----------
    if content_type == "database_dump":
        lines = [
            "-- Fake database dump (for deception only)",
            "CREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(100), email VARCHAR(100), role VARCHAR(20));",
            "INSERT INTO users (id, username, password_hash, email, role) VALUES"
        ]
        values = []
        for i in range(1, random.randint(8, 15)):
            u = _random_user(i)
            values.append(
                f"({i}, '{u['username']}', '{_fake_hash()}', '{u['email']}', '{u['role']}')"
            )
        lines.append(",\n".join(values) + ";")

        lines.append("")
        lines.append("-- Fake config table")
        lines.append("CREATE TABLE config (key VARCHAR(50), value VARCHAR(255));")
        lines.append("INSERT INTO config (key, value) VALUES")
        cfg = [
            ("api_key_payment", "pk_live_" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(24))),
            ("jwt_secret", "".join(random.choice("abcdef0123456789") for _ in range(32))),
            ("backup_enabled", random.choice(["true", "false"])),
        ]
        cfg_values = [f"('{k}', '{v}')" for (k, v) in cfg]
        lines.append(",\n".join(cfg_values) + ";")

        return "\n".join(lines)

    # ---------- DEFAULT / UNKNOWN ----------
    # For any unknown type, just return something harmless.
    return {
        "message": "Unknown content type requested",
        "type": content_type
    }
