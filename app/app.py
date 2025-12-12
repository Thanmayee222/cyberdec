from flask import Flask, request, render_template, jsonify, session
import uuid
import time
import json
from datetime import datetime
from utils.threat_detection import evaluate_threat
from utils.deception import generate_fake_content
import threading
import os
from flask import make_response


app = Flask(__name__)
app.secret_key = os.urandom(24)

# Simple in-memory storage for sessions and banned IPs
session_data = {}
banned_ips = set()

LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'session_logs.jsonl')  # ⭐ .jsonl = JSON Lines format


# -----------------------------------------------------------------------------
# Session helper
# -----------------------------------------------------------------------------
def initialize_session_if_needed():
    if 'session_id' not in session:
        # ⭐ stable UUID for this browser session
        session['session_id'] = str(uuid.uuid4())
        session['start_time'] = time.time()
        session['page_visits'] = 0
        session['form_submissions'] = 0
        session['last_activity'] = time.time()

    if session['session_id'] not in session_data:
        session_data[session['session_id']] = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'activities': [],
            'threat_score': 0.0
        }


# -----------------------------------------------------------------------------
# Activity logging
# -----------------------------------------------------------------------------
def log_activity(activity_type, data):
    initialize_session_if_needed()

    session['last_activity'] = time.time()

    activity = {
        'type': activity_type,
        'timestamp': datetime.utcnow().isoformat() + "Z",
        'data': data
    }

    # Update in-memory session record
    sess_id = session['session_id']
    if sess_id not in session_data:
        session_data[sess_id] = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'activities': [],
            'threat_score': 0.0
        }

    session_data[sess_id]['activities'].append(activity)

    # ⭐ Append one JSON object per line for easy analysis
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps({
                'session_id': sess_id,
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'activity': activity
            }) + '\n')
    except Exception as e:
        # In production you'd use proper logging; for now printing is fine
        print(f"[LOG ERROR] Error writing to log file: {e}")


def delayed_ban(ip, delay=5):
    """Ban an IP after a short delay to make it less obvious."""
    time.sleep(delay)
    banned_ips.add(ip)
    print(f"[BAN] IP banned: {ip}")


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route('/')
def index():
    if request.remote_addr in banned_ips:
        return "Access denied", 403

    initialize_session_if_needed()

    log_activity('page_visit', {'path': '/'})
    session['page_visits'] += 1

    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    if request.remote_addr in banned_ips:
        return "Access denied", 403

    initialize_session_if_needed()

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Log the submission (password length only for safety)
    log_activity('form_submission', {
        'form': 'login',
        'username': username,
        'password_length': len(password)
    })

    session['form_submissions'] += 1
    sess_id = session['session_id']

    # ⭐ Safe threat evaluation (don’t let it crash the route)
    try:
        threat_score = evaluate_threat(session_data[sess_id])
    except Exception as e:
        print(f"[THREAT ERROR] evaluate_threat failed: {e}")
        threat_score = 0.0

    session_data[sess_id]['threat_score'] = threat_score

    # If suspicious, show fake admin panel
    if threat_score > 0.6:
        # ⭐ Safe fake content generation
        try:
            fake_content = generate_fake_content('admin_panel', {
                'username': username,
                'threat_level': threat_score
            })
        except Exception as e:
            print(f"[DECEPTION ERROR] generate_fake_content failed: {e}")
            fake_content = "Error loading admin panel."

        # Highly suspicious: ban in background
        if threat_score > 0.8:
            threading.Thread(target=delayed_ban, args=(request.remote_addr,)).start()

        return render_template('fake_admin.html', content=fake_content)

    # Normal users get redirected to login failure
    return render_template('login_failed.html')


@app.route('/api/system/logs')
def fake_logs():
    if request.remote_addr in banned_ips:
        return "Access denied", 403

    initialize_session_if_needed()

    log_activity('page_visit', {'path': '/api/system/logs'})

    # Generate fake logs
    try:
        fake_logs = generate_fake_content('system_logs', {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')
        })
    except Exception as e:
        print(f"[DECEPTION ERROR] generate_fake_content logs failed: {e}")
        fake_logs = ["Error generating logs."]

    return render_template('fake_logs.html', logs=fake_logs)


@app.route('/admin/monitor')
def admin_monitor():
    # A real admin would use proper authentication.
    # This is just a simple demonstration.
    password = request.args.get('password', '')

    if password != 'supersecureadminpass':
        initialize_session_if_needed()
        log_activity('unauthorized_admin_access', {})

        sess_id = session['session_id']
        try:
            threat_score = evaluate_threat(session_data[sess_id])
        except Exception as e:
            print(f"[THREAT ERROR] evaluate_threat in admin_monitor failed: {e}")
            threat_score = 0.0

        session_data[sess_id]['threat_score'] = threat_score

        if threat_score > 0.7:
            threading.Thread(target=delayed_ban, args=(request.remote_addr,)).start()

        return "Unauthorized", 401

    # ⭐ JSON view for experiment analysis
    return jsonify({
        'sessions': session_data,
        'banned_ips': list(banned_ips)
    })

@app.route('/.well-known/internal-backup')
def canary():
    """
    Canary endpoint: normal users should never hit this.
    Any request here is treated as highly suspicious.
    """
    initialize_session_if_needed()
    log_activity('canary_access', {'path': request.path})

    sess_id = session['session_id']
    # Spike threat score for this session
    current = session_data[sess_id].get('threat_score', 0.0)
    session_data[sess_id]['threat_score'] = max(current, 0.9)

    return "Not found", 404
@app.route('/mark_suspicious')
def mark_suspicious():
    """
    Mark current session as suspicious and set a cookie which a
    reverse proxy can use to route this user to the deception app.
    """
    initialize_session_if_needed()
    sess_id = session['session_id']
    session_data[sess_id]['threat_score'] = 1.0
    log_activity('mark_suspicious', {})

    resp = make_response("Session marked as suspicious")
    resp.set_cookie('deception_route', '1', httponly=True)
    return resp

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    os.makedirs(LOG_DIR, exist_ok=True)
    app.run(debug=True)
from utils.deception import generate_fake_content
