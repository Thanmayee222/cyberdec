from flask import Flask, request, jsonify
from honeypot.agent import HoneypotAgent
from utils.logger import get_logger

log = get_logger(__name__)
app = Flask(__name__)
agent = HoneypotAgent()

@app.route("/honeypot", methods=["POST"])
def honeypot_listener():
    print(" Received POST request at /honeypot")  # Debug log
    data = request.get_json(force=True, silent=True) or {}
    print(" Data received:", data)
    log.info("Incoming request: %s", data)
    decision, response = agent.handle_intrusion(data)
    print(" Response:", decision, response)
    return jsonify({"decision": decision, "response": response}), 200

@app.route("/", methods=["GET"])
def index():
    return " Intelligent Cyber Deception System is running."

@app.route("/dashboard", methods=["GET"])
def dashboard():
    try:
        with open("honeypot.log", "r") as f:
            logs = f.read()
    except FileNotFoundError:
        logs = " No logs found yet."
    return f"<h2> Honeypot Logs</h2><pre>{logs}</pre>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
