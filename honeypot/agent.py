# Multi-agent orchestration logic
from honeypot.deception_engine import DeceptionEngine
from honeypot.ml_models import IntrusionDetector
from honeypot.rl_defense import RLDefender
from utils.logger import get_logger

log = get_logger(__name__)

class HoneypotAgent:
    """
    Orchestrates detection, deception and reinforcement-learning feedback.
    """
    def __init__(self):
        self.detector = IntrusionDetector()
        self.deceiver = DeceptionEngine()
        self.rl = RLDefender()

    def handle_intrusion(self, packet: dict):
        """
        Returns (decision, response_payload)
        decision ∈ {"intrusion", "benign"}
        """
        is_bad = self.detector.is_intrusion(packet)
        decision = "intrusion" if is_bad else "benign"

        if is_bad:
            self.rl.update(packet)               # learn from attack
            response = self.deceiver.respond()   # craft fake data
        else:
            response = {"msg": "Request accepted."}

        log.info("Decision=%s | Response=%s", decision, response)
        return decision, response
