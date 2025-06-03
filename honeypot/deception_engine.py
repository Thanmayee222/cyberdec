# Logic for misleading attackers
from honeypot.decoy_data_generator import DecoyGenerator
from faker import Faker
import random

fake = Faker()

class DeceptionEngine:
    """
    Produces believable but useless data to mislead attackers.
    """
    def __init__(self):
        self.gen = DecoyGenerator()

    def _fake_credentials(self):
        return {
            "username": fake.user_name(),
            "password": fake.password(length=12)
        }

    def respond(self):
        # 50 % chance: AI-generated narrative, 50 %: fake creds
        if random.random() < 0.5:
            return {"decoy_story": self.gen.generate_fake_data()}
        return {"fake_credentials": self._fake_credentials()}
