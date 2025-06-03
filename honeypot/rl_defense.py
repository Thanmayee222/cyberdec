# Reinforcement learning-based decision maker
"""
Toy reinforcement-learning loop.
Every detected intrusion → one step in CartPole to keep policy updated.
Replace with real cyber-range environment if desired.
"""
from stable_baselines3 import PPO
import gymnasium as gym
from utils.logger import get_logger

log = get_logger(__name__)

class RLDefender:
    def __init__(self):
        self.env = gym.make("CartPole-v1")
        self.model = PPO("MlpPolicy", self.env, verbose=0)

    def update(self, _pkt):
        # run exactly one training step using a random rollout
        obs, info = self.env.reset()
        action, _ = self.model.predict(obs)
        obs, reward, terminated, truncated, info = self.env.step(action)
        self.model.learn(total_timesteps=1)     # fast single-step update
        log.debug("RL defender updated (reward=%s)", reward)
