# LLM-based decoy content generation
from transformers import pipeline, set_seed
from utils.logger import get_logger

log = get_logger(__name__)

class DecoyGenerator:
    """
    Generates believable but fake narratives to distract attackers.
    Uses GPT-2 (small) so it installs quickly.
    """
    _pipe = None

    def __init__(self):
        if DecoyGenerator._pipe is None:        # load once globally
            log.info("Loading GPT-2 text-generation pipeline…")
            DecoyGenerator._pipe = pipeline("text-generation",
                                            model="gpt2",
                                            device=-1)  # CPU-safe
            set_seed(42)  # repeatable demos

    def generate_fake_data(self, prompt="User data:", length=50) -> str:
        out = self._pipe(prompt,
                         max_length=length,
                         num_return_sequences=1)[0]["generated_text"]
        return out.replace("\n", " ")
