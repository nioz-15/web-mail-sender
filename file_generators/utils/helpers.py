import random
import string
from time import time
from datetime import datetime
from uuid import uuid5, NAMESPACE_URL


def generate_random_id() -> str:
    """Generate a random ID with letters and timestamp."""
    random_letters = ''.join(random.choices(string.ascii_uppercase, k=25))
    timestamp = str(int(time()))
    return f"{random_letters}-{timestamp}"


def stamp() -> float:
    """Return current timestamp."""
    return time()


def date_now() -> str:
    """Return formatted current datetime."""
    return datetime.now().strftime("%d%m%y_%H_%M_%S_%f")


def gen_response_id(now: str) -> str:
    """Generate response ID from datetime string."""
    return uuid5(NAMESPACE_URL, now).hex
