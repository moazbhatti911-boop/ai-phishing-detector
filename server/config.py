"""Server settings, loaded from the environment / .env file."""
import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Configuration for the phishing detector server."""

    api_key: str = os.getenv("PHISH_API_KEY", "")
    server_url: str = os.getenv("PHISH_SERVER_URL", "http://127.0.0.1:8004")
    db_path: str = os.getenv("PHISH_DB_PATH", "phish.db")


settings = Settings()
