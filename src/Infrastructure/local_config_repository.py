import json
import logging
import os
from typing import Any, Dict


logger = logging.getLogger("qqmusic_decrypt.infrastructure.config")


class LocalConfigRepository:
    """File-based repository for plugins configuration."""

    def __init__(self, config_path: str):
        self.config_path = config_path

    def load(self) -> Dict[str, Any]:
        if not os.path.exists(self.config_path):
            return {}

        try:
            with open(self.config_path, "r", encoding="utf-8") as file_obj:
                data = json.load(file_obj)
            if isinstance(data, dict):
                return data
            logger.warning("Config file is not a JSON object: %s", self.config_path)
            return {}
        except Exception:
            logger.exception("Failed to load config file: %s", self.config_path)
            return {}

    def save(self, data: Dict[str, Any]) -> None:
        directory = os.path.dirname(self.config_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as file_obj:
            json.dump(data, file_obj, ensure_ascii=False, indent=4)
