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
            logger.warning("配置文件不是对象格式，忽略: %s", self.config_path)
            return {}
        except Exception:
            logger.exception("读取配置文件失败: %s", self.config_path)
            return {}

    def save(self, data: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as file_obj:
            json.dump(data, file_obj, ensure_ascii=False, indent=4)

