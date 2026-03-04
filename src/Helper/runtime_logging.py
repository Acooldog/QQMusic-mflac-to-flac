import json
import logging
import os
from datetime import datetime
from typing import Any, Dict


def get_runtime_dir() -> str:
    return os.getcwd()


def get_plugins_config_path() -> str:
    return os.path.join(get_runtime_dir(), "plugins", "plugins.json")


def _merge_defaults(existing: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(existing)
    for key, default_value in defaults.items():
        if key not in merged:
            merged[key] = default_value
            continue

        if isinstance(default_value, dict) and isinstance(merged.get(key), dict):
            child = dict(merged[key])
            for child_key, child_default in default_value.items():
                child.setdefault(child_key, child_default)
            merged[key] = child
    return merged


def ensure_plugins_config(defaults: Dict[str, Any]) -> Dict[str, Any]:
    config_path = get_plugins_config_path()
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    if not os.path.exists(config_path):
        with open(config_path, "w", encoding="utf-8") as file_obj:
            json.dump(defaults, file_obj, ensure_ascii=False, indent=4)
        return dict(defaults)

    current: Dict[str, Any] = {}
    try:
        with open(config_path, "r", encoding="utf-8") as file_obj:
            loaded = json.load(file_obj)
        if isinstance(loaded, dict):
            current = loaded
        else:
            logging.getLogger("qqmusic_decrypt").warning(
                "Config file has invalid format, resetting defaults: %s",
                config_path,
            )
    except Exception:
        logging.getLogger("qqmusic_decrypt").exception(
            "Failed to read config file, resetting defaults: %s",
            config_path,
        )

    merged = _merge_defaults(current, defaults)
    if merged != current:
        with open(config_path, "w", encoding="utf-8") as file_obj:
            json.dump(merged, file_obj, ensure_ascii=False, indent=4)

    return merged


def setup_logging(app_name: str = "qqmusic_decrypt") -> logging.Logger:
    logger = logging.getLogger(app_name)
    if getattr(logger, "_configured_by_runtime_logging", False):
        return logger

    runtime_dir = get_runtime_dir()
    now = datetime.now()
    day_dir = f"{now.year}-{now.month}-{now.day}"
    log_dir = os.path.join(runtime_dir, "_log", day_dir)
    os.makedirs(log_dir, exist_ok=True)

    log_file_path = os.path.join(
        log_dir,
        f"run_{now.strftime('%H-%M-%S')}_pid{os.getpid()}.log",
    )

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    logger._configured_by_runtime_logging = True
    logger.log_file_path = log_file_path
    return logger
