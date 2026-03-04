import json
import logging
import os
from datetime import datetime


def get_runtime_dir() -> str:
    return os.getcwd()


def get_plugins_config_path() -> str:
    return os.path.join(get_runtime_dir(), "plugins", "plugins.json")


def ensure_plugins_config(defaults: dict) -> dict:
    config_path = get_plugins_config_path()
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    if not os.path.exists(config_path):
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(defaults, f, ensure_ascii=False, indent=4)
        return defaults.copy()

    config = {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            config = loaded
        else:
            logging.getLogger("qqmusic_decrypt").warning(
                "配置文件格式不是对象，已重建默认配置: %s",
                config_path,
            )
    except Exception:
        logging.getLogger("qqmusic_decrypt").exception(
            "读取配置文件失败，已重建默认配置: %s",
            config_path,
        )

    changed = False
    merged = dict(config)
    for key, value in defaults.items():
        if key not in merged:
            merged[key] = value
            changed = True

    if not config:
        changed = True

    if changed:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, indent=4)

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

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

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
