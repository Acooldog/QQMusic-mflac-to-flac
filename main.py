import logging
import sys

from PyQt5.QtWidgets import QApplication

from src.Application.config_service import ConfigService
from src.Application.format_policy_service import FormatPolicyService
from src.Helper.runtime_logging import (
    ensure_plugins_config,
    get_plugins_config_path,
    get_runtime_dir,
    setup_logging,
)
from src.Infrastructure.local_config_repository import LocalConfigRepository
from src.UI.MainWindow.MainWindow import MainWindow


def bootstrap_runtime() -> logging.Logger:
    logger = setup_logging("qqmusic_decrypt")

    policy = FormatPolicyService()
    config_service = ConfigService(LocalConfigRepository(get_plugins_config_path()), policy)
    ensure_plugins_config(config_service.default_settings())

    logger.info("运行目录: %s", get_runtime_dir())
    logger.info("配置文件: %s", get_plugins_config_path())
    logger.info("日志文件: %s", getattr(logger, "log_file_path", ""))
    return logger


if __name__ == "__main__":
    logger = bootstrap_runtime()

    try:
        app = QApplication(sys.argv)
        app.setApplicationName("QQ音乐解密工具")
        app.setApplicationVersion("1.0.0")

        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except Exception:
        logger.exception("程序启动失败")
        raise
