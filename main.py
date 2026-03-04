"""QQ音乐解密工具 - 纯控制台版本

使用Frida调用QQMusicCommon.dll中的EncAndDesMediaFile类来解密加密音频文件
"""

import argparse
import json
import logging
import os
import time

from src.Helper.runtime_logging import (
    ensure_plugins_config,
    get_plugins_config_path,
    get_runtime_dir,
    setup_logging,
)
from src.Manager.qqmusic_decrypt import Decryptor_main


logger = logging.getLogger("qqmusic_decrypt.main")
DEFAULT_SETTINGS = {
    "input": "",
    "output": "",
    "del": False,
    "wheel": False,
}


def print_banner():
    """打印程序横幅"""
    banner = (
        "\n"
        "╔═════════════════════════════════════════╗\n"
        "║     QQ音乐加密文件解密器 v1.0.0        ║\n"
        "║           纯控制台版本                 ║\n"
        "╚═════════════════════════════════════════╝"
    )
    logger.info(banner)


def print_disclaimer():
    """打印免责声明"""
    disclaimer = (
        "\n"
        + "=" * 50
        + "\n免责声明\n"
        + "=" * 50
        + "\n本软件仅供学习交流使用，请勿用于商业用途"
        + "\n并且本软件纯属免费, 如付费购买，请立即退款并联系作者!"
        + "\n作者会帮你维权!"
        + "\n作者QQ: 2622138410"
        + "\n开源链接: https://gitee.com/daoges_x/QQMusic-mflac-to-flac"
        + "\n"
        + "=" * 50
        + "\n"
    )
    logger.info(disclaimer)


def load_settings(config_path):
    """从配置文件加载设置"""
    settings = DEFAULT_SETTINGS.copy()

    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            if isinstance(config, dict):
                settings.update(config)
            else:
                logger.warning("配置文件格式异常，已使用默认值: %s", config_path)
        except Exception:
            logger.exception("加载配置文件失败: %s", config_path)
    else:
        logger.info("配置文件不存在，使用默认配置: %s", config_path)

    return settings


def save_settings(settings, config_path):
    """保存设置到配置文件"""
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=4)
        logger.info("配置已保存到: %s", config_path)
    except Exception:
        logger.exception("保存配置文件失败: %s", config_path)


def interactive_mode(config_path):
    """交互式模式"""
    print_banner()
    print_disclaimer()

    settings = load_settings(config_path)

    # 获取输入目录
    if settings.get("input"):
        logger.info("上次使用的输入目录: %s", settings["input"])
        use_last = input("是否使用上次目录? (y/n): ").strip().lower()
        if use_last == "y":
            input_dir = settings["input"]
        else:
            input_dir = input("请输入QQ音乐下载目录路径: ").strip()
    else:
        input_dir = input("请输入QQ音乐下载目录路径: ").strip()

    # 获取输出目录
    if settings.get("output"):
        logger.info("上次使用的输出目录: %s", settings["output"])
        use_last = input("是否使用上次目录? (y/n): ").strip().lower()
        if use_last == "y":
            output_dir = settings["output"]
        else:
            output_dir = input("请输入输出目录路径: ").strip()
    else:
        output_dir = input("请输入输出目录路径: ").strip()

    # 询问是否删除原文件
    del_original = input("解密后删除原音频文件? (y/n): ").strip().lower() == "y"

    # 询问是否循环运行
    wheel_mode = input("循环运行模式? (y/n): ").strip().lower() == "y"

    logger.info(
        "交互模式参数: input=%s, output=%s, delete=%s, loop=%s",
        input_dir,
        output_dir,
        del_original,
        wheel_mode,
    )

    # 保存配置
    settings["input"] = input_dir
    settings["output"] = output_dir
    settings["del"] = del_original
    settings["wheel"] = wheel_mode
    save_settings(settings, config_path)

    # 执行解密
    logger.info("=" * 50)
    logger.info("开始解密...")
    logger.info("=" * 50)

    if wheel_mode:
        logger.info("循环运行模式已启用")
        logger.info("按 Ctrl+C 停止程序")

    try:
        while True:
            Decryptor_main(input_dir, output_dir, del_original)

            if not wheel_mode:
                break

            logger.info("等待5秒后继续...")
            time.sleep(5)

    except KeyboardInterrupt:
        logger.info("程序已停止")
    except Exception:
        logger.exception("程序运行发生错误")

    logger.info("程序结束")


def command_line_mode(args, config_path):
    """命令行模式"""
    print_banner()

    settings = load_settings(config_path)

    # 命令行参数优先
    input_dir = args.input or settings.get("input")
    output_dir = args.output or settings.get("output")
    del_original = args.delete or settings.get("del", False)
    wheel_mode = args.loop or settings.get("wheel", False)

    # 如果没有提供必要的参数，提示用户
    if not input_dir or not output_dir:
        logger.error("错误: 必须指定输入目录和输出目录")
        logger.error("使用 --help 查看帮助信息")
        return

    # 保存配置
    settings["input"] = input_dir
    settings["output"] = output_dir
    settings["del"] = del_original
    settings["wheel"] = wheel_mode
    save_settings(settings, config_path)

    # 执行解密
    logger.info("输入目录: %s", input_dir)
    logger.info("输出目录: %s", output_dir)
    logger.info("删除原文件: %s", del_original)
    logger.info("循环模式: %s", wheel_mode)

    if wheel_mode:
        logger.info("循环运行模式已启用")
        logger.info("按 Ctrl+C 停止程序")

    try:
        while True:
            Decryptor_main(input_dir, output_dir, del_original)

            if not wheel_mode:
                break

            logger.info("等待5秒后继续...")
            time.sleep(5)

    except KeyboardInterrupt:
        logger.info("程序已停止")
    except Exception:
        logger.exception("程序运行发生错误")


def main():
    """主函数"""
    app_logger = setup_logging("qqmusic_decrypt")
    config_path = get_plugins_config_path()
    ensure_plugins_config(DEFAULT_SETTINGS)

    app_logger.info("程序启动")
    app_logger.info("运行目录: %s", get_runtime_dir())
    app_logger.info("配置文件路径: %s", config_path)
    app_logger.info("日志文件路径: %s", getattr(app_logger, "log_file_path", ""))

    parser = argparse.ArgumentParser(
        description="QQ音乐加密文件解密器 - 纯控制台版本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 交互式模式
  python main.py

  # 命令行模式
  python main.py -i "C:\\QQMusicDownload" -o "C:\\Decrypted"

  # 解密后删除原文件
  python main.py -i "C:\\QQMusicDownload" -o "C:\\Decrypted" -d

  # 循环运行模式
  python main.py -i "C:\\QQMusicDownload" -o "C:\\Decrypted" -l
        """,
    )

    parser.add_argument("-i", "--input", help="QQ音乐下载目录路径")
    parser.add_argument("-o", "--output", help="输出目录路径")
    parser.add_argument(
        "-d",
        "--delete",
        action="store_true",
        help="解密后删除原音频文件",
    )
    parser.add_argument("-l", "--loop", action="store_true", help="循环运行模式")

    args = parser.parse_args()

    # 如果没有命令行参数，使用交互式模式
    if not (args.input or args.output or args.delete or args.loop):
        interactive_mode(config_path)
    else:
        command_line_mode(args, config_path)


if __name__ == "__main__":
    main()
