"""QQ音乐解密工具 - 纯控制台版本

使用Frida调用QQMusicCommon.dll中的EncAndDesMediaFile类来解密加密音频文件
"""

import argparse
import logging
import os
import time
import webbrowser

from src.Application.config_service import ConfigService
from src.Application.decrypt_job_service import DecryptJobService
from src.Application.format_policy_service import FormatPolicyService
from src.Helper.runtime_logging import (
    get_plugins_config_path,
    get_runtime_dir,
    setup_logging,
)
from src.Infrastructure.ffmpeg_transcoder import FfmpegTranscoder
from src.Infrastructure.filesystem_adapter import FileSystemAdapter
from src.Infrastructure.frida_decrypt_gateway import FridaDecryptGateway
from src.Infrastructure.local_config_repository import LocalConfigRepository


logger = logging.getLogger("qqmusic_decrypt.main")


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


def create_context(config_path: str):
    policy = FormatPolicyService()
    repository = LocalConfigRepository(config_path)
    config_service = ConfigService(repository, policy)
    settings = config_service.load()
    config_service.save(settings)

    transcoder = FfmpegTranscoder()
    if transcoder.available:
        logger.info("FFmpeg 检测结果: 可用")
        if transcoder.version_text:
            logger.info("FFmpeg 版本: %s", transcoder.version_text)
    else:
        logger.warning("FFmpeg 检测结果: 不可用")

    decrypt_service = DecryptJobService(
        decrypt_gateway=FridaDecryptGateway(),
        transcoder=transcoder,
        fs_adapter=FileSystemAdapter(),
        format_policy=policy,
    )
    return policy, config_service, settings, transcoder, decrypt_service


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    yes_values = {"y", "yes", "1"}
    no_values = {"n", "no", "0"}
    default_text = "y" if default else "n"
    while True:
        value = input(f"{prompt} (y/n, 默认 {default_text}): ").strip().lower()
        if not value:
            return default
        if value in yes_values:
            return True
        if value in no_values:
            return False
        logger.warning("输入无效，请输入 y 或 n")


def ask_custom_format_rules(policy: FormatPolicyService, current_rules: dict) -> dict:
    logger.info(
        "当前格式配置: mflac=%s, mgg=%s, mmp4=%s",
        current_rules.get("mflac"),
        current_rules.get("mgg"),
        current_rules.get("mmp4"),
    )

    if not ask_yes_no("是否自定义输出格式", default=False):
        return current_rules

    logger.info(
        "支持格式: %s",
        ",".join(sorted(policy.FORMAT_WHITELIST)),
    )
    updated = dict(current_rules)
    for src_ext in ["mflac", "mgg", "mmp4"]:
        default_fmt = updated.get(src_ext, policy.default_format(src_ext))
        value = input(
            f"设置 {src_ext} 输出格式（默认 {default_fmt}，留空保持默认）: "
        ).strip()
        if value:
            updated[src_ext] = value

    normalized = policy.normalize_rules(updated)
    logger.info(
        "更新后格式配置: mflac=%s, mgg=%s, mmp4=%s",
        normalized.get("mflac"),
        normalized.get("mgg"),
        normalized.get("mmp4"),
    )
    return normalized


def prompt_ffmpeg_missing() -> str:
    logger.warning("检测到需要转码，但当前系统未安装 FFmpeg")
    logger.warning("1. 跳转官网下载 FFmpeg 并退出本次任务")
    logger.warning("2. 本次仅解密不转码（回退默认格式）")
    while True:
        choice = input("请选择 [1/2]: ").strip()
        if choice == "1":
            webbrowser.open(FfmpegTranscoder.DOWNLOAD_URL)
            return "download_exit"
        if choice == "2":
            return "decrypt_only"
        logger.warning("输入无效，请输入 1 或 2")


def run_job_loop(
    decrypt_service: DecryptJobService,
    input_dir: str,
    output_dir: str,
    del_original: bool,
    wheel_mode: bool,
    format_rules: dict,
):
    logger.info("输入目录: %s", input_dir)
    logger.info("输出目录: %s", output_dir)
    logger.info("删除原文件: %s", del_original)
    logger.info("循环模式: %s", wheel_mode)
    logger.info(
        "格式配置: mflac=%s, mgg=%s, mmp4=%s",
        format_rules.get("mflac"),
        format_rules.get("mgg"),
        format_rules.get("mmp4"),
    )
    logger.info("=" * 50)
    logger.info("开始解密...")
    logger.info("=" * 50)

    if wheel_mode:
        logger.info("循环运行模式已启用")
        logger.info("按 Ctrl+C 停止程序")

    try:
        while True:
            success, message = decrypt_service.run(
                input_dir=input_dir,
                output_dir=output_dir,
                del_original=del_original,
                format_rules=format_rules,
                on_ffmpeg_missing=prompt_ffmpeg_missing,
            )
            if not success:
                logger.warning("任务中断: %s", message)
                break
            logger.info("任务结果: %s", message)

            if not wheel_mode:
                break
            logger.info("等待5秒后继续...")
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("程序已停止")
    except Exception:
        logger.exception("程序运行发生错误")


def interactive_mode(config_service: ConfigService, settings: dict, decrypt_service: DecryptJobService, policy: FormatPolicyService):
    """交互式模式"""
    print_banner()
    print_disclaimer()

    # 输入目录
    if settings.get("input"):
        logger.info("上次使用的输入目录: %s", settings["input"])
        use_last = ask_yes_no("是否使用上次输入目录", default=True)
        if use_last:
            input_dir = settings["input"]
        else:
            input_dir = input("请输入QQ音乐下载目录路径: ").strip()
    else:
        input_dir = input("请输入QQ音乐下载目录路径: ").strip()

    # 输出目录
    if settings.get("output"):
        logger.info("上次使用的输出目录: %s", settings["output"])
        use_last = ask_yes_no("是否使用上次输出目录", default=True)
        if use_last:
            output_dir = settings["output"]
        else:
            output_dir = input("请输入输出目录路径: ").strip()
    else:
        output_dir = input("请输入输出目录路径: ").strip()

    del_original = ask_yes_no("解密后删除原音频文件", default=bool(settings.get("del", False)))
    wheel_mode = ask_yes_no("循环运行模式", default=bool(settings.get("wheel", False)))
    format_rules = ask_custom_format_rules(policy, settings.get("format_rules", {}))

    settings["input"] = input_dir
    settings["output"] = output_dir
    settings["del"] = del_original
    settings["wheel"] = wheel_mode
    settings["format_rules"] = format_rules
    config_service.save(settings)

    run_job_loop(
        decrypt_service=decrypt_service,
        input_dir=input_dir,
        output_dir=output_dir,
        del_original=del_original,
        wheel_mode=wheel_mode,
        format_rules=format_rules,
    )
    logger.info("程序结束")


def command_line_mode(
    args,
    config_service: ConfigService,
    settings: dict,
    decrypt_service: DecryptJobService,
    policy: FormatPolicyService,
):
    """命令行模式"""
    print_banner()

    input_dir = args.input or settings.get("input")
    output_dir = args.output or settings.get("output")
    del_original = args.delete or settings.get("del", False)
    wheel_mode = args.loop or settings.get("wheel", False)

    format_overrides = {
        "mflac": args.format_mflac,
        "mgg": args.format_mgg,
        "mmp4": args.format_mmp4,
    }
    settings = config_service.apply_cli_format_overrides(settings, format_overrides)
    format_rules = settings.get("format_rules", policy.DEFAULT_RULES)

    if not input_dir or not output_dir:
        logger.error("错误: 必须指定输入目录和输出目录")
        logger.error("使用 --help 查看帮助信息")
        return

    settings["input"] = input_dir
    settings["output"] = output_dir
    settings["del"] = del_original
    settings["wheel"] = wheel_mode
    settings["format_rules"] = format_rules
    config_service.save(settings)

    run_job_loop(
        decrypt_service=decrypt_service,
        input_dir=input_dir,
        output_dir=output_dir,
        del_original=del_original,
        wheel_mode=wheel_mode,
        format_rules=format_rules,
    )


def main():
    app_logger = setup_logging("qqmusic_decrypt")
    config_path = get_plugins_config_path()
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

  # 自定义输出格式
  python main.py -i "C:\\QQMusicDownload" -o "C:\\Decrypted" --format-mflac mp3 --format-mgg ogg --format-mmp4 aac
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
    parser.add_argument("--format-mflac", help="mflac 输出格式（默认 flac）")
    parser.add_argument("--format-mgg", help="mgg 输出格式（默认 ogg）")
    parser.add_argument("--format-mmp4", help="mmp4 输出格式（默认 m4a）")

    args = parser.parse_args()
    policy, config_service, settings, transcoder, decrypt_service = create_context(config_path)

    # 如果没有命令行参数，使用交互式模式
    used_only_format_args = bool(args.format_mflac or args.format_mgg or args.format_mmp4)
    if not (args.input or args.output or args.delete or args.loop or used_only_format_args):
        interactive_mode(
            config_service=config_service,
            settings=settings,
            decrypt_service=decrypt_service,
            policy=policy,
        )
    else:
        command_line_mode(
            args=args,
            config_service=config_service,
            settings=settings,
            decrypt_service=decrypt_service,
            policy=policy,
        )


if __name__ == "__main__":
    main()

