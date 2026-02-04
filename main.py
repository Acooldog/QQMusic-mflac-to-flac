"""QQ音乐解密工具 - 纯控制台版本

使用Frida调用QQMusicCommon.dll中的EncAndDesMediaFile类来解密加密音频文件
"""

import os
import json
import argparse
from src.Manager.qqmusic_decrypt import Decryptor_main

PLUGINS_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "plugins", "plugins.json")


def print_banner():
    """打印程序横幅"""
    banner = """
╔═════════════════════════════════════════╗
║     QQ音乐加密文件解密器 v1.0.0        ║
║           纯控制台版本                 ║
╚═════════════════════════════════════════╝
"""
    print(banner)


def print_disclaimer():
    """打印免责声明"""
    print("\n" + "="*50)
    print("免责声明")
    print("="*50)
    print("本软件仅供学习交流使用，请勿用于商业用途")
    print("并且本软件纯属免费, 如付费购买，请立即退款并联系作者!")
    print("作者会帮你维权!")
    print("作者QQ: 2622138410")
    print("开源链接: https://gitee.com/daoges_x/QQMusic-mflac-to-flac")
    print("="*50 + "\n")


def load_settings():
    """从配置文件加载设置"""
    settings = {
        "input": "",
        "output": "",
        "del": False,
        "wheel": False
    }

    if os.path.exists(PLUGINS_CONFIG_PATH):
        try:
            with open(PLUGINS_CONFIG_PATH, "r", encoding="utf-8") as f:
                config = json.load(f)
                settings.update(config)
        except Exception as e:
            print(f"[!] 加载配置文件失败: {e}")

    return settings


def save_settings(settings):
    """保存设置到配置文件"""
    try:
        os.makedirs(os.path.dirname(PLUGINS_CONFIG_PATH), exist_ok=True)
        with open(PLUGINS_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=4)
        print(f"[*] 配置已保存到: {PLUGINS_CONFIG_PATH}")
    except Exception as e:
        print(f"[!] 保存配置文件失败: {e}")


def interactive_mode():
    """交互式模式"""
    print_banner()
    print_disclaimer()

    settings = load_settings()

    # 获取输入目录
    if settings.get("input"):
        print(f"[*] 上次使用的输入目录: {settings['input']}")
        use_last = input("是否使用上次目录? (y/n): ").strip().lower()
        if use_last == 'y':
            input_dir = settings["input"]
        else:
            input_dir = input("请输入QQ音乐下载目录路径: ").strip()
    else:
        input_dir = input("请输入QQ音乐下载目录路径: ").strip()

    # 获取输出目录
    if settings.get("output"):
        print(f"[*] 上次使用的输出目录: {settings['output']}")
        use_last = input("是否使用上次目录? (y/n): ").strip().lower()
        if use_last == 'y':
            output_dir = settings["output"]
        else:
            output_dir = input("请输入输出目录路径: ").strip()
    else:
        output_dir = input("请输入输出目录路径: ").strip()

    # 询问是否删除原文件
    del_original = input("解密后删除原音频文件? (y/n): ").strip().lower() == 'y'

    # 询问是否循环运行
    wheel_mode = input("循环运行模式? (y/n): ").strip().lower() == 'y'

    # 保存配置
    settings["input"] = input_dir
    settings["output"] = output_dir
    settings["del"] = del_original
    settings["wheel"] = wheel_mode
    save_settings(settings)

    # 执行解密
    print("\n" + "="*50)
    print("开始解密...")
    print("="*50)

    if wheel_mode:
        print("[*] 循环运行模式已启用")
        print("[*] 按 Ctrl+C 停止程序\n")

    try:
        while True:
            Decryptor_main(input_dir, output_dir, del_original)

            if not wheel_mode:
                break

            print("\n[*] 等待5秒后继续...")
            import time
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[*] 程序已停止")
    except Exception as e:
        print(f"\n[!] 发生错误: {e}")
        import traceback
        traceback.print_exc()

    print("\n[*] 程序结束")


def command_line_mode(args):
    """命令行模式"""
    print_banner()

    settings = load_settings()

    # 命令行参数优先
    input_dir = args.input or settings.get("input")
    output_dir = args.output or settings.get("output")
    del_original = args.delete or settings.get("del", False)
    wheel_mode = args.loop or settings.get("wheel", False)

    # 如果没有提供必要的参数，提示用户
    if not input_dir or not output_dir:
        print("[!] 错误: 必须指定输入目录和输出目录")
        print("使用 --help 查看帮助信息\n")
        return

    # 保存配置
    settings["input"] = input_dir
    settings["output"] = output_dir
    settings["del"] = del_original
    settings["wheel"] = wheel_mode
    save_settings(settings)

    # 执行解密
    print(f"\n输入目录: {input_dir}")
    print(f"输出目录: {output_dir}")
    print(f"删除原文件: {del_original}")
    print(f"循环模式: {wheel_mode}\n")

    if wheel_mode:
        print("[*] 循环运行模式已启用")
        print("[*] 按 Ctrl+C 停止程序\n")

    try:
        while True:
            Decryptor_main(input_dir, output_dir, del_original)

            if not wheel_mode:
                break

            print("\n[*] 等待5秒后继续...")
            import time
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[*] 程序已停止")
    except Exception as e:
        print(f"\n[!] 发生错误: {e}")
        import traceback
        traceback.print_exc()


def main():
    """主函数"""
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
        """
    )

    parser.add_argument(
        '-i', '--input',
        help='QQ音乐下载目录路径'
    )
    parser.add_argument(
        '-o', '--output',
        help='输出目录路径'
    )
    parser.add_argument(
        '-d', '--delete',
        action='store_true',
        help='解密后删除原音频文件'
    )
    parser.add_argument(
        '-l', '--loop',
        action='store_true',
        help='循环运行模式'
    )

    args = parser.parse_args()

    # 如果没有命令行参数，使用交互式模式
    if not (args.input or args.output or args.delete or args.loop):
        interactive_mode()
    else:
        command_line_mode(args)


if __name__ == "__main__":
    main()
