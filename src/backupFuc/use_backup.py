from src.Manager.qqmusic_decrypt import QQMusicDecryptor

import os
import frida
import hashlib


def Decryptor_main(input_dir="", output_dir="", del_original=False):
    """主程序：解密QQ音乐下载的加密音频文件
    
    Args:
        input_dir: 输入目录（QQ音乐下载目录）
        output_dir: 输出目录
        del_original: 是否删除原始加密文件（.mflac/.mgg）
    """
    print(f"[*] 输入目录: {input_dir}")
    print(f"[*] 输出目录: {output_dir}")
    print(f"[*] 删除原文件: {del_original}")

    # 获取Frida版本和本地设备
    print(f"[*] Frida version: {frida.__version__}")
    device_manager = frida.get_device_manager()
    device = device_manager.get_local_device()
    print(f"[*] Device name: {device.name}")

    # 查找QQ音乐进程
    try:
        processes = device.enumerate_processes()
        qq_music_process = next(
            (p for p in processes if "qqmusic" in p.name.lower()),
            None
        )
        if not qq_music_process:
            raise RuntimeError("请先启动QQ音乐")

        print(f"[*] 找到QQ音乐进程: PID={qq_music_process.pid}")
    except Exception as e:
        raise RuntimeError(f"查找QQ音乐进程失败: {e}")

    # 附加到QQ音乐进程
    session = device.attach(qq_music_process.pid)

    # 初始化解密器（会自动查找并加载所需的函数）
    try:
        decryptor = QQMusicDecryptor(session)
    except Exception as e:
        print(f"[!] 初始化解密器失败: {e}")
        import traceback
        traceback.print_exc()
        return

    # 构造QQ音乐下载目录路径
    qq_music_dir = input_dir

    if not os.path.exists(qq_music_dir):
        raise RuntimeError(f"QQ音乐下载目录不存在: {qq_music_dir}")

    print(f"[*] QQ音乐目录: {qq_music_dir}")

    # 创建输出目录
    output_dir_path = output_dir
    if not os.path.exists(output_dir_path):
        os.makedirs(output_dir_path)
    print(f"[*] 输出目录: {output_dir_path}")

    # 遍历QQ音乐下载目录中的文件
    processed_count = 0
    skipped_count = 0

    for entry in os.listdir(qq_music_dir):
        file_path = os.path.join(qq_music_dir, entry)
        if not os.path.isfile(file_path):
            continue

        # 处理mflac和mgg文件
        _, ext = os.path.splitext(entry)
        if ext.lower() in [".mflac", ".mgg"]:
            # 映射文件扩展名：mflac→flac, mgg→ogg
            new_ext = "flac" if ext.lower() == ".mflac" else "ogg"
            base_name = os.path.splitext(entry)[0]
            new_file_name = base_name + "." + new_ext
            new_file_path = os.path.join(output_dir_path, new_file_name)

            # 跳过已存在的文件
            if os.path.exists(new_file_path):
                
                print(f"[*] 文件已存在: {new_file_path} 跳过处理")
                # 如果开启删除原文件
                if del_original:
                    try:
                        os.remove(file_path)
                        print(f"[*] 已删除原文件: {file_path}")
                    except Exception as e:
                        print(f"[!] 删除原文件失败: {file_path}, {e}")
                skipped_count += 1
                continue

            # 生成MD5哈希作为临时文件名
            md5_hash = hashlib.md5(new_file_name.encode()).hexdigest()
            tmp_file_path = os.path.join(output_dir_path, md5_hash)

            try:
                # 调用解密器进行解密
                success = decryptor.decrypt(file_path, tmp_file_path)

                if success:
                    # 重命名临时文件为最终文件名
                    os.rename(tmp_file_path, new_file_path)
                    print(f"[*] 处理文件: {new_file_path} 完成")

                    # 如果开启删除原文件
                    if del_original:
                        try:
                            os.remove(file_path)
                            print(f"[*] 已删除原文件: {file_path}")
                        except Exception as e:
                            print(f"[!] 删除原文件失败: {file_path}, {e}")

                    processed_count += 1
                else:
                    print(f"[!] 解密失败: {file_path}")
                    # 清理临时文件
                    if os.path.exists(tmp_file_path):
                        os.remove(tmp_file_path)

            except Exception as e:
                print(f"[!] 处理文件失败 {file_path}: {e}")
                # 清理临时文件
                if os.path.exists(tmp_file_path):
                    os.remove(tmp_file_path)

    print(f"\n[*] 处理完成！成功: {processed_count}, 跳过: {skipped_count}")
    return True, f"成功处理 {processed_count} 个文件，跳过 {skipped_count} 个文件"

# if __name__ == "__main__":
#     try:
#         Decryptor_main(r'C:\Users\01080\Music\VipSongsDownload', r'O:\A_python\A_QQd\output')
#     except Exception as e:
#         print(f"[!] 错误: {e}")
#         import traceback
#         traceback.print_exc()
