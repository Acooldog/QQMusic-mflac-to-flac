import logging
import os
import time
from typing import Callable, Dict, Optional, Tuple

from src.Application.format_policy_service import FormatPolicyService
from src.Infrastructure.ffmpeg_transcoder import FfmpegTranscoder
from src.Infrastructure.filesystem_adapter import FileSystemAdapter
from src.Infrastructure.frida_decrypt_gateway import FridaDecryptGateway


logger = logging.getLogger("qqmusic_decrypt.application.decrypt_job")


class DecryptJobService:
    """Orchestrate decrypt + optional transcode without changing core decrypt logic."""

    def __init__(
        self,
        decrypt_gateway: FridaDecryptGateway,
        transcoder: FfmpegTranscoder,
        fs_adapter: FileSystemAdapter,
        format_policy: FormatPolicyService,
    ):
        self.decrypt_gateway = decrypt_gateway
        self.transcoder = transcoder
        self.fs = fs_adapter
        self.policy = format_policy

    def run(
        self,
        input_dir: str,
        output_dir: str,
        del_original: bool,
        format_rules: Dict[str, str],
        on_ffmpeg_missing: Optional[Callable[[], str]] = None,
    ) -> Tuple[bool, str]:
        start_time = time.perf_counter()

        if not os.path.exists(input_dir):
            raise RuntimeError(f"QQ音乐下载目录不存在: {input_dir}")

        self.fs.ensure_dir(output_dir)
        tmp_base_dir = self.fs.pick_tmp_base_dir(output_dir)
        if tmp_base_dir != output_dir:
            logger.info("使用临时目录写入: %s", tmp_base_dir)

        processed_count = 0
        skipped_count = 0
        failed_count = 0

        # Run-level fallback switch when ffmpeg is missing.
        fallback_decrypt_only = False
        ffmpeg_prompted = False

        for file_path in self.fs.list_files(input_dir):
            entry = os.path.basename(file_path)
            base_name, ext = os.path.splitext(entry)
            src_ext = self.policy.normalize_source_ext(ext)
            if not self.policy.is_supported_source(src_ext):
                continue

            default_fmt = self.policy.default_format(src_ext)
            target_fmt = self.policy.target_format(src_ext, format_rules)
            needs_transcode = self.policy.needs_transcode(src_ext, target_fmt)

            if needs_transcode and not self.transcoder.available and not fallback_decrypt_only:
                if not ffmpeg_prompted:
                    ffmpeg_prompted = True
                    if on_ffmpeg_missing:
                        action = on_ffmpeg_missing()
                    else:
                        action = "decrypt_only"

                    if action == "download_exit":
                        logger.warning("用户选择下载 FFmpeg 并退出本次任务")
                        elapsed = time.perf_counter() - start_time
                        return (
                            False,
                            f"用户选择下载FFmpeg并退出，耗时 {elapsed:.2f} 秒",
                        )
                    fallback_decrypt_only = True
                    logger.warning("本次运行将仅解密不转码（FFmpeg 不可用）")

            effective_fmt = target_fmt
            if needs_transcode and (fallback_decrypt_only or not self.transcoder.available):
                effective_fmt = default_fmt
                needs_transcode = False

            final_name = f"{base_name}.{effective_fmt}"
            final_path = self.fs.build_path(output_dir, final_name)
            logger.info(
                "处理文件: %s | 源扩展=%s 默认=%s 目标=%s 转码=%s",
                file_path,
                src_ext,
                default_fmt,
                target_fmt,
                "是" if (self.policy.default_format(src_ext) != target_fmt and effective_fmt == target_fmt) else "否",
            )

            if self.fs.file_exists(final_path):
                logger.info("文件已存在，跳过处理: %s", final_path)
                if del_original:
                    try:
                        self.fs.remove_file(file_path)
                        logger.info("已删除原文件: %s", file_path)
                    except Exception as exc:
                        logger.warning("删除原文件失败: %s, %s", file_path, exc)
                skipped_count += 1
                continue

            decrypt_tmp_name = self.fs.make_tmp_file_name(final_name + ".decrypt", default_fmt)
            decrypt_tmp_path = self.fs.build_path(tmp_base_dir, decrypt_tmp_name)
            transcode_tmp_path = ""

            try:
                success = self.decrypt_gateway.decrypt_file(file_path, decrypt_tmp_path)
                if not success:
                    logger.error("解密失败: %s", file_path)
                    failed_count += 1
                    self.fs.remove_file(decrypt_tmp_path)
                    continue

                source_for_move = decrypt_tmp_path
                if self.policy.default_format(src_ext) != target_fmt and effective_fmt == target_fmt:
                    transcode_tmp_name = self.fs.make_tmp_file_name(final_name + ".transcode", target_fmt)
                    transcode_tmp_path = self.fs.build_path(tmp_base_dir, transcode_tmp_name)
                    transcode_success = self.transcoder.transcode(decrypt_tmp_path, transcode_tmp_path)
                    if not transcode_success:
                        logger.error("转码失败，跳过文件: %s", file_path)
                        failed_count += 1
                        self.fs.remove_file(decrypt_tmp_path)
                        self.fs.remove_file(transcode_tmp_path)
                        continue
                    source_for_move = transcode_tmp_path
                    self.fs.remove_file(decrypt_tmp_path)

                self.fs.move(source_for_move, final_path)
                logger.info("处理文件完成: %s", final_path)

                if del_original:
                    try:
                        self.fs.remove_file(file_path)
                        logger.info("已删除原文件: %s", file_path)
                    except Exception as exc:
                        logger.warning("删除原文件失败: %s, %s", file_path, exc)

                processed_count += 1
            except Exception as exc:
                logger.exception("处理文件失败: %s, %s", file_path, exc)
                failed_count += 1
                self.fs.remove_file(decrypt_tmp_path)
                if transcode_tmp_path:
                    self.fs.remove_file(transcode_tmp_path)

        elapsed = time.perf_counter() - start_time
        logger.info(
            "处理完成！成功: %s, 跳过: %s, 失败: %s, 耗时: %.2f 秒",
            processed_count,
            skipped_count,
            failed_count,
            elapsed,
        )
        return (
            True,
            f"成功处理 {processed_count} 个文件，跳过 {skipped_count} 个文件，失败 {failed_count} 个文件，耗时 {elapsed:.2f} 秒",
        )

