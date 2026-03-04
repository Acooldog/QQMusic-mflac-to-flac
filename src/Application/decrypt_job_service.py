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
    """Orchestrate scan -> decrypt -> optional transcode -> cleanup."""

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

    @staticmethod
    def _emit(on_log: Optional[Callable[[str], None]], message: str) -> None:
        if on_log:
            on_log(message)

    def _iter_supported_files(self, input_dir: str):
        for file_path in self.fs.list_files(input_dir):
            ext = os.path.splitext(file_path)[1]
            src_ext = self.policy.normalize_source_ext(ext)
            if self.policy.is_supported_source(src_ext):
                yield file_path, src_ext

    def requires_transcode(self, input_dir: str, format_rules: Dict[str, str]) -> bool:
        if not os.path.isdir(input_dir):
            return False

        normalized_rules = self.policy.normalize_rules(format_rules or {})
        for _, src_ext in self._iter_supported_files(input_dir):
            target_fmt = self.policy.target_format(src_ext, normalized_rules)
            if self.policy.needs_transcode(src_ext, target_fmt):
                return True
        return False

    def run(
        self,
        input_dir: str,
        output_dir: str,
        del_original: bool,
        format_rules: Dict[str, str],
        on_ffmpeg_missing: Optional[Callable[[], str]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        start_time = time.perf_counter()

        if not os.path.isdir(input_dir):
            raise RuntimeError(f"输入目录不存在: {input_dir}")

        normalized_rules = self.policy.normalize_rules(format_rules or {})
        self.fs.ensure_dir(output_dir)

        tmp_base_dir = self.fs.pick_tmp_base_dir(output_dir)
        if tmp_base_dir != output_dir:
            msg = f"[*] 使用临时写入目录: {tmp_base_dir}"
            logger.info(msg)
            self._emit(on_log, msg)

        processed_count = 0
        skipped_count = 0
        failed_count = 0

        fallback_decrypt_only = False
        ffmpeg_prompted = False

        for file_path, src_ext in self._iter_supported_files(input_dir):
            entry = os.path.basename(file_path)
            base_name = os.path.splitext(entry)[0]

            default_fmt = self.policy.default_format(src_ext)
            requested_fmt = self.policy.target_format(src_ext, normalized_rules)
            will_transcode = self.policy.needs_transcode(src_ext, requested_fmt)

            if will_transcode and not self.transcoder.available:
                if not ffmpeg_prompted:
                    ffmpeg_prompted = True
                    action = on_ffmpeg_missing() if on_ffmpeg_missing else "decrypt_only"
                    if action == "download_exit":
                        msg = "[!] 用户选择下载 FFmpeg 并退出"
                        logger.warning(msg)
                        self._emit(on_log, msg)
                        elapsed = time.perf_counter() - start_time
                        return False, f"用户选择下载 FFmpeg 并退出，耗时 {elapsed:.2f} 秒"

                    fallback_decrypt_only = True
                    msg = "[!] FFmpeg 不可用，本次任务将仅解密不转码"
                    logger.warning(msg)
                    self._emit(on_log, msg)

            effective_fmt = requested_fmt
            if will_transcode and (fallback_decrypt_only or not self.transcoder.available):
                effective_fmt = default_fmt
                will_transcode = False

            final_name = f"{base_name}.{effective_fmt}"
            final_path = self.fs.build_path(output_dir, final_name)

            file_plan_message = (
                f"[*] 文件决策: {entry} | 源={src_ext} 默认={default_fmt} "
                f"目标={requested_fmt} 实际={effective_fmt} 转码={'是' if will_transcode else '否'}"
            )
            logger.info(file_plan_message)
            self._emit(on_log, file_plan_message)

            if self.fs.file_exists(final_path):
                msg = f"[*] 目标文件已存在，跳过: {final_path}"
                logger.info(msg)
                self._emit(on_log, msg)

                if del_original:
                    try:
                        self.fs.remove_file(file_path)
                        delete_msg = f"[*] 已删除原始文件: {file_path}"
                        logger.info(delete_msg)
                        self._emit(on_log, delete_msg)
                    except Exception as exc:
                        warn_msg = f"[!] 删除原始文件失败: {file_path}, {exc}"
                        logger.warning(warn_msg)
                        self._emit(on_log, warn_msg)

                skipped_count += 1
                continue

            decrypt_tmp_name = self.fs.make_tmp_file_name(final_name + ".decrypt", default_fmt)
            decrypt_tmp_path = self.fs.build_path(tmp_base_dir, decrypt_tmp_name)
            transcode_tmp_path = ""

            try:
                decrypt_msg = f"[*] 开始解密: {file_path} -> {decrypt_tmp_path}"
                logger.info(decrypt_msg)
                self._emit(on_log, decrypt_msg)

                success = self.decrypt_gateway.decrypt_file(file_path, decrypt_tmp_path)
                if not success:
                    fail_msg = f"[!] 解密失败: {file_path}"
                    logger.error(fail_msg)
                    self._emit(on_log, fail_msg)
                    failed_count += 1
                    self.fs.remove_file(decrypt_tmp_path)
                    continue

                source_for_move = decrypt_tmp_path
                if will_transcode:
                    transcode_tmp_name = self.fs.make_tmp_file_name(final_name + ".transcode", effective_fmt)
                    transcode_tmp_path = self.fs.build_path(tmp_base_dir, transcode_tmp_name)

                    transcode_msg = f"[*] 开始转码: {decrypt_tmp_path} -> {transcode_tmp_path}"
                    logger.info(transcode_msg)
                    self._emit(on_log, transcode_msg)

                    transcode_success = self.transcoder.transcode(decrypt_tmp_path, transcode_tmp_path)
                    if not transcode_success:
                        fail_msg = f"[!] 转码失败，跳过文件: {file_path}"
                        logger.error(fail_msg)
                        self._emit(on_log, fail_msg)
                        failed_count += 1
                        self.fs.remove_file(decrypt_tmp_path)
                        self.fs.remove_file(transcode_tmp_path)
                        continue

                    source_for_move = transcode_tmp_path
                    self.fs.remove_file(decrypt_tmp_path)

                self.fs.move(source_for_move, final_path)
                done_msg = f"[*] 处理完成: {final_path}"
                logger.info(done_msg)
                self._emit(on_log, done_msg)

                if del_original:
                    try:
                        self.fs.remove_file(file_path)
                        delete_msg = f"[*] 已删除原始文件: {file_path}"
                        logger.info(delete_msg)
                        self._emit(on_log, delete_msg)
                    except Exception as exc:
                        warn_msg = f"[!] 删除原始文件失败: {file_path}, {exc}"
                        logger.warning(warn_msg)
                        self._emit(on_log, warn_msg)

                processed_count += 1
            except Exception as exc:
                logger.exception("文件处理失败: %s", file_path)
                self._emit(on_log, f"[!] 文件处理失败: {file_path}, {exc}")
                failed_count += 1
                self.fs.remove_file(decrypt_tmp_path)
                if transcode_tmp_path:
                    self.fs.remove_file(transcode_tmp_path)

        elapsed = time.perf_counter() - start_time
        summary = (
            f"成功={processed_count}, 跳过={skipped_count}, 失败={failed_count}, 耗时={elapsed:.2f}秒"
        )
        logger.info("处理完成: %s", summary)
        self._emit(on_log, f"[*] 处理完成: {summary}")
        return True, summary
