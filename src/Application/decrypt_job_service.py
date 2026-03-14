import logging
import os
import time
from typing import Callable, Dict, Optional, Tuple

from src.Application.format_policy_service import FormatPolicyService
from src.Infrastructure.cover_art_service import CoverArtService
from src.Infrastructure.ffmpeg_transcoder import FfmpegTranscoder
from src.Infrastructure.filesystem_adapter import FileSystemAdapter
from src.Infrastructure.frida_decrypt_gateway import FridaDecryptGateway


logger = logging.getLogger("qqmusic_decrypt.application.decrypt_job")


class DecryptJobService:
    """Orchestrate scan -> decrypt -> validate -> optional transcode -> cover enrich -> cleanup."""

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
        self.cover_art = CoverArtService(fs_adapter)

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

    def _log_media_summary(self, label: str, path: str, on_log: Optional[Callable[[str], None]]) -> Dict[str, object]:
        summary = self.transcoder.probe_media_summary(path)
        message = f"[*] {label}: {os.path.basename(path)} | {self.transcoder.summary_to_log(summary)}"
        logger.info(message)
        self._emit(on_log, message)
        return summary

    def _validate_summary(self, label: str, path: str, summary: Dict[str, object], on_log: Optional[Callable[[str], None]]) -> bool:
        container = str(summary.get("container") or "bin")
        if container == "bin":
            message = f"[!] {label} produced an unrecognized audio container: {path}"
            logger.error(message)
            self._emit(on_log, message)
            return False
        return True

    def _maybe_attach_cover(self, source_path: str, output_path: str, on_log: Optional[Callable[[str], None]]) -> None:
        suffix = os.path.splitext(output_path)[1].lower()
        if suffix not in {".m4a", ".mp3", ".flac"}:
            return
        summary_before = self.transcoder.probe_media_summary(output_path)
        if summary_before.get("has_cover"):
            return
        cover_path = self.cover_art.resolve_cover(source_path, summary_before)
        if not cover_path:
            return
        if self.transcoder.attach_cover(output_path, str(cover_path)):
            summary_after = self.transcoder.probe_media_summary(output_path)
            message = f"[*] Cover attached: {os.path.basename(output_path)} | {self.transcoder.summary_to_log(summary_after)}"
            logger.info(message)
            self._emit(on_log, message)

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
            raw_fmt = self.policy.raw_decrypt_format(src_ext)
            requested_fmt = self.policy.target_format(src_ext, normalized_rules)
            will_transcode = self.policy.needs_transcode(src_ext, requested_fmt)

            if will_transcode and not self.transcoder.available:
                if not ffmpeg_prompted:
                    ffmpeg_prompted = True
                    action = on_ffmpeg_missing() if on_ffmpeg_missing else "decrypt_only"
                    if action == "download_exit":
                        elapsed = time.perf_counter() - start_time
                        return False, f"用户选择下载 FFmpeg 并退出，耗时 {elapsed:.2f} 秒"
                    if action == "cancel":
                        return False, "用户取消任务"
                    fallback_decrypt_only = True
                    msg = "[!] FFmpeg 不可用，本次任务仅解密不转码"
                    logger.warning(msg)
                    self._emit(on_log, msg)

            effective_fmt = requested_fmt
            if will_transcode and (fallback_decrypt_only or not self.transcoder.available):
                effective_fmt = raw_fmt
                will_transcode = False

            final_name = f"{base_name}.{effective_fmt}"
            final_path = self.fs.build_path(output_dir, final_name)
            if self.fs.file_exists(final_path):
                msg = f"[*] 目标文件已存在，跳过: {final_path}"
                logger.info(msg)
                self._emit(on_log, msg)
                if del_original:
                    try:
                        self.fs.remove_file(file_path)
                    except Exception:
                        logger.exception("删除原始文件失败: %s", file_path)
                skipped_count += 1
                continue

            decrypt_tmp_name = self.fs.make_tmp_file_name(final_name + ".decrypt", raw_fmt)
            decrypt_tmp_path = self.fs.build_path(tmp_base_dir, decrypt_tmp_name)
            transcode_tmp_path = ""
            try:
                decrypt_msg = f"[*] 开始解密: {file_path} -> {decrypt_tmp_path}"
                logger.info(decrypt_msg)
                self._emit(on_log, decrypt_msg)
                success = self.decrypt_gateway.decrypt_file(file_path, decrypt_tmp_path)
                if not success:
                    failed_count += 1
                    self.fs.remove_file(decrypt_tmp_path)
                    self._emit(on_log, f"[!] 解密失败: {file_path}")
                    continue

                decrypt_summary = self._log_media_summary("Decrypt media summary", decrypt_tmp_path, on_log)
                if not self._validate_summary("Decrypt", decrypt_tmp_path, decrypt_summary, on_log):
                    failed_count += 1
                    self.fs.remove_file(decrypt_tmp_path)
                    continue

                source_for_publish = decrypt_tmp_path
                if will_transcode:
                    transcode_tmp_name = self.fs.make_tmp_file_name(final_name + ".transcode", effective_fmt)
                    transcode_tmp_path = self.fs.build_path(tmp_base_dir, transcode_tmp_name)
                    transcode_msg = f"[*] 开始转码: {decrypt_tmp_path} -> {transcode_tmp_path}"
                    logger.info(transcode_msg)
                    self._emit(on_log, transcode_msg)
                    transcode_success = self.transcoder.transcode(decrypt_tmp_path, transcode_tmp_path, effective_fmt)
                    if not transcode_success:
                        failed_count += 1
                        self.fs.remove_file(decrypt_tmp_path)
                        self.fs.remove_file(transcode_tmp_path)
                        self._emit(on_log, f"[!] 转码失败，跳过文件: {file_path}")
                        continue
                    transcode_summary = self._log_media_summary("Transcode media summary", transcode_tmp_path, on_log)
                    if not self._validate_summary("Transcode", transcode_tmp_path, transcode_summary, on_log):
                        failed_count += 1
                        self.fs.remove_file(decrypt_tmp_path)
                        self.fs.remove_file(transcode_tmp_path)
                        continue
                    source_for_publish = transcode_tmp_path
                    self.fs.remove_file(decrypt_tmp_path)

                self._maybe_attach_cover(file_path, source_for_publish, on_log)
                final_summary = self._log_media_summary("Final media summary", source_for_publish, on_log)
                if not self._validate_summary("Final publish", source_for_publish, final_summary, on_log):
                    failed_count += 1
                    self.fs.remove_file(source_for_publish)
                    continue

                self.fs.move(source_for_publish, final_path)
                logger.info("[*] 处理完成: %s", final_path)
                self._emit(on_log, f"[*] 处理完成: {final_path}")
                if del_original:
                    try:
                        self.fs.remove_file(file_path)
                    except Exception:
                        logger.exception("删除原始文件失败: %s", file_path)
                processed_count += 1
            except Exception as exc:
                logger.exception("文件处理失败: %s", file_path)
                self._emit(on_log, f"[!] 文件处理失败: {file_path}, {exc}")
                failed_count += 1
                self.fs.remove_file(decrypt_tmp_path)
                if transcode_tmp_path:
                    self.fs.remove_file(transcode_tmp_path)

        elapsed = time.perf_counter() - start_time
        summary = f"成功={processed_count}, 跳过={skipped_count}, 失败={failed_count}, 耗时={elapsed:.2f}秒"
        logger.info("处理完成: %s", summary)
        self._emit(on_log, f"[*] 处理完成: {summary}")
        return True, summary
