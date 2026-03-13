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
    """Orchestrate decrypt + optional transcode without changing core decrypt logic."""

    def __init__(
        self,
        decrypt_gateway: FridaDecryptGateway,
        transcoder: FfmpegTranscoder,
        fs_adapter: FileSystemAdapter,
        format_policy: FormatPolicyService,
        cover_art_service: CoverArtService,
    ):
        self.decrypt_gateway = decrypt_gateway
        self.transcoder = transcoder
        self.fs = fs_adapter
        self.policy = format_policy
        self.cover_art = cover_art_service

    @staticmethod
    def _summary_text(summary: Dict[str, object]) -> str:
        return (
            f"container={summary.get('container') or 'unknown'} "
            f"audio={summary.get('audio_streams', 0)} "
            f"video={summary.get('video_streams', 0)} "
            f"cover={'yes' if summary.get('has_cover') else 'no'} "
            f"cover_codec={summary.get('cover_codec') or '-'} "
            f"probe={summary.get('probe_backend') or '-'}"
        )

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
            raise RuntimeError(f"QQ download directory does not exist: {input_dir}")

        self.fs.ensure_dir(output_dir)
        tmp_base_dir = self.fs.pick_tmp_base_dir(output_dir)
        if tmp_base_dir != output_dir:
            logger.info("Using ASCII-safe temp directory: %s", tmp_base_dir)

        processed_count = 0
        skipped_count = 0
        failed_count = 0

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
                    action = on_ffmpeg_missing() if on_ffmpeg_missing else "decrypt_only"
                    if action == "download_exit":
                        elapsed = time.perf_counter() - start_time
                        logger.warning("User chose to download FFmpeg and exit this run")
                        return False, f"User chose to exit and download FFmpeg, elapsed {elapsed:.2f}s"
                    fallback_decrypt_only = True
                    logger.warning("FFmpeg unavailable; this run will decrypt without transcoding")

            effective_fmt = target_fmt
            if needs_transcode and (fallback_decrypt_only or not self.transcoder.available):
                effective_fmt = default_fmt
                needs_transcode = False

            expected_final_name = f"{base_name}.{effective_fmt}"
            expected_final_path = self.fs.build_path(output_dir, expected_final_name)
            logger.info(
                "Processing file: %s | src=%s default=%s target=%s transcode=%s",
                file_path,
                src_ext,
                default_fmt,
                target_fmt,
                "yes" if (self.policy.default_format(src_ext) != target_fmt and effective_fmt == target_fmt) else "no",
            )

            if self.fs.file_exists(expected_final_path):
                logger.info("Target file already exists, skipping: %s", expected_final_path)
                if del_original:
                    self._try_remove_original(file_path)
                skipped_count += 1
                continue

            decrypt_tmp_name = self.fs.make_tmp_file_name(expected_final_name + ".decrypt", default_fmt)
            decrypt_tmp_path = self.fs.build_path(tmp_base_dir, decrypt_tmp_name)
            transcode_tmp_path = ""

            try:
                success = self.decrypt_gateway.decrypt_file(file_path, decrypt_tmp_path)
                if not success:
                    logger.error("Decrypt step failed: %s", file_path)
                    failed_count += 1
                    self.fs.remove_file(decrypt_tmp_path)
                    continue

                detected_container, recognition_stage = self.transcoder.detect_audio_container(decrypt_tmp_path)
                decrypt_summary = self.transcoder.probe_media_summary(decrypt_tmp_path)
                logger.info(
                    "Decrypt media summary: %s | %s",
                    file_path,
                    self._summary_text(decrypt_summary),
                )
                if detected_container == "bin":
                    logger.error(
                        "Decrypt produced an unrecognized audio container: %s | stage=%s",
                        file_path,
                        recognition_stage,
                    )
                    failed_count += 1
                    self.fs.remove_file(decrypt_tmp_path)
                    continue

                if detected_container != default_fmt:
                    logger.warning(
                        "Decrypt container differs from expected default: %s | expected=%s actual=%s stage=%s",
                        file_path,
                        default_fmt,
                        detected_container,
                        recognition_stage,
                    )

                final_fmt = effective_fmt
                source_for_move = decrypt_tmp_path

                if self.policy.default_format(src_ext) != target_fmt and effective_fmt == target_fmt:
                    transcode_tmp_name = self.fs.make_tmp_file_name(expected_final_name + ".transcode", target_fmt)
                    transcode_tmp_path = self.fs.build_path(tmp_base_dir, transcode_tmp_name)
                    transcode_success = self.transcoder.transcode(decrypt_tmp_path, transcode_tmp_path)
                    if not transcode_success:
                        logger.error("Transcode failed, skipping file: %s", file_path)
                        failed_count += 1
                        self.fs.remove_file(decrypt_tmp_path)
                        self.fs.remove_file(transcode_tmp_path)
                        continue

                    transcoded_container, transcode_stage = self.transcoder.detect_audio_container(transcode_tmp_path)
                    transcode_summary = self.transcoder.probe_media_summary(transcode_tmp_path)
                    logger.info(
                        "Transcode media summary: %s | %s",
                        file_path,
                        self._summary_text(transcode_summary),
                    )
                    if decrypt_summary.get("has_cover") and not transcode_summary.get("has_cover"):
                        logger.warning(
                            "Cover art was present before transcode but missing after transcode: %s",
                            file_path,
                        )
                    if transcoded_container == "bin":
                        logger.error(
                            "Transcode produced an unrecognized audio container: %s | stage=%s",
                            file_path,
                            transcode_stage,
                        )
                        failed_count += 1
                        self.fs.remove_file(decrypt_tmp_path)
                        self.fs.remove_file(transcode_tmp_path)
                        continue

                    source_for_move = transcode_tmp_path
                    final_fmt = target_fmt
                    self.fs.remove_file(decrypt_tmp_path)
                else:
                    final_fmt = detected_container

                final_name = f"{base_name}.{final_fmt}"
                final_path = self.fs.build_path(output_dir, final_name)

                if self.fs.file_exists(final_path):
                    logger.info("Resolved target already exists, skipping: %s", final_path)
                    self.fs.remove_file(source_for_move)
                    if del_original:
                        self._try_remove_original(file_path)
                    skipped_count += 1
                    continue

                self.fs.move(source_for_move, final_path)
                logger.info("Finished file: %s", final_path)

                final_summary = self.transcoder.probe_media_summary(final_path)
                logger.info(
                    "Final media summary: %s | %s",
                    file_path,
                    self._summary_text(final_summary),
                )
                cover_result = self.cover_art.supplement_cover(
                    audio_path=final_path,
                    source_file_path=file_path,
                    media_summary=final_summary,
                )
                if cover_result.status == "embedded":
                    refreshed_summary = self.transcoder.probe_media_summary(final_path)
                    logger.info(
                        "Cover art supplemented: %s | source=%s image=%s | %s",
                        file_path,
                        cover_result.source,
                        cover_result.image_path,
                        self._summary_text(refreshed_summary),
                    )
                elif cover_result.status not in {"already_present", "unsupported"}:
                    logger.info(
                        "Cover art not supplemented: %s | status=%s message=%s",
                        file_path,
                        cover_result.status,
                        cover_result.message,
                    )

                if del_original:
                    self._try_remove_original(file_path)

                processed_count += 1
            except Exception as exc:
                logger.exception("Processing failed: %s, %s", file_path, exc)
                failed_count += 1
                self.fs.remove_file(decrypt_tmp_path)
                if transcode_tmp_path:
                    self.fs.remove_file(transcode_tmp_path)

        elapsed = time.perf_counter() - start_time
        logger.info(
            "Finished run: success=%s skipped=%s failed=%s elapsed=%.2fs",
            processed_count,
            skipped_count,
            failed_count,
            elapsed,
        )
        return (
            True,
            f"Processed {processed_count} files, skipped {skipped_count}, failed {failed_count}, elapsed {elapsed:.2f}s",
        )

    def _try_remove_original(self, file_path: str) -> None:
        try:
            self.fs.remove_file(file_path)
            logger.info("Removed original file: %s", file_path)
        except Exception as exc:
            logger.warning("Failed to remove original file: %s, %s", file_path, exc)
