import hashlib
import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict

from src.Helper.runtime_logging import get_runtime_dir


logger = logging.getLogger("qqmusic_decrypt.infrastructure.ffmpeg")


class FfmpegTranscoder:
    """Bundled ffmpeg adapter with media probing and cover-aware transcode helpers."""

    DOWNLOAD_URL = "https://ffmpeg.org/download.html"

    def __init__(self):
        self.ffmpeg_path = self._resolve_ffmpeg_path()
        self.available = self.ffmpeg_path is not None
        self.version_text = self._detect_version() if self.available else ""
        if self.available:
            logger.info("Bundled FFmpeg available: %s", self.ffmpeg_path)
            if self.version_text:
                logger.info("FFmpeg version: %s", self.version_text)
        else:
            logger.warning("Bundled FFmpeg not found in assets")

    def _bundle_root(self) -> pathlib.Path:
        base = getattr(sys, "_MEIPASS", None)
        if base:
            return pathlib.Path(base)
        return pathlib.Path(get_runtime_dir())

    def _resolve_ffmpeg_path(self) -> str | None:
        runtime_root = pathlib.Path(get_runtime_dir())
        bundle_root = self._bundle_root()
        candidates = [
            runtime_root / "assets" / "ffmpeg-win-x86_64-v7.1.exe",
            runtime_root / "assets" / "ffmpeg.exe",
            bundle_root / "assets" / "ffmpeg-win-x86_64-v7.1.exe",
            bundle_root / "assets" / "ffmpeg.exe",
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return str(candidate)
        return shutil.which("ffmpeg")

    def _subprocess_window_kwargs(self) -> Dict[str, Any]:
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            return {"creationflags": subprocess.CREATE_NO_WINDOW, "startupinfo": startupinfo}
        return {}

    def _detect_version(self) -> str:
        if not self.ffmpeg_path:
            return ""
        try:
            completed = subprocess.run(
                [self.ffmpeg_path, "-version"],
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="ignore",
                **self._subprocess_window_kwargs(),
            )
            if completed.returncode != 0:
                return ""
            return (completed.stdout.splitlines()[0] if completed.stdout else "").strip()
        except Exception:
            logger.exception("Failed to detect FFmpeg version")
            return ""

    def _run_ffmpeg(self, command: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
            **self._subprocess_window_kwargs(),
        )

    def fast_detect_container(self, path: str) -> str:
        file_path = pathlib.Path(path)
        if not file_path.exists() or file_path.stat().st_size < 4:
            return "bin"
        head = file_path.read_bytes()[:64]
        if head.startswith(b"fLaC"):
            return "flac"
        if head.startswith(b"OggS"):
            return "ogg"
        if head.startswith(b"RIFF") and len(head) >= 12 and head[8:12] == b"WAVE":
            return "wav"
        if head.startswith(b"ID3"):
            return "mp3"
        if len(head) >= 2 and head[0] == 0xFF and head[1] in (0xFB, 0xF3, 0xF2):
            return "mp3"
        if len(head) >= 12 and head[4:8] == b"ftyp":
            return "m4a"
        return "bin"

    def probe_media_summary(self, path: str) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            "path": path,
            "container": self.fast_detect_container(path),
            "recognition_stage": "fast" if self.fast_detect_container(path) != "bin" else "unrecognized",
            "audio_codec": "",
            "video_codec": "",
            "has_audio": False,
            "has_cover": False,
            "cover_codec": "",
            "metadata": {},
            "probe_ok": False,
        }
        if not self.ffmpeg_path or not os.path.exists(path):
            return summary
        completed = self._run_ffmpeg([self.ffmpeg_path, "-hide_banner", "-i", path])
        stderr = completed.stderr or ""
        lower = stderr.lower()
        marker = "Input #0, "
        start = stderr.find(marker)
        if start >= 0:
            after = stderr[start + len(marker):]
            format_name = after.split(",", 1)[0].strip().lower()
            mapping = {
                "flac": "flac",
                "ogg": "ogg",
                "wav": "wav",
                "wav_pipe": "wav",
                "mp3": "mp3",
                "mov": "m4a",
                "mp4": "m4a",
                "m4a": "m4a",
                "3gp": "m4a",
                "3g2": "m4a",
                "mj2": "m4a",
            }
            if format_name in mapping:
                summary["container"] = mapping[format_name]
                summary["recognition_stage"] = "ffmpeg_probe"
        metadata_started = False
        metadata_indent = None
        for line in stderr.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped == "Metadata:":
                metadata_started = True
                metadata_indent = len(line) - len(line.lstrip())
                continue
            if metadata_started:
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= (metadata_indent or 0):
                    metadata_started = False
                else:
                    match = re.match(r"\s*([^:]+)\s*:\s*(.*)", line)
                    if match:
                        key = match.group(1).strip().lower()
                        value = match.group(2).strip()
                        summary["metadata"][key] = value
                    continue
            if " Audio:" in line:
                summary["has_audio"] = True
                codec = line.split("Audio:", 1)[1].split(",", 1)[0].strip()
                summary["audio_codec"] = codec
            elif " Video:" in line:
                codec = line.split("Video:", 1)[1].split(",", 1)[0].strip()
                summary["video_codec"] = codec
                if "mjpeg" in codec.lower() or "attached pic" in lower:
                    summary["has_cover"] = True
                    summary["cover_codec"] = codec
        summary["probe_ok"] = bool(summary["audio_codec"] or summary["video_codec"] or summary["metadata"])
        return summary

    def detect_audio_container(self, path: str) -> tuple[str, str]:
        summary = self.probe_media_summary(path)
        return str(summary["container"]), str(summary["recognition_stage"])

    def _codec_args(self, target_format: str) -> list[str]:
        if target_format == "mp3":
            return ["-codec:a", "libmp3lame", "-q:a", "2"]
        if target_format == "m4a":
            return ["-codec:a", "aac", "-b:a", "256k"]
        if target_format == "wav":
            return ["-codec:a", "pcm_s16le"]
        if target_format == "flac":
            return ["-codec:a", "flac"]
        return []

    def transcode(self, input_path: str, output_path: str, target_format: str) -> bool:
        if not self.ffmpeg_path:
            logger.error("FFmpeg unavailable: %s -> %s", input_path, output_path)
            return False
        temp_output = pathlib.Path(output_path).with_name(f".{pathlib.Path(output_path).stem}.transcode.{time.time_ns()}{pathlib.Path(output_path).suffix}")
        command = [
            self.ffmpeg_path,
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            input_path,
            "-map",
            "0:a:0",
            "-vn",
            "-sn",
            "-dn",
            "-map_metadata",
            "0",
            "-map_chapters",
            "0",
            *self._codec_args(target_format),
            str(temp_output),
        ]
        logger.info("Run transcode command: %s", " ".join(command))
        try:
            completed = self._run_ffmpeg(command)
            if completed.returncode != 0:
                logger.error("FFmpeg transcode failed: %s", completed.stderr.strip())
                return False
            if os.path.exists(output_path):
                os.remove(output_path)
            temp_output.replace(output_path)
            return True
        except Exception:
            logger.exception("FFmpeg transcode raised an exception")
            return False
        finally:
            if temp_output.exists():
                try:
                    temp_output.unlink()
                except OSError:
                    pass

    def attach_cover(self, audio_path: str, cover_path: str) -> bool:
        if not self.ffmpeg_path or not os.path.exists(audio_path) or not os.path.exists(cover_path):
            return False
        suffix = pathlib.Path(audio_path).suffix.lower()
        if suffix not in {".m4a", ".mp3", ".flac"}:
            return False
        temp_output = pathlib.Path(audio_path).with_name(f".{pathlib.Path(audio_path).stem}.cover.{time.time_ns()}{suffix}")
        command = [
            self.ffmpeg_path,
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            audio_path,
            "-i",
            cover_path,
            "-map",
            "0:a:0",
            "-map",
            "1:v:0",
            "-map_metadata",
            "0",
            "-map_chapters",
            "0",
            "-codec:a",
            "copy",
            "-codec:v",
            "mjpeg",
            "-disposition:v:0",
            "attached_pic",
            "-metadata:s:v",
            "title=Album cover",
            "-metadata:s:v",
            "comment=Cover (front)",
            str(temp_output),
        ]
        try:
            completed = self._run_ffmpeg(command)
            if completed.returncode != 0:
                logger.warning("Attach cover failed: %s", completed.stderr.strip())
                return False
            os.replace(temp_output, audio_path)
            return True
        except Exception:
            logger.exception("Attach cover raised an exception")
            return False
        finally:
            if temp_output.exists():
                try:
                    temp_output.unlink()
                except OSError:
                    pass

    @staticmethod
    def summary_to_log(summary: Dict[str, Any]) -> str:
        metadata = summary.get("metadata") or {}
        meta_bits = []
        for key in ("title", "artist", "album"):
            value = str(metadata.get(key, "") or "").strip()
            if value:
                meta_bits.append(f"{key}={value}")
        meta_text = (" | " + ", ".join(meta_bits)) if meta_bits else ""
        return (
            f"container={summary.get('container')} audio={summary.get('audio_codec') or '-'} "
            f"video={summary.get('video_codec') or '-'} cover={'yes' if summary.get('has_cover') else 'no'} "
            f"cover_codec={summary.get('cover_codec') or '-'} probe={'ok' if summary.get('probe_ok') else 'no'}{meta_text}"
        )
