import json
import logging
import os
import pathlib
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple


logger = logging.getLogger("qqmusic_decrypt.infrastructure.ffmpeg")


class FfmpegTranscoder:
    """Transcoder adapter around ffmpeg binary."""

    DOWNLOAD_URL = "https://ffmpeg.org/download.html"

    def __init__(self):
        self.ffmpeg_path = shutil.which("ffmpeg")
        self.ffprobe_path = self._detect_ffprobe_path()
        self.available = self.ffmpeg_path is not None
        self.version_text = self._detect_version() if self.available else ""

    def _detect_ffprobe_path(self) -> Optional[str]:
        discovered = shutil.which("ffprobe")
        if discovered:
            return discovered
        if not self.ffmpeg_path:
            return None
        candidate = str(pathlib.Path(self.ffmpeg_path).with_name("ffprobe.exe"))
        return candidate if os.path.exists(candidate) else None

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
            )
            if completed.returncode != 0:
                return ""
            first_line = completed.stdout.splitlines()[0] if completed.stdout else ""
            return first_line.strip()
        except Exception:
            logger.exception("Failed to detect FFmpeg version")
            return ""

    @staticmethod
    def _fast_detect_container(input_path: str) -> str:
        path = pathlib.Path(input_path)
        if not path.exists() or path.stat().st_size < 4:
            return "bin"
        head = path.read_bytes()[:64]
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

    @staticmethod
    def _parse_ffmpeg_input_format(stderr: str) -> Optional[str]:
        marker = "Input #0, "
        start = stderr.find(marker)
        if start < 0:
            return None
        after = stderr[start + len(marker):]
        format_name = after.split(",", 1)[0].strip().lower()
        if format_name == "flac":
            return "flac"
        if format_name == "ogg":
            return "ogg"
        if format_name in {"wav", "wav_pipe"}:
            return "wav"
        if format_name == "mp3":
            return "mp3"
        if format_name in {"mov", "mp4", "m4a", "3gp", "3g2", "mj2"}:
            return "m4a"
        return None

    def probe_input_container(self, input_path: str) -> Optional[str]:
        if not self.ffmpeg_path:
            return None
        command = [
            self.ffmpeg_path,
            "-hide_banner",
            "-i",
            input_path,
            "-f",
            "null",
            os.devnull,
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="ignore",
            )
            return self._parse_ffmpeg_input_format(completed.stderr or "")
        except Exception:
            logger.exception("FFmpeg probe failed: %s", input_path)
            return None

    def detect_audio_container(self, input_path: str) -> Tuple[str, str]:
        fast = self._fast_detect_container(input_path)
        if fast != "bin":
            return fast, "fast"
        probed = self.probe_input_container(input_path)
        if probed:
            return probed, "ffmpeg_probe"
        return "bin", "unrecognized"

    def probe_media_summary(self, input_path: str) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            "path": input_path,
            "container": None,
            "audio_streams": 0,
            "video_streams": 0,
            "has_cover": False,
            "cover_codec": None,
            "duration": None,
            "bit_rate": None,
            "probe_backend": "none",
            "tags": {},
        }
        if self.ffprobe_path:
            probed = self._probe_media_summary_with_ffprobe(input_path)
            if probed is not None:
                return probed
        container, stage = self.detect_audio_container(input_path)
        summary["container"] = None if container == "bin" else container
        summary["probe_backend"] = stage
        return summary

    def _probe_media_summary_with_ffprobe(self, input_path: str) -> Optional[Dict[str, Any]]:
        if not self.ffprobe_path:
            return None
        command = [
            self.ffprobe_path,
            "-v",
            "error",
            "-show_entries",
            "format=format_name,duration,bit_rate:format_tags:stream=index,codec_type,codec_name,disposition:stream_tags",
            "-of",
            "json",
            input_path,
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="ignore",
            )
            if completed.returncode != 0:
                return None
            payload = json.loads(completed.stdout or "{}")
            fmt = payload.get("format") or {}
            streams = payload.get("streams") or []
            audio_streams = 0
            video_streams = 0
            has_cover = False
            cover_codec = None
            for stream in streams:
                codec_type = stream.get("codec_type")
                if codec_type == "audio":
                    audio_streams += 1
                elif codec_type == "video":
                    video_streams += 1
                disposition = stream.get("disposition") or {}
                codec_name = stream.get("codec_name")
                if disposition.get("attached_pic") == 1:
                    has_cover = True
                    cover_codec = codec_name
                elif codec_type == "video" and codec_name in {"mjpeg", "png", "jpeg"}:
                    has_cover = True
                    cover_codec = codec_name
            format_name = fmt.get("format_name")
            container = None
            if format_name:
                lowered = str(format_name).lower()
                if "flac" in lowered:
                    container = "flac"
                elif "ogg" in lowered:
                    container = "ogg"
                elif "wav" in lowered:
                    container = "wav"
                elif "mp3" in lowered:
                    container = "mp3"
                elif lowered.startswith("mov") or "m4a" in lowered or "mp4" in lowered:
                    container = "m4a"
            tags = {}
            if isinstance(fmt.get("tags"), dict):
                tags.update({str(k).lower(): str(v) for k, v in fmt.get("tags", {}).items() if isinstance(v, (str, int, float))})
            for stream in streams:
                if isinstance(stream.get("tags"), dict):
                    for key, value in stream.get("tags", {}).items():
                        lowered = str(key).lower()
                        if lowered not in tags and isinstance(value, (str, int, float)):
                            tags[lowered] = str(value)
            if not has_cover:
                if "metadata_block_picture" in tags or "coverart" in tags:
                    has_cover = True
                    cover_codec = "metadata_block_picture"

            return {
                "path": input_path,
                "container": container,
                "audio_streams": audio_streams,
                "video_streams": video_streams,
                "has_cover": has_cover,
                "cover_codec": cover_codec,
                "duration": fmt.get("duration"),
                "bit_rate": fmt.get("bit_rate"),
                "probe_backend": "ffprobe",
                "tags": tags,
            }
        except Exception:
            logger.exception("FFprobe media summary failed: %s", input_path)
            return None

    @staticmethod
    def _stream_selection_args(target_ext: str) -> list[str]:
        if target_ext in {"mp3", "m4a", "flac"}:
            return ["-map", "0:a:0", "-map", "0:v?"]
        return ["-map", "0:a:0"]

    @staticmethod
    def _metadata_args() -> list[str]:
        return ["-map_metadata", "0", "-map_chapters", "0"]

    @staticmethod
    def _codec_args(target_ext: str) -> list[str]:
        if target_ext == "mp3":
            return ["-codec:a", "libmp3lame", "-q:a", "2", "-codec:v", "copy", "-id3v2_version", "3"]
        if target_ext == "m4a":
            return [
                "-codec:a",
                "aac",
                "-b:a",
                "256k",
                "-codec:v",
                "copy",
                "-disposition:v:0",
                "attached_pic",
                "-movflags",
                "+faststart",
            ]
        if target_ext == "wav":
            return ["-codec:a", "pcm_s16le"]
        if target_ext == "flac":
            return ["-codec:a", "flac", "-codec:v", "copy"]
        if target_ext == "ogg":
            return ["-codec:a", "libvorbis", "-q:a", "5"]
        return []

    def transcode(self, input_path: str, output_path: str) -> bool:
        if not self.ffmpeg_path:
            logger.error("FFmpeg is not available: %s -> %s", input_path, output_path)
            return False

        target_ext = pathlib.Path(output_path).suffix.lower().lstrip(".")
        command = [
            self.ffmpeg_path,
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            input_path,
            *self._stream_selection_args(target_ext),
            *self._metadata_args(),
            *self._codec_args(target_ext),
            output_path,
        ]
        logger.info("Running transcode command: %s", " ".join(command))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="ignore",
            )
            if completed.returncode == 0:
                return True
            logger.error("FFmpeg transcode failed: %s", completed.stderr.strip())
            return False
        except Exception:
            logger.exception("FFmpeg transcode raised an exception")
            return False
