import logging
import shutil
import subprocess
from typing import Optional


logger = logging.getLogger("qqmusic_decrypt.infrastructure.ffmpeg")


class FfmpegTranscoder:
    """Transcoder adapter around ffmpeg binary."""

    DOWNLOAD_URL = "https://ffmpeg.org/download.html"

    def __init__(self):
        self.ffmpeg_path = shutil.which("ffmpeg")
        self.available = self.ffmpeg_path is not None
        self.version_text = self._detect_version() if self.available else ""

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
            logger.exception("检测 FFmpeg 版本失败")
            return ""

    def transcode(self, input_path: str, output_path: str) -> bool:
        if not self.ffmpeg_path:
            logger.error("FFmpeg 不可用，无法转码: %s -> %s", input_path, output_path)
            return False

        # Keep command generic and rely on output extension to select muxer/encoder.
        command = [
            self.ffmpeg_path,
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            input_path,
            output_path,
        ]
        logger.info("执行转码命令: %s", " ".join(command))
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
            logger.error("FFmpeg 转码失败: %s", completed.stderr.strip())
            return False
        except Exception:
            logger.exception("执行 FFmpeg 转码异常")
            return False

