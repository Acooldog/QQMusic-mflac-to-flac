import logging
import shutil
import subprocess


logger = logging.getLogger("qqmusic_decrypt.infrastructure.ffmpeg")


class FfmpegTranscoder:
    """Transcoder adapter around ffmpeg binary."""

    DOWNLOAD_URL = "https://ffmpeg.org/download.html"

    def __init__(self):
        self.ffmpeg_path = shutil.which("ffmpeg")
        self.available = self.ffmpeg_path is not None
        self.version_text = self._detect_version() if self.available else ""

        if self.available:
            logger.info("FFmpeg available: %s", self.ffmpeg_path)
            if self.version_text:
                logger.info("FFmpeg version: %s", self.version_text)
        else:
            logger.warning("FFmpeg not found, transcoding is unavailable")

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

    def transcode(self, input_path: str, output_path: str) -> bool:
        if not self.ffmpeg_path:
            logger.error("FFmpeg unavailable: %s -> %s", input_path, output_path)
            return False

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
        logger.info("Run transcode command: %s", " ".join(command))

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
