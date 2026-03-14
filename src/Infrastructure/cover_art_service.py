from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict

from src.Helper.runtime_logging import get_runtime_dir
from src.Infrastructure.filesystem_adapter import FileSystemAdapter


logger = logging.getLogger("qqmusic_decrypt.infrastructure.cover_art")


class CoverArtService:
    """Local-first cover art lookup with cache and QQ network fallback."""

    def __init__(self, fs_adapter: FileSystemAdapter):
        self.fs = fs_adapter
        self.cache_dir = pathlib.Path(get_runtime_dir()) / "plugins" / "cover_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cover_candidates(self, source_path: pathlib.Path) -> list[pathlib.Path]:
        names = [
            source_path.stem,
            "cover",
            "folder",
            "front",
            "albumart",
            "album",
        ]
        suffixes = [".jpg", ".jpeg", ".png", ".webp"]
        candidates: list[pathlib.Path] = []
        for name in names:
            for suffix in suffixes:
                candidates.append(source_path.with_name(f"{name}{suffix}"))
        return candidates

    def _cache_key(self, summary: Dict[str, Any], source_path: pathlib.Path) -> str:
        metadata = summary.get("metadata") or {}
        seed = "|".join(
            [
                str(metadata.get("title", "") or "").strip().lower(),
                str(metadata.get("artist", "") or "").strip().lower(),
                str(metadata.get("album", "") or "").strip().lower(),
                source_path.stem.strip().lower(),
            ]
        )
        return hashlib.sha1(seed.encode("utf-8", errors="ignore")).hexdigest()

    def _find_local_cover(self, source_path: pathlib.Path, summary: Dict[str, Any]) -> pathlib.Path | None:
        for candidate in self._cover_candidates(source_path):
            if candidate.exists() and candidate.is_file() and candidate.stat().st_size > 1024:
                return candidate
        cache_key = self._cache_key(summary, source_path)
        for suffix in (".jpg", ".jpeg", ".png", ".webp"):
            candidate = self.cache_dir / f"{cache_key}{suffix}"
            if candidate.exists() and candidate.is_file() and candidate.stat().st_size > 1024:
                return candidate
        return None

    def _query_keyword(self, summary: Dict[str, Any], source_path: pathlib.Path) -> str:
        metadata = summary.get("metadata") or {}
        title = str(metadata.get("title", "") or "").strip()
        artist = str(metadata.get("artist", "") or "").strip()
        album = str(metadata.get("album", "") or "").strip()
        if title and artist:
            return f"{artist} {title}"
        if title:
            return title
        if album and artist:
            return f"{artist} {album}"
        if " - " in source_path.stem:
            return source_path.stem.replace("_", " ")
        return source_path.stem

    def _download_url(self, url: str, target_path: pathlib.Path) -> pathlib.Path | None:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Referer": "https://y.qq.com/",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                content_type = str(response.headers.get("Content-Type", "")).lower()
                data = response.read()
            if len(data) <= 1024 or "image" not in content_type:
                return None
            target_path.write_bytes(data)
            return target_path
        except Exception:
            return None

    def _search_qq_cover(self, summary: Dict[str, Any], source_path: pathlib.Path) -> pathlib.Path | None:
        keyword = self._query_keyword(summary, source_path)
        if not keyword:
            return None
        cache_key = self._cache_key(summary, source_path)
        cache_path = self.cache_dir / f"{cache_key}.jpg"
        params = {
            "w": keyword,
            "n": "1",
            "p": "1",
            "format": "json",
            "t": "0",
            "cr": "1",
            "new_json": "1",
            "platform": "yqq.json",
            "needNewCode": "0",
        }
        url = "https://c.y.qq.com/soso/fcgi-bin/client_search_cp?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Referer": "https://y.qq.com/",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                payload = response.read().decode("utf-8", errors="ignore")
            match = re.search(r"\{.*\}", payload, re.S)
            if match:
                payload = match.group(0)
            data = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            return None
        album_mid = ""
        try:
            song_list = ((data.get("data") or {}).get("song") or {}).get("list") or []
            if song_list:
                first = song_list[0]
                album_mid = str(first.get("album", {}).get("mid") or first.get("albummid") or "").strip()
        except Exception:
            album_mid = ""
        if not album_mid:
            return None
        cover_url = f"https://y.qq.com/music/photo_new/T002R500x500M000{album_mid}.jpg"
        downloaded = self._download_url(cover_url, cache_path)
        if downloaded:
            logger.info("QQ cover cached: %s -> %s", keyword, downloaded)
        return downloaded

    def resolve_cover(self, source_path: str, media_summary: Dict[str, Any]) -> pathlib.Path | None:
        source = pathlib.Path(source_path)
        local = self._find_local_cover(source, media_summary)
        if local:
            return local
        return self._search_qq_cover(media_summary, source)
