import hashlib
import os
import shutil
from typing import List

from src.Manager.qqmusic_decrypt import pick_safe_tmp_dir


class FileSystemAdapter:
    """File-system operations used by application service."""

    @staticmethod
    def ensure_dir(path: str) -> None:
        os.makedirs(path, exist_ok=True)

    @staticmethod
    def file_exists(path: str) -> bool:
        return os.path.exists(path)

    @staticmethod
    def list_files(directory: str) -> List[str]:
        entries: List[str] = []
        for entry in sorted(os.listdir(directory)):
            full_path = os.path.join(directory, entry)
            if os.path.isfile(full_path):
                entries.append(full_path)
        return entries

    @staticmethod
    def remove_file(path: str) -> None:
        if path and os.path.exists(path):
            os.remove(path)

    @staticmethod
    def move(src: str, dst: str) -> None:
        shutil.move(src, dst)

    @staticmethod
    def pick_tmp_base_dir(output_dir: str) -> str:
        return pick_safe_tmp_dir(output_dir)

    @staticmethod
    def make_tmp_file_name(seed: str, ext: str) -> str:
        md5_hash = hashlib.md5(seed.encode("utf-8")).hexdigest()
        return f"{md5_hash}.{ext}"

    @staticmethod
    def build_path(directory: str, name: str) -> str:
        return os.path.join(directory, name)
