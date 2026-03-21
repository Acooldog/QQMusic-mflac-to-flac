from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SAMPLE_NAME = "伊然 - 尝尽世间万般苦 (有种想哭的冲动)_H.mgg"
REPOS = [
    Path(r"O:\A_python\A_QKKd"),
    Path(r"O:\A_python\A_QKKd_main_ui"),
]


def _run_one(repo_root: Path) -> dict[str, object]:
    snippet = f"""
from pathlib import Path
import json, sys
repo_root = Path(r\"{repo_root}\")
sys.path.insert(0, str(repo_root))
from src.Infrastructure.platforms.qq.adapter import QQPlatformAdapter
adapter = QQPlatformAdapter()
sample = Path(r\"O:\\QKKDecrypt UI\\i\\{SAMPLE_NAME}\")
work_dir = repo_root / '_log' / 'ascii_path_runtime_test' / sample.stem
work_dir.mkdir(parents=True, exist_ok=True)
detail = adapter.decrypt_one(sample, work_dir, {{}}, log_dir=work_dir)
print(json.dumps({{
    'repo': str(repo_root),
    'sample': sample.name,
    'backend': detail.get('backend'),
    'detected_container': detail.get('detected_container'),
    'recognition_stage': detail.get('recognition_stage'),
    'output_path': detail.get('output_path'),
    'decoded_bytes': detail.get('decoded_bytes'),
}}, ensure_ascii=False))
"""
    completed = subprocess.run(
        [sys.executable, "-X", "utf8", "-c", snippet],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{repo_root}: {completed.stderr.strip()}")
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1])
    return payload


def main() -> int:
    results = [_run_one(repo_root) for repo_root in REPOS]
    output = Path(r"O:\A_python\A_QQd\_log\ascii_path_runtime_results.json")
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
