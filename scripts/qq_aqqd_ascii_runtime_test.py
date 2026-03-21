from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.Application.decrypt_job_service import DecryptJobService
from src.Application.format_policy_service import FormatPolicyService
from src.Infrastructure.cover_art_service import CoverArtService
from src.Infrastructure.ffmpeg_transcoder import FfmpegTranscoder
from src.Infrastructure.filesystem_adapter import FileSystemAdapter
from src.Infrastructure.frida_decrypt_gateway import FridaDecryptGateway


def main() -> int:
    sample = Path(r"O:\QKKDecrypt UI\i\伊然 - 尝尽世间万般苦 (有种想哭的冲动)_H.mgg")
    runtime_root = ROOT / "_log" / "aqd_ascii_runtime_test"
    input_dir = runtime_root / "input"
    output_dir = runtime_root / "output"
    if runtime_root.exists():
        shutil.rmtree(runtime_root)
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sample, input_dir / sample.name)

    service = DecryptJobService(
        FridaDecryptGateway(),
        FfmpegTranscoder(),
        FileSystemAdapter(),
        FormatPolicyService(),
        CoverArtService(str(ROOT / "plugins" / "cover_cache")),
    )
    ok, message = service.run(str(input_dir), str(output_dir), False, {"mgg": "m4a"})
    results = {
        "ok": ok,
        "message": message,
        "outputs": [path.name for path in sorted(output_dir.glob("*"))],
    }
    output = ROOT / "_log" / "aqd_ascii_runtime_test.json"
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
