from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.Infrastructure.ffmpeg_transcoder import FfmpegTranscoder
from src.Infrastructure.frida_decrypt_gateway import FridaDecryptGateway


def main() -> int:
    base = Path(r"O:\QKKDecrypt UI\i")
    work = ROOT / "_log" / "ascii_source_decrypt_check"
    src_dir = work / "src"
    out_dir = work / "out"
    src_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    samples = [
        "伊然 - 尝尽世间万般苦 (有种想哭的冲动)_H.mgg",
        "刀郎 - 手心里的温柔 (慢三版)_L.mgg",
        "周华健 - 朋友_H.mgg",
        "邓丽君 - 小城故事_H.mgg",
        "陈瑞 - 情罪_H.mgg",
    ]

    gateway = FridaDecryptGateway()
    transcoder = FfmpegTranscoder()
    results = []

    for name in samples:
        src = base / name
        token = hashlib.md5(name.encode("utf-8")).hexdigest()[:12]
        staged = src_dir / f"{token}{src.suffix}"
        out = out_dir / f"{token}.ogg"

        staged.write_bytes(src.read_bytes())
        if out.exists():
            out.unlink()

        ok = gateway.decrypt_file(str(staged), str(out))
        container = "missing"
        stage = "missing"
        summary = {}
        if out.exists():
            container, stage = transcoder.detect_audio_container(str(out))
            summary = transcoder.probe_media_summary(str(out))

        results.append(
            {
                "name": name,
                "ok": ok,
                "container": container,
                "stage": stage,
                "summary": summary,
                "out": str(out),
            }
        )

    path = work / "results.json"
    path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
