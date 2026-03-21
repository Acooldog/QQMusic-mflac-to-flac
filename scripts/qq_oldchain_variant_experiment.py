from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.Infrastructure.ffmpeg_transcoder import FfmpegTranscoder
from src.Infrastructure.frida_decrypt_gateway import FridaDecryptGateway


TAIL_SIZE = 192


@dataclass
class VariantResult:
    name: str
    encrypted_path: str
    decrypted_path: str
    detected_container: str
    recognition_stage: str
    summary: dict[str, object]
    decrypt_success: bool
    encrypted_size: int
    decrypted_size: int


def _swap_slice(target: bytes, donor: bytes, start: int, end: int) -> bytes:
    return target[:start] + donor[start:end] + target[end:]


def _replace_tail(target: bytes, donor: bytes, start: int = 0, end: int = TAIL_SIZE) -> bytes:
    target_tail = target[-TAIL_SIZE:]
    donor_tail = donor[-TAIL_SIZE:]
    merged_tail = _swap_slice(target_tail, donor_tail, start, end)
    return target[:-TAIL_SIZE] + merged_tail


def _variant_builders() -> list[tuple[str, Callable[[bytes, bytes], bytes]]]:
    return [
        ("baseline", lambda target, donor: target),
        ("tail_full", lambda target, donor: _replace_tail(target, donor, 0, TAIL_SIZE)),
        ("tail_first4", lambda target, donor: _replace_tail(target, donor, 0, 4)),
        ("tail_first12", lambda target, donor: _replace_tail(target, donor, 0, 12)),
        ("tail_first32", lambda target, donor: _replace_tail(target, donor, 0, 32)),
        ("tail_first64", lambda target, donor: _replace_tail(target, donor, 0, 64)),
        ("tail_utf16_a", lambda target, donor: _replace_tail(target, donor, 12, 76)),
        ("tail_utf16_b", lambda target, donor: _replace_tail(target, donor, 76, 140)),
        ("tail_utf16_both", lambda target, donor: _replace_tail(target, donor, 12, 140)),
        ("tail_last16", lambda target, donor: _replace_tail(target, donor, 176, 192)),
    ]


def _ascii_name(source_name: str, donor_name: str, variant_name: str, suffix: str) -> str:
    token = hashlib.md5(f"{source_name}|{donor_name}|{variant_name}".encode("utf-8")).hexdigest()[:16]
    return f"{variant_name}_{token}{suffix}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Try converting failed QQ encrypted variants into old-chain compatible inputs.")
    parser.add_argument(
        "--input-dir",
        default=r"O:\QKKDecrypt UI\i",
        help="Directory containing QQ encrypted files.",
    )
    parser.add_argument(
        "--source",
        default="伊然 - 尝尽世间万般苦 (有种想哭的冲动)_H.mgg",
        help="Failing encrypted sample to mutate.",
    )
    parser.add_argument(
        "--donor",
        action="append",
        default=[
            "刘晓超 - 旧梦_H.mgg",
            "安儿陈 - 我用一生等你_H.mgg",
        ],
        help="Successful encrypted sample whose tail will be borrowed. Can be passed multiple times.",
    )
    parser.add_argument(
        "--work-dir",
        default=r"O:\A_python\A_QQd\_log\oldchain_variant_experiment",
        help="Working directory for variants and outputs.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    work_dir = Path(args.work_dir)
    variant_dir = work_dir / "variants"
    output_dir = work_dir / "decrypted"
    variant_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    source_path = input_dir / args.source
    source_bytes = source_path.read_bytes()

    gateway = FridaDecryptGateway()
    transcoder = FfmpegTranscoder()

    results: list[VariantResult] = []
    builders = _variant_builders()

    for donor_name in args.donor:
        donor_path = input_dir / donor_name
        donor_bytes = donor_path.read_bytes()

        for variant_name, builder in builders:
            encrypted_variant = builder(source_bytes, donor_bytes)
            variant_file_name = _ascii_name(source_path.name, donor_path.name, variant_name, source_path.suffix)
            variant_path = variant_dir / variant_file_name
            decrypted_path = output_dir / (Path(variant_file_name).stem + ".ogg")

            variant_path.write_bytes(encrypted_variant)
            if decrypted_path.exists():
                decrypted_path.unlink()

            decrypt_success = False
            try:
                decrypt_success = gateway.decrypt_file(str(variant_path), str(decrypted_path))
            except Exception:
                decrypt_success = False

            detected_container = "missing"
            recognition_stage = "missing"
            summary: dict[str, object] = {}
            decrypted_size = decrypted_path.stat().st_size if decrypted_path.exists() else 0
            if decrypted_path.exists():
                detected_container, recognition_stage = transcoder.detect_audio_container(str(decrypted_path))
                summary = transcoder.probe_media_summary(str(decrypted_path))

            results.append(
                VariantResult(
                    name=f"{donor_path.name}:{variant_name}",
                    encrypted_path=str(variant_path),
                    decrypted_path=str(decrypted_path),
                    detected_container=detected_container,
                    recognition_stage=recognition_stage,
                    summary=summary,
                    decrypt_success=decrypt_success,
                    encrypted_size=variant_path.stat().st_size,
                    decrypted_size=decrypted_size,
                )
            )

    report = {
        "source": str(source_path),
        "donors": args.donor,
        "results": [asdict(item) for item in results],
    }
    report_path = work_dir / "report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
