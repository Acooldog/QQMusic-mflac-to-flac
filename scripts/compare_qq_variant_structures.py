from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


ASCII_PATTERN = re.compile(rb"[ -~]{4,}")


@dataclass
class SampleReport:
    name: str
    size: int
    md5_head256: str
    md5_tail192: str
    md5_tail512: str
    head64_hex: str
    tail192_hex: str
    tail64_hex: str
    ascii_tail_strings: list[str]
    tail_u32_le: list[int]
    marker_offsets: dict[str, list[int]]


def _find_all(data: bytes, needle: bytes, limit: int = 16) -> list[int]:
    positions: list[int] = []
    start = 0
    while len(positions) < limit:
        idx = data.find(needle, start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + 1
    return positions


def _report_for(path: Path) -> SampleReport:
    data = path.read_bytes()
    head256 = data[:256]
    tail192 = data[-192:]
    tail512 = data[-512:]
    ascii_tail_strings = [
        match.group().decode("ascii", "ignore")
        for match in ASCII_PATTERN.finditer(data[-4096:])
    ][:20]
    marker_offsets = {
        "ID3": _find_all(data, b"ID3"),
        "fLaC": _find_all(data, b"fLaC"),
        "OggS": _find_all(data, b"OggS"),
    }
    return SampleReport(
        name=path.name,
        size=len(data),
        md5_head256=hashlib.md5(head256).hexdigest(),
        md5_tail192=hashlib.md5(tail192).hexdigest(),
        md5_tail512=hashlib.md5(tail512).hexdigest(),
        head64_hex=head256[:64].hex(),
        tail192_hex=tail192.hex(),
        tail64_hex=tail512[-64:].hex(),
        ascii_tail_strings=ascii_tail_strings,
        tail_u32_le=[
            int.from_bytes(tail192[idx : idx + 4], "little")
            for idx in range(0, min(64, len(tail192)), 4)
        ],
        marker_offsets=marker_offsets,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare QQ encrypted file variants.")
    parser.add_argument(
        "--input-dir",
        default=r"O:\QKKDecrypt UI\i",
        help="Directory containing QQ encrypted files.",
    )
    parser.add_argument(
        "--output",
        default=r"O:\A_python\A_QQd\_log\variant_compare_report.json",
        help="Path to write the comparison report JSON.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output = Path(args.output)

    samples = {
        "success": [
            "安儿陈 - 我用一生等你_H.mgg",
            "刘晓超 - 旧梦_H.mgg",
            "安静 - 红颜知己_H.mgg",
            "凤凰传奇 - 最炫民族风_H.mgg",
            "那英 - 春暖花开_L.mgg",
        ],
        "fail": [
            "伊然 - 尝尽世间万般苦 (有种想哭的冲动)_H.mgg",
            "刀郎 - 手心里的温柔 (慢三版)_L.mgg",
            "周华健 - 朋友_H.mgg",
            "邓丽君 - 小城故事_H.mgg",
            "陈瑞 - 情罪_H.mgg",
        ],
    }

    report: dict[str, list[dict[str, object]]] = {}
    for group_name, sample_names in samples.items():
        entries: list[dict[str, object]] = []
        for sample_name in sample_names:
            path = input_dir / sample_name
            entries.append(asdict(_report_for(path)))
        report[group_name] = entries

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
