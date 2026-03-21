import argparse
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare two QQ internal export probe summaries.")
    parser.add_argument("--base", required=True, help="Base summary json")
    parser.add_argument("--new", required=True, help="New summary json")
    return parser.parse_args()


def load_json(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"summary not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> int:
    args = parse_args()
    base = load_json(args.base)
    new = load_json(args.new)

    base_rel = base.get("latest_relations") or {}
    new_rel = new.get("latest_relations") or {}
    base_fields = base.get("extracted_fields") or {}
    new_fields = new.get("extracted_fields") or {}

    keys = [
        "core_ecx",
        "owner_base_expected",
        "state_arg4",
        "helper_arg2",
        "helper_arg3",
        "helper_arg4",
        "core_arg1",
        "copy_entry_ecx",
        "vector_item0",
        "vector_item1",
        "vector_item1_plus_0x8c",
    ]

    print("== Relations ==")
    for key in keys:
        print(f"{key}:")
        print(f"  base: {base_rel.get(key)}")
        print(f"  new : {new_rel.get(key)}")

    field_keys = [
        "lookup_item0_cache_path",
        "lookup_item0_output_path",
        "lookup_item0_cover_path",
        "queue_item0_cache_path",
        "queue_item0_output_path",
        "queue_item0_cover_path",
        "build_item0_cache_path",
        "build_item0_output_path",
        "build_item0_cover_path",
        "entry_item0_cache_path",
        "entry_item0_output_path",
        "entry_item0_cover_path",
        "helper_source_cache_path",
        "helper_source_output_path",
        "helper_source_cover_path",
        "helper_output_path",
        "helper_cover_path",
        "core_output_path",
        "core_cover_path",
        "lookup_item0_numeric_0x50_0x64",
        "queue_item0_numeric_0x50_0x64",
        "build_item0_numeric_0x50_0x64",
        "entry_item0_numeric_0x50_0x64",
        "vector_item1_state_word_0x14c",
        "vector_item1_numeric_0x50_0x64",
    ]

    print("== Fields ==")
    for key in field_keys:
        base_value = base_fields.get(key)
        new_value = new_fields.get(key)
        if base_value == new_value:
            continue
        print(f"{key}:")
        print(f"  base: {json.dumps(base_value, ensure_ascii=False)}")
        print(f"  new : {json.dumps(new_value, ensure_ascii=False)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
