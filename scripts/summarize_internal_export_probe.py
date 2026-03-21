import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


PATH_RE = re.compile(r"[A-Za-z]:\\[^\\\r\n\"']+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize QQ internal export probe logs.")
    parser.add_argument("--log", required=True, help="Path to probe_internal_*.jsonl")
    parser.add_argument("--out", help="Optional output summary json path")
    return parser.parse_args()


def safe_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(str(value), 16)
    except Exception:
        return None


def walk_strings(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        for value in obj.values():
            found.extend(walk_strings(value))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(walk_strings(value))
    elif isinstance(obj, str):
        found.append(obj)
    return found


def extract_paths(obj: Any) -> list[str]:
    paths: list[str] = []
    for text in walk_strings(obj):
        for match in PATH_RE.findall(text):
            paths.append(match)
    return paths


def find_entry_by_offset(entries: list[dict[str, Any]] | None, offset: str) -> dict[str, Any] | None:
    if not entries:
        return None
    for entry in entries:
        if entry.get("offset") == offset:
            return entry
    return None


def best_text(entry: dict[str, Any] | None) -> str | None:
    if not entry:
        return None
    return entry.get("utf16") or entry.get("ansi")


def add_hex_int(ptr_text: str | None, offset: int) -> str | None:
    if not ptr_text:
        return None
    try:
        return hex(int(str(ptr_text), 16) + offset)
    except Exception:
        return None


def latest_export_arg(records: list[dict[str, Any]], export_name: str, arg_index: int) -> str | None:
    for record in reversed(records):
        if record.get("name") != export_name:
            continue
        args = record.get("args") or []
        if len(args) <= arg_index:
            continue
        desc = args[arg_index].get("desc") or {}
        text = desc.get("utf16") or desc.get("ansi")
        if text:
            return text
    return None


def unique_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def main() -> int:
    args = parse_args()
    log_path = Path(args.log)
    if not log_path.exists():
        raise SystemExit(f"log not found: {log_path}")

    records: list[dict[str, Any]] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    name_counter = Counter()
    deliver_state_records: list[dict[str, Any]] = []
    deliver_helper_records: list[dict[str, Any]] = []
    deliver_core_records: list[dict[str, Any]] = []
    flac_records: list[dict[str, Any]] = []

    for record in records:
        name = record.get("name")
        kind = record.get("kind")
        if name:
            name_counter[name] += 1
        if kind == "internal_enter" and name == "QQMusic.dll+deliver_state":
            deliver_state_records.append(record)
        elif kind == "internal_enter" and name == "QQMusic.dll+deliver_helper":
            deliver_helper_records.append(record)
        elif kind == "internal_enter" and name == "QQMusic.dll+deliver_core":
            deliver_core_records.append(record)
        elif kind == "export_enter" and isinstance(name, str) and name.startswith("qmp_flac.dll!"):
            flac_records.append(record)

    latest_state = deliver_state_records[-1] if deliver_state_records else None
    latest_helper = deliver_helper_records[-1] if deliver_helper_records else None
    latest_core = deliver_core_records[-1] if deliver_core_records else None
    latest_copy_entry = None
    latest_copy_build = None
    latest_copy_lookup = None
    latest_copy_queue = None

    for record in records:
        if record.get("kind") == "internal_enter" and record.get("name") == "QQMusic.dll+copy_async_entry":
            latest_copy_entry = record
        elif record.get("kind") == "internal_enter" and record.get("name") == "QQMusic.dll+copy_async_build":
            latest_copy_build = record
        elif record.get("kind") == "internal_enter" and record.get("name") == "QQMusic.dll+copy_async_lookup":
            latest_copy_lookup = record
        elif record.get("kind") == "internal_enter" and record.get("name") == "QQMusic.dll+copy_async_queue":
            latest_copy_queue = record

    state_arg4 = None
    helper_arg2 = None
    helper_arg3 = None
    helper_arg4 = None
    core_ecx = None
    core_arg1 = None
    copy_entry_ecx = None
    vector_item0 = None
    vector_item1 = None
    relation_summary: dict[str, Any] = {}

    if latest_state:
        stack_args = latest_state.get("stack_args", [])
        if len(stack_args) > 4:
            state_arg4 = safe_int(stack_args[4].get("desc", {}).get("raw"))
    if latest_helper:
        stack_args = latest_helper.get("stack_args", [])
        if len(stack_args) > 2:
            helper_arg2 = safe_int(stack_args[2].get("desc", {}).get("raw"))
        if len(stack_args) > 3:
            helper_arg3 = safe_int(stack_args[3].get("desc", {}).get("raw"))
        if len(stack_args) > 4:
            helper_arg4 = safe_int(stack_args[4].get("desc", {}).get("raw"))
    if latest_core:
        core_ecx = safe_int(latest_core.get("ecx"))
        stack_args = latest_core.get("stack_args", [])
        if len(stack_args) > 1:
            core_arg1 = safe_int(stack_args[1].get("desc", {}).get("raw"))
    if latest_copy_entry:
        copy_entry_ecx = safe_int(latest_copy_entry.get("ecx"))
        vec = ((latest_copy_entry.get("replay_candidate") or {}).get("items_vector")) or {}
        vector_item0 = (vec.get("first_item") or {}).get("raw")
        vector_item1 = (vec.get("second_item") or {}).get("raw")

    if core_ecx is not None:
        relation_summary["core_ecx"] = hex(core_ecx)
        relation_summary["owner_base_expected"] = hex(core_ecx - 0x40)
    if state_arg4 is not None:
        relation_summary["state_arg4"] = hex(state_arg4)
    if helper_arg3 is not None:
        relation_summary["helper_arg3"] = hex(helper_arg3)
    if helper_arg4 is not None:
        relation_summary["helper_arg4"] = hex(helper_arg4)
    if core_arg1 is not None:
        relation_summary["core_arg1"] = hex(core_arg1)
    if copy_entry_ecx is not None:
        relation_summary["copy_entry_ecx"] = hex(copy_entry_ecx)
    if vector_item0 is not None:
        relation_summary["vector_item0"] = vector_item0
    if vector_item1 is not None:
        relation_summary["vector_item1"] = vector_item1
    if helper_arg2 is not None:
        relation_summary["helper_arg2"] = hex(helper_arg2)
    if core_ecx is not None and state_arg4 is not None:
        relation_summary["state_matches_core_minus_0x40"] = state_arg4 == core_ecx - 0x40
    if core_ecx is not None and helper_arg3 is not None:
        relation_summary["helper_matches_core_ecx"] = helper_arg3 == core_ecx
    if copy_entry_ecx is not None and core_ecx is not None:
        relation_summary["copy_entry_matches_core_ecx"] = copy_entry_ecx == core_ecx
    if vector_item0 is not None and helper_arg2 is not None:
        relation_summary["helper_arg2_matches_vector_item0"] = hex(helper_arg2) == vector_item0
    if vector_item1 is not None:
        relation_summary["vector_item1_plus_0x8c"] = add_hex_int(vector_item1, 0x8C)
    if vector_item1 is not None and core_arg1 is not None:
        relation_summary["core_arg1_matches_item1_plus_0x8c"] = (
            add_hex_int(vector_item1, 0x8C) == hex(core_arg1)
        )
    if vector_item1 is not None and helper_arg4 is not None:
        relation_summary["helper_arg4_matches_item1_plus_0x8c"] = (
            add_hex_int(vector_item1, 0x8C) == hex(helper_arg4)
        )

    extracted_fields: dict[str, Any] = {}
    if latest_state:
        state_stack = latest_state.get("stack_args") or []
        source_arg = state_stack[0] if state_stack else {}
        source_nested = source_arg.get("nested") or []
        extracted_fields["source_url_primary"] = best_text(find_entry_by_offset(source_nested, "0x34"))
        extracted_fields["source_url_secondary"] = best_text(find_entry_by_offset(source_nested, "0x38"))
        extracted_fields["source_cache_path"] = best_text(find_entry_by_offset(source_nested, "0x3c"))
    if latest_helper:
        helper_stack = latest_helper.get("stack_args") or []
        helper_src_arg = helper_stack[2] if len(helper_stack) > 2 else {}
        helper_src_probe = helper_src_arg.get("object_probe") or []
        extracted_fields["helper_source_cache_path"] = best_text(find_entry_by_offset(helper_src_probe, "0x3c"))
        extracted_fields["helper_source_output_path"] = best_text(find_entry_by_offset(helper_src_probe, "0x14c"))
        extracted_fields["helper_source_cover_path"] = best_text(find_entry_by_offset(helper_src_probe, "0x150"))
        helper_out_arg = helper_stack[4] if len(helper_stack) > 4 else {}
        helper_out_probe = helper_out_arg.get("object_probe") or []
        extracted_fields["helper_output_path"] = best_text(find_entry_by_offset(helper_out_probe, "0x0"))
        extracted_fields["helper_cover_path"] = best_text(find_entry_by_offset(helper_out_probe, "0x4"))
        extracted_fields["helper_output_owner_or_context"] = best_text(find_entry_by_offset(helper_out_probe, "0x10"))
    if latest_core:
        core_candidate = latest_core.get("replay_candidate") or {}
        core_out = ((core_candidate.get("arg1_output") or {}).get("object_probe")) or []
        extracted_fields["core_output_path"] = best_text(find_entry_by_offset(core_out, "0x0"))
        extracted_fields["core_cover_path"] = best_text(find_entry_by_offset(core_out, "0x4"))
        ecx_probe = latest_core.get("ecx_probe") or []
        context_out = find_entry_by_offset(ecx_probe, "0x158") or {}
        extracted_fields["context_cached_output_paths"] = [
            best_text(item)
            for item in (context_out.get("nested") or [])
            if best_text(item)
        ]
    if latest_copy_entry:
        entry_candidate = latest_copy_entry.get("replay_candidate") or {}
        entry_mgr_probe = ((entry_candidate.get("manager_this") or {}).get("object_probe")) or []
        extracted_fields["copy_entry_manager_plus_0x40"] = best_text(find_entry_by_offset(entry_mgr_probe, "0x40"))
        extracted_fields["copy_entry_manager_plus_0x108"] = best_text(find_entry_by_offset(entry_mgr_probe, "0x108"))
        vec = entry_candidate.get("items_vector") or {}
        item0_probe = ((vec.get("first_item") or {}).get("object_probe")) or []
        extracted_fields["entry_item0_cache_path"] = best_text(find_entry_by_offset(item0_probe, "0x3c"))
        extracted_fields["entry_item0_output_path"] = best_text(find_entry_by_offset(item0_probe, "0x14c"))
        extracted_fields["entry_item0_cover_path"] = best_text(find_entry_by_offset(item0_probe, "0x150"))
        extracted_fields["entry_item0_numeric_0x50_0x64"] = {
            "0x50": (find_entry_by_offset(item0_probe, "0x50") or {}).get("u32"),
            "0x54": (find_entry_by_offset(item0_probe, "0x54") or {}).get("u32"),
            "0x58": (find_entry_by_offset(item0_probe, "0x58") or {}).get("ptr"),
            "0x5c": (find_entry_by_offset(item0_probe, "0x5c") or {}).get("u32"),
            "0x60": (find_entry_by_offset(item0_probe, "0x60") or {}).get("u32"),
            "0x64": (find_entry_by_offset(item0_probe, "0x64") or {}).get("u32"),
        }
        item1_probe = ((vec.get("second_item") or {}).get("object_probe")) or []
        item1_sub = find_entry_by_offset(item1_probe, "0x8c") or {}
        extracted_fields["vector_item1_plus_0x8c_ptr"] = item1_sub.get("ptr")
        nested = item1_sub.get("nested") or []
        extracted_fields["vector_item1_plus_0x8c_cache_prefix"] = best_text(find_entry_by_offset(nested, "0x28"))
        extracted_fields["vector_item1_plus_0x8c_cache_prefix_dup"] = best_text(find_entry_by_offset(nested, "0x2c"))
        extracted_fields["vector_item1_plus_0x8c_meta_blob"] = best_text(find_entry_by_offset(nested, "0x40"))
        extracted_fields["vector_item1_state_word_0x14c"] = (
            (find_entry_by_offset(item1_probe, "0x14c") or {}).get("ptr")
        )
        extracted_fields["vector_item1_numeric_0x50_0x64"] = {
            "0x50": (find_entry_by_offset(item1_probe, "0x50") or {}).get("u32"),
            "0x54": (find_entry_by_offset(item1_probe, "0x54") or {}).get("u32"),
            "0x58": (find_entry_by_offset(item1_probe, "0x58") or {}).get("ptr"),
            "0x5c": (find_entry_by_offset(item1_probe, "0x5c") or {}).get("u32"),
            "0x60": (find_entry_by_offset(item1_probe, "0x60") or {}).get("u32"),
            "0x64": (find_entry_by_offset(item1_probe, "0x64") or {}).get("u32"),
        }
    if latest_copy_build:
        build_candidate = latest_copy_build.get("replay_candidate") or {}
        build_item0 = ((build_candidate.get("item_arg0") or {}).get("object_probe")) or []
        extracted_fields["build_item0_cache_path"] = best_text(find_entry_by_offset(build_item0, "0x3c"))
        extracted_fields["build_item0_output_path"] = best_text(find_entry_by_offset(build_item0, "0x14c"))
        extracted_fields["build_item0_cover_path"] = best_text(find_entry_by_offset(build_item0, "0x150"))
        extracted_fields["build_item0_numeric_0x50_0x64"] = {
            "0x50": (find_entry_by_offset(build_item0, "0x50") or {}).get("u32"),
            "0x54": (find_entry_by_offset(build_item0, "0x54") or {}).get("u32"),
            "0x58": (find_entry_by_offset(build_item0, "0x58") or {}).get("ptr"),
            "0x5c": (find_entry_by_offset(build_item0, "0x5c") or {}).get("u32"),
            "0x60": (find_entry_by_offset(build_item0, "0x60") or {}).get("u32"),
            "0x64": (find_entry_by_offset(build_item0, "0x64") or {}).get("u32"),
        }
    if latest_copy_lookup:
        lookup_candidate = latest_copy_lookup.get("replay_candidate") or {}
        lookup_item0 = ((lookup_candidate.get("item_arg0") or {}).get("object_probe")) or []
        extracted_fields["lookup_item0_cache_path"] = best_text(find_entry_by_offset(lookup_item0, "0x3c"))
        extracted_fields["lookup_item0_output_path"] = best_text(find_entry_by_offset(lookup_item0, "0x14c"))
        extracted_fields["lookup_item0_cover_path"] = best_text(find_entry_by_offset(lookup_item0, "0x150"))
        extracted_fields["lookup_item0_numeric_0x50_0x64"] = {
            "0x50": (find_entry_by_offset(lookup_item0, "0x50") or {}).get("u32"),
            "0x54": (find_entry_by_offset(lookup_item0, "0x54") or {}).get("u32"),
            "0x58": (find_entry_by_offset(lookup_item0, "0x58") or {}).get("ptr"),
            "0x5c": (find_entry_by_offset(lookup_item0, "0x5c") or {}).get("u32"),
            "0x60": (find_entry_by_offset(lookup_item0, "0x60") or {}).get("u32"),
            "0x64": (find_entry_by_offset(lookup_item0, "0x64") or {}).get("u32"),
        }
    if latest_copy_queue:
        queue_candidate = latest_copy_queue.get("replay_candidate") or {}
        queue_item0 = ((queue_candidate.get("item_arg0") or {}).get("object_probe")) or []
        extracted_fields["queue_item0_cache_path"] = best_text(find_entry_by_offset(queue_item0, "0x3c"))
        extracted_fields["queue_item0_output_path"] = best_text(find_entry_by_offset(queue_item0, "0x14c"))
        extracted_fields["queue_item0_cover_path"] = best_text(find_entry_by_offset(queue_item0, "0x150"))
        extracted_fields["queue_item0_numeric_0x50_0x64"] = {
            "0x50": (find_entry_by_offset(queue_item0, "0x50") or {}).get("u32"),
            "0x54": (find_entry_by_offset(queue_item0, "0x54") or {}).get("u32"),
            "0x58": (find_entry_by_offset(queue_item0, "0x58") or {}).get("ptr"),
            "0x5c": (find_entry_by_offset(queue_item0, "0x5c") or {}).get("u32"),
            "0x60": (find_entry_by_offset(queue_item0, "0x60") or {}).get("u32"),
            "0x64": (find_entry_by_offset(queue_item0, "0x64") or {}).get("u32"),
        }

    extracted_fields["flac_metadata_output_path"] = latest_export_arg(
        flac_records, "qmp_flac.dll!QMP_FLAC__metadata_simple_iterator_init", 1
    )
    extracted_fields["flac_album_art_output_path"] = latest_export_arg(
        flac_records, "qmp_flac.dll!QMP_FLAC__metadata_set_album_art", 0
    )
    extracted_fields["flac_album_art_cover_path"] = latest_export_arg(
        flac_records, "qmp_flac.dll!QMP_FLAC__metadata_set_album_art", 1
    )
    extracted_fields["flac_import_pic_cover_path"] = latest_export_arg(
        flac_records, "qmp_flac.dll!QMP_FLAC__import_pic_from", 2
    )

    source_paths = unique_keep_order(
        extract_paths(latest_state) + extract_paths(latest_helper) + extract_paths(latest_core)
    )
    flac_paths = unique_keep_order(extract_paths(flac_records))

    summary = {
        "log_path": str(log_path),
        "record_count": len(records),
        "counts": dict(name_counter),
        "latest_relations": relation_summary,
        "extracted_fields": extracted_fields,
        "source_related_paths": source_paths,
        "flac_chain_paths": flac_paths,
        "latest_state": latest_state,
        "latest_helper": latest_helper,
        "latest_core": latest_core,
        "latest_copy_entry": latest_copy_entry,
        "latest_copy_build": latest_copy_build,
        "latest_copy_lookup": latest_copy_lookup,
        "latest_copy_queue": latest_copy_queue,
    }

    out_path = Path(args.out) if args.out else log_path.with_suffix(".summary.json")
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
