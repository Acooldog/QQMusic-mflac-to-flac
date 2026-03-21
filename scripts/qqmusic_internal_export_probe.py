import argparse
import json
import os
import sys
import time
from pathlib import Path

import frida

QQ_RVAS = {
    "copy_async_entry": 0x184730,
    "copy_async_stage": 0x17EC70,
    "copy_async_lookup": 0x17ED10,
    "copy_async_queue": 0x17EF10,
    "copy_async_build": 0x17EFC0,
    "decrypt_cache_file": 0x1845C0,
    "deliver_core": 0x185480,
    "deliver_open_path": 0x185110,
    "deliver_state": 0x189B00,
    "deliver_helper": 0x4B7D60,
}

OBJ_OFFSETS = [0x3C, 0x64, 0x100, 0x140, 0x144, 0x148, 0x14C, 0x150, 0x154, 0x158, 0x15C, 0x160]
SOURCE_ARG_OFFSETS = [0x34, 0x38, 0x3C]
ITEM_RUNTIME_OFFSETS = [
    0x34,
    0x38,
    0x3C,
    0x50,
    0x54,
    0x58,
    0x5C,
    0x60,
    0x64,
    0x68,
    0x6C,
    0x70,
    0x74,
    0x78,
    0x7C,
    0x80,
    0x84,
    0x88,
    0x8C,
    0x98,
    0x100,
    0x118,
    0x11C,
    0x124,
    0x12C,
    0x148,
    0x14C,
    0x150,
    0x154,
    0x158,
]
ITEM_ARG_OFFSETS = [
    0x34,
    0x38,
    0x3C,
    0x40,
    0x44,
    0x48,
    0x4C,
    0x50,
    0x54,
    0x58,
    0x5C,
    0x60,
    0x64,
    0x68,
    0x6C,
    0x70,
    0x74,
    0x78,
    0x7C,
    0x80,
    0x84,
    0x88,
    0x8C,
    0x100,
    0x118,
    0x11C,
    0x124,
    0x12C,
    0x148,
    0x14C,
    0x150,
    0x154,
    0x158,
]
OUTPUT_ARG_OFFSETS = [0x0, 0x4, 0x8, 0xC, 0x10, 0x14, 0x5C]
DECRYPT_CACHE_ARG_OFFSETS = [0x0, 0x4, 0x8, 0xC]
HELPER_OUTPUT_ARG_OFFSETS = [0x0, 0x4, 0x8, 0xC, 0x10]
HELPER_CONTEXT_ARG_OFFSETS = [0x140, 0x144, 0x148, 0x14C, 0x150, 0x154, 0x158, 0x15C, 0x160]
MANAGER_OFFSETS = [0x8, 0xC, 0x28, 0x30, 0x34, 0x3C, 0x40, 0x48, 0x108]
OWNER_BASE_OFFSETS = [0x0, 0x4, 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40]
NESTED_SCAN_OFFSETS = [
    0x0,
    0x4,
    0x8,
    0xC,
    0x10,
    0x14,
    0x18,
    0x1C,
    0x20,
    0x24,
    0x28,
    0x2C,
    0x30,
    0x34,
    0x38,
    0x3C,
    0x40,
    0x44,
    0x48,
    0x4C,
    0x50,
    0x54,
    0x58,
    0x5C,
    0x60,
    0x64,
    0x68,
    0x6C,
    0x70,
    0x74,
    0x78,
    0x7C,
]


def find_qqmusic_pid() -> int | None:
    for line in os.popen('tasklist /FI "IMAGENAME eq QQMusic.exe" /FO CSV /NH').read().splitlines():
        if "QQMusic.exe" not in line:
            continue
        parts = [p.strip('"') for p in line.split(',')]
        if len(parts) > 1:
            return int(parts[1])
    return None


def build_script_source(sample_name: str) -> str:
    sample_json = json.dumps(sample_name, ensure_ascii=False)
    qq_rvas_json = json.dumps(QQ_RVAS)
    obj_offsets_json = json.dumps(OBJ_OFFSETS)
    source_arg_offsets_json = json.dumps(SOURCE_ARG_OFFSETS)
    item_runtime_offsets_json = json.dumps(ITEM_RUNTIME_OFFSETS)
    item_arg_offsets_json = json.dumps(ITEM_ARG_OFFSETS)
    output_arg_offsets_json = json.dumps(OUTPUT_ARG_OFFSETS)
    decrypt_cache_arg_offsets_json = json.dumps(DECRYPT_CACHE_ARG_OFFSETS)
    helper_output_arg_offsets_json = json.dumps(HELPER_OUTPUT_ARG_OFFSETS)
    helper_context_arg_offsets_json = json.dumps(HELPER_CONTEXT_ARG_OFFSETS)
    manager_offsets_json = json.dumps(MANAGER_OFFSETS)
    owner_base_offsets_json = json.dumps(OWNER_BASE_OFFSETS)
    nested_offsets_json = json.dumps(NESTED_SCAN_OFFSETS)
    return f"""
const sampleName = {sample_json};
const qqRvas = {qq_rvas_json};
const objOffsets = {obj_offsets_json};
const sourceArgOffsets = {source_arg_offsets_json};
const itemRuntimeOffsets = {item_runtime_offsets_json};
const itemArgOffsets = {item_arg_offsets_json};
const outputArgOffsets = {output_arg_offsets_json};
const decryptCacheArgOffsets = {decrypt_cache_arg_offsets_json};
const helperOutputArgOffsets = {helper_output_arg_offsets_json};
const helperContextArgOffsets = {helper_context_arg_offsets_json};
const managerOffsets = {manager_offsets_json};
const ownerBaseOffsets = {owner_base_offsets_json};
const nestedOffsets = {nested_offsets_json};
const counts = {{}};

function sendEvent(kind, payload) {{
  send(Object.assign({{ kind, ts: Date.now() / 1000 }}, payload || {{}}));
}}

function limited(key, limit) {{
  const next = (counts[key] || 0) + 1;
  counts[key] = next;
  return next <= limit;
}}

function safeReadU32(ptr) {{
  try {{
    return ptr.readU32();
  }} catch (_) {{
    return null;
  }}
}}

function safeReadPointer(ptr) {{
  try {{
    return ptr.readPointer();
  }} catch (_) {{
    return null;
  }}
}}

function tryAnsi(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const s = ptr.readCString();
    if (!s || s.length === 0 || s.length > 520) return null;
    return s;
  }} catch (_) {{
    return null;
  }}
}}

function tryUtf16(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const s = ptr.readUtf16String();
    if (!s || s.length === 0 || s.length > 520) return null;
    return s;
  }} catch (_) {{
    return null;
  }}
}}

function looksInteresting(s) {{
  if (!s) return false;
  const lower = String(s).toLowerCase();
  return lower.indexOf(sampleName.toLowerCase()) !== -1 ||
         lower.indexOf('music') !== -1 ||
         lower.indexOf('flac') !== -1 ||
         lower.indexOf('qqmusicpicture') !== -1 ||
         lower.indexOf('cover') !== -1 ||
         lower.indexOf('album') !== -1;
}}

function describePtr(ptr) {{
  if (!ptr) return null;
  const out = {{ raw: ptr.toString() }};
  const ansi = tryAnsi(ptr);
  const utf16 = tryUtf16(ptr);
  if (looksInteresting(ansi)) out.ansi = ansi;
  if (looksInteresting(utf16)) out.utf16 = utf16;
  return out;
}}

function inspectNested(ptr, offsets) {{
  if (!ptr || ptr.isNull()) return [];
  const results = [];
  for (const off of offsets) {{
    try {{
      const slot = ptr.add(off);
      const value = safeReadPointer(slot);
      if (!value || value.isNull()) continue;
      const entry = {{
        offset: '0x' + off.toString(16),
        slot: slot.toString(),
        ptr: value.toString(),
      }};
      const ansi = tryAnsi(value);
      const utf16 = tryUtf16(value);
      if (looksInteresting(ansi)) entry.ansi = ansi;
      if (looksInteresting(utf16)) entry.utf16 = utf16;
      if (entry.ansi || entry.utf16) results.push(entry);
    }} catch (_) {{}}
  }}
  return results;
}}

function inspectObject(basePtr) {{
  return inspectPointerFields(basePtr, objOffsets);
}}

function inspectPointerFields(basePtr, offsets) {{
  if (!basePtr || basePtr.isNull()) return null;
  const result = [];
  for (const off of offsets) {{
    try {{
      const slot = basePtr.add(off);
      const value = safeReadPointer(slot);
      const entry = {{
        offset: '0x' + off.toString(16),
        slot: slot.toString(),
        u32: safeReadU32(slot),
        ptr: value ? value.toString() : null
      }};
      if (value && !value.isNull()) {{
        const ansi = tryAnsi(value);
        const utf16 = tryUtf16(value);
        if (looksInteresting(ansi)) entry.ansi = ansi;
        if (looksInteresting(utf16)) entry.utf16 = utf16;
        const nested = inspectNested(value, nestedOffsets);
        if (nested.length) entry.nested = nested;
      }}
      result.push(entry);
    }} catch (e) {{
      result.push({{ offset: '0x' + off.toString(16), error: String(e) }});
    }}
  }}
  return result;
}}

function inspectVector(ptr, itemSize, maxItems) {{
  if (!ptr || ptr.isNull()) return null;
  try {{
    const begin = safeReadPointer(ptr);
    const end = safeReadPointer(ptr.add(4));
    const out = {{
      begin: begin ? begin.toString() : null,
      end: end ? end.toString() : null,
      item_size: itemSize,
    }};
    if (!begin || !end || begin.isNull() || end.isNull()) {{
      return out;
    }}
    const delta = end.sub(begin).toInt32();
    out.delta = delta;
    out.count = itemSize > 0 ? Math.floor(delta / itemSize) : null;
    if (out.count !== null && out.count > 0 && out.count <= (maxItems || 4)) {{
      out.first_item = makeSnapshot('vector_item0', begin, itemRuntimeOffsets, itemSize);
      if (out.count > 1) {{
        out.second_item = makeSnapshot('vector_item1', begin.add(itemSize), itemRuntimeOffsets, itemSize);
      }}
      try {{
        out.raw_items_hex = safeReadBytesHex(begin, itemSize * Math.min(out.count, maxItems || 4));
      }} catch (_) {{}}
    }}
    return out;
  }} catch (_) {{
    return null;
  }}
}}

function safeReadBytesHex(ptr, size) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const buf = ptr.readByteArray(size);
    if (!buf) return null;
    return Array.from(new Uint8Array(buf)).map(b => ('0' + b.toString(16)).slice(-2)).join('');
  }} catch (_) {{
    return null;
  }}
}}

function makeSnapshot(name, ptr, offsets, blobSize) {{
  if (!ptr || ptr.isNull()) return null;
  return {{
    name,
    raw: ptr.toString(),
    object_probe: inspectPointerFields(ptr, offsets),
    bytes_hex: safeReadBytesHex(ptr, blobSize || 64),
  }};
}}

function selectArgFieldOffsets(name, index) {{
  if (name === 'QQMusic.dll+decrypt_cache_file' && (index === 0 || index === 1)) return decryptCacheArgOffsets;
  if (name === 'QQMusic.dll+copy_async_stage' && index === 0) return itemRuntimeOffsets;
  if (name === 'QQMusic.dll+copy_async_lookup' && index === 0) return itemRuntimeOffsets;
  if (name === 'QQMusic.dll+copy_async_queue' && index === 0) return itemRuntimeOffsets;
  if (name === 'QQMusic.dll+copy_async_build' && index === 0) return itemRuntimeOffsets;
  if (name === 'QQMusic.dll+deliver_open_path' && index === 0) return itemArgOffsets;
  if (name === 'QQMusic.dll+deliver_core' && index === 0) return itemArgOffsets;
  if (name === 'QQMusic.dll+deliver_core' && index === 1) return outputArgOffsets;
  if (name === 'QQMusic.dll+deliver_helper' && index === 2) return itemArgOffsets;
  if (name === 'QQMusic.dll+deliver_helper' && index === 3) return helperContextArgOffsets;
  if (name === 'QQMusic.dll+deliver_helper' && index === 4) return helperOutputArgOffsets;
  return null;
}}

function bt(ctx) {{
  try {{
    return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 12).map(addr => {{
      const ds = DebugSymbol.fromAddress(addr);
      const mod = Process.findModuleByAddress(addr);
      return {{
        addr: addr.toString(),
        module: mod ? mod.name : null,
        symbol: ds ? ds.name : null
      }};
    }});
  }} catch (e) {{
    return [{{ error: String(e) }}];
  }}
}}

function hookByRva(moduleName, rvaName, rva) {{
  const mod = Process.findModuleByName(moduleName);
  if (!mod) {{
    sendEvent('missing_module', {{ module: moduleName, rvaName }});
    return;
  }}
  const address = mod.base.add(rva);
  const name = moduleName + '+' + rvaName;
  sendEvent('hooked_internal', {{ name, address: address.toString(), base: mod.base.toString(), rva: '0x' + rva.toString(16) }});
  Interceptor.attach(address, {{
    onEnter(args) {{
      this.capture = limited(name, 80);
      if (!this.capture) return;
      const ecx = this.context.ecx;
      const stackArgs = [];
      for (let i = 0; i < 6; i++) {{
        const desc = describePtr(args[i]);
        const nested = inspectNested(args[i], nestedOffsets);
        const entry = {{ index: i, desc, nested }};
        const argOffsets = selectArgFieldOffsets(name, i);
        if (argOffsets) {{
          const objectProbe = inspectPointerFields(args[i], argOffsets);
          if (objectProbe && objectProbe.length) entry.object_probe = objectProbe;
        }}
        stackArgs.push(entry);
      }}
      let replayCandidate = null;
      if (name === 'QQMusic.dll+deliver_core') {{
        replayCandidate = {{
          this_ptr: makeSnapshot('this', ecx, objOffsets, 96),
          owner_base: ecx && !ecx.isNull() ? makeSnapshot('owner_base', ecx.sub(0x40), ownerBaseOffsets, 96) : null,
          arg0_source: makeSnapshot('arg0_source', args[0], itemArgOffsets, 384),
          arg1_output: makeSnapshot('arg1_output', args[1], outputArgOffsets, 96),
        }};
      }} else if (name === 'QQMusic.dll+decrypt_cache_file') {{
        replayCandidate = {{
          arg0_source_path_field: makeSnapshot('arg0_source_path_field', args[0], decryptCacheArgOffsets, 64),
          arg1_output_path_field: makeSnapshot('arg1_output_path_field', args[1], decryptCacheArgOffsets, 64),
        }};
      }} else if (name === 'QQMusic.dll+deliver_helper') {{
        replayCandidate = {{
          helper_this: makeSnapshot('helper_this', ecx, objOffsets, 96),
          arg2_source: makeSnapshot('arg2_source', args[2], itemArgOffsets, 384),
          arg3_context: makeSnapshot('arg3_context', args[3], helperContextArgOffsets, 96),
          arg4_output: makeSnapshot('arg4_output', args[4], helperOutputArgOffsets, 96),
        }};
      }} else if (name === 'QQMusic.dll+deliver_open_path') {{
        replayCandidate = {{
          item_arg0: makeSnapshot('item_arg0', args[0], itemArgOffsets, 384),
        }};
      }} else if (name === 'QQMusic.dll+copy_async_entry') {{
        replayCandidate = {{
          manager_this: makeSnapshot('manager_this', ecx, managerOffsets, 192),
          items_vector: inspectVector(args[0], 0xC0, 4),
        }};
      }} else if (name === 'QQMusic.dll+copy_async_stage') {{
        replayCandidate = {{
          stage_this: makeSnapshot('stage_this', ecx, itemRuntimeOffsets, 0xC0),
          arg0_item: makeSnapshot('arg0_item', args[0], itemRuntimeOffsets, 0xC0),
        }};
      }} else if (name === 'QQMusic.dll+copy_async_lookup' || name === 'QQMusic.dll+copy_async_queue' || name === 'QQMusic.dll+copy_async_build') {{
        replayCandidate = {{
          manager_this: makeSnapshot('manager_this', ecx, managerOffsets, 192),
          item_arg0: makeSnapshot('item_arg0', args[0], itemRuntimeOffsets, 0xC0),
        }};
      }}
      sendEvent('internal_enter', {{
        name,
        ecx: ecx ? ecx.toString() : null,
        ecx_probe: inspectObject(ecx),
        stack_args: stackArgs,
        replay_candidate: replayCandidate,
        backtrace: bt(this.context),
      }});
    }},
    onLeave(retval) {{
      if (!this.capture) return;
      const out = {{ name, retval_raw: retval.toString() }};
      try {{ out.retval_u32 = retval.toUInt32(); }} catch (_) {{}}
      sendEvent('internal_leave', out);
    }}
  }});
}}

function hookExport(moduleName, exportName, argCount, limit) {{
  let mod = null;
  try {{
    mod = Process.findModuleByName(moduleName);
  }} catch (_) {{
    mod = null;
  }}
  if (!mod) {{
    sendEvent('missing_export_module', {{ module: moduleName, exportName }});
    return;
  }}
  let addr = null;
  try {{
    addr = mod.findExportByName(exportName);
  }} catch (_) {{
    addr = null;
  }}
  if (!addr) {{
    sendEvent('missing_export', {{ module: moduleName, exportName }});
    return;
  }}
  const name = moduleName + '!' + exportName;
  sendEvent('hooked_export', {{ name, address: addr.toString() }});
  Interceptor.attach(addr, {{
    onEnter(args) {{
      this.capture = limited(name, limit || 40);
      if (!this.capture) return;
      const payload = {{ name, args: [] }};
      for (let i = 0; i < argCount; i++) {{
        const desc = describePtr(args[i]);
        const nested = inspectNested(args[i], nestedOffsets);
        payload.args.push({{ index: i, desc, nested }});
      }}
      payload.backtrace = bt(this.context);
      sendEvent('export_enter', payload);
    }},
    onLeave(retval) {{
      if (!this.capture) return;
      const out = {{ name, retval_raw: retval.toString() }};
      try {{ out.retval_u32 = retval.toUInt32(); }} catch (_) {{}}
      sendEvent('export_leave', out);
    }}
  }});
}}

hookByRva('QQMusic.dll', 'decrypt_cache_file', qqRvas.decrypt_cache_file);
hookByRva('QQMusic.dll', 'copy_async_entry', qqRvas.copy_async_entry);
hookByRva('QQMusic.dll', 'copy_async_stage', qqRvas.copy_async_stage);
hookByRva('QQMusic.dll', 'copy_async_lookup', qqRvas.copy_async_lookup);
hookByRva('QQMusic.dll', 'copy_async_queue', qqRvas.copy_async_queue);
hookByRva('QQMusic.dll', 'copy_async_build', qqRvas.copy_async_build);
hookByRva('QQMusic.dll', 'deliver_core', qqRvas.deliver_core);
hookByRva('QQMusic.dll', 'deliver_open_path', qqRvas.deliver_open_path);
hookByRva('QQMusic.dll', 'deliver_state', qqRvas.deliver_state);
hookByRva('QQMusic.dll', 'deliver_helper', qqRvas.deliver_helper);

hookExport('qmp_flac.dll', 'Init', 4, 60);
hookExport('qmp_flac.dll', 'SetCallBack', 6, 60);
hookExport('qmp_flac.dll', 'QMP_FLAC__metadata_simple_iterator_init', 6, 60);
hookExport('qmp_flac.dll', 'QMP_FLAC__metadata_set_album_art', 6, 60);
hookExport('qmp_flac.dll', 'QMP_FLAC__import_pic_from', 4, 60);
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe QQ internal export path without UI automation.")
    parser.add_argument("--sample", required=True, help="Encrypted QQ sample file path for context.")
    parser.add_argument("--duration", type=int, default=60, help="Probe duration in seconds.")
    parser.add_argument(
        "--log-dir",
        default=str(Path(__file__).resolve().parents[1] / "_log" / "probe_qqmusic_play"),
        help="Directory for probe logs.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sample = Path(args.sample)
    if not sample.exists():
        print(f"sample not found: {sample}", file=sys.stderr)
        return 2

    pid = find_qqmusic_pid()
    if not pid:
        print("QQMusic.exe is not running", file=sys.stderr)
        return 2

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    started_at = int(time.time())
    log_path = log_dir / f"probe_internal_{started_at}.jsonl"
    control_path = log_dir / "probe_internal_control.json"
    stop_flag = log_dir / "probe_internal_stop.flag"
    if stop_flag.exists():
        stop_flag.unlink()

    meta = {
        "sample": str(sample),
        "started_at": started_at,
        "duration_sec": args.duration,
        "log_path": str(log_path),
        "status": "starting",
        "pid": pid,
        "stop_flag": str(stop_flag),
    }
    control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    session = None
    fh = None
    try:
        device = frida.get_local_device()
        session = device.attach(pid)
        script = session.create_script(build_script_source(sample.name))
        fh = log_path.open("w", encoding="utf-8")

        def on_message(message, data):
            record = message["payload"] if message["type"] == "send" else message
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()

        script.on("message", on_message)
        script.load()

        meta["status"] = "running"
        control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

        print(f"Internal export probe attached to PID={pid}")
        print(f"log: {log_path}")
        print(f"control: {control_path}")
        print(f"stop flag: {stop_flag}")

        deadline = time.time() + args.duration
        try:
            while time.time() < deadline:
                if stop_flag.exists():
                    meta["status"] = "stopped_by_flag"
                    control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
                    print("stopped by flag")
                    break
                time.sleep(1)
            else:
                meta["status"] = "completed"
                control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
                print("probe completed")
        except KeyboardInterrupt:
            meta["status"] = "stopped_by_keyboard"
            control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            print("stopped by Ctrl+C")
    finally:
        if fh:
            fh.close()
        if session:
            try:
                session.detach()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
