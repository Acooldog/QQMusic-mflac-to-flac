import argparse
import json
import os
import sys
import time
from pathlib import Path

import frida


QQ_RVAS = {
    "copy_async_entry": 0x184730,
}

# Captured from a successful QQ internal export run. We keep the opaque fields
# as-is and only patch the path/URL pointers so the experiment stays as close
# as possible to the real runtime item layout.
ITEM_TEMPLATE_HEX = (
    "07000000362700004077ea14301a311da40f897930003200f3d6cf0200000000"
    "f3d6cf02f3d6cf02f12af800584c311d00000000c8d3622070b1f81fa85f2f1f"
    "0300000000000000a40f8979a40f89790100000002000000050000002e005c00"
    "e81c7723020000000000000001000000e27c3700e3000000ffffffffc9000000"
    "8b1a000006000000d7fa03004077ea144019311d5018311d40872f1fa40f8979"
    "ffffffff00000000000000000000000000000000000000000000000000000000"
)

SECOND_ITEM_TEMPLATE_HEX = (
    "010000000037cb1d2f000000f88806232c8906232c8906230000000000000000"
    "000000000000000000000000000000006037cb1d000000000000000000050000"
    "ffffffff020500002aa84a9c000000008b1a00000605000000fcc82380180800"
    "100000007fff71010000000001000000000000007e0400000000000000000000"
    "a40f8979820400000200000020240623a40f897900000000a40f897901000000"
    "8006a22c81210401652304017b220401000000009015cd1d00000000a40f8979"
)


def find_qqmusic_pid() -> int | None:
    for line in os.popen('tasklist /FI "IMAGENAME eq QQMusic.exe" /FO CSV /NH').read().splitlines():
        if "QQMusic.exe" not in line:
            continue
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) > 1:
            return int(parts[1])
    return None


def build_script_source(config: dict) -> str:
    payload = json.dumps(config, ensure_ascii=False)
    return f"""
const config = {payload};

function sendEvent(kind, payload) {{
  send(Object.assign({{ kind, ts: Date.now() / 1000 }}, payload || {{}}));
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

function inspectManager(ptr) {{
  if (!ptr || ptr.isNull()) return null;
  const offsets = [0x0, 0x28, 0x30, 0x34, 0x40, 0x108, 0x148, 0x158];
  const out = [];
  for (const off of offsets) {{
    try {{
      const slot = ptr.add(off);
      const value = safeReadPointer(slot);
      const item = {{
        offset: '0x' + off.toString(16),
        u32: safeReadU32(slot),
        ptr: value ? value.toString() : null,
      }};
      const s = tryUtf16(value);
      if (s) item.utf16 = s;
      out.push(item);
    }} catch (e) {{
      out.push({{ offset: '0x' + off.toString(16), error: String(e) }});
    }}
  }}
  return out;
}}

function buildItem(rawHex, url1, url2, cachePath, streamUrl, outPath, patchPointers) {{
  const raw = rawHex.match(/../g).map((x) => parseInt(x, 16));
  const item = Memory.alloc(raw.length);
  item.writeByteArray(raw);

  if (!patchPointers) {{
    return item;
  }}

  const sUrl1 = Memory.allocUtf16String(url1);
  const sUrl2 = Memory.allocUtf16String(url2);
  const sCache = Memory.allocUtf16String(cachePath);
  const sStream = Memory.allocUtf16String(streamUrl);
  const sOut = Memory.allocUtf16String(outPath);

  item.add(0x34).writePointer(sUrl1);
  item.add(0x38).writePointer(sUrl2);
  item.add(0x3c).writePointer(sCache);
  item.add(0x98).writePointer(sStream);
  item.add(0x14c).writePointer(sOut);
  return item;
}}

function buildVector(items) {{
  const bytes = items.length * 0xC0;
  const base = Memory.alloc(bytes);
  for (let i = 0; i < items.length; i++) {{
    Memory.copy(base.add(i * 0xC0), items[i], 0xC0);
  }}
  const vec = Memory.alloc(12);
  vec.writePointer(base);
  vec.add(4).writePointer(base.add(bytes));
  vec.add(8).writePointer(base.add(bytes));
  return {{ vec, base }};
}}

function hookCreateFile() {{
  for (const modName of ['KernelBase.dll', 'KERNEL32.DLL']) {{
    const mod = Process.findModuleByName(modName);
    if (!mod) continue;
    const addr = mod.findExportByName('CreateFileW');
    if (!addr) continue;
    Interceptor.attach(addr, {{
      onEnter(args) {{
        try {{
          const path = args[0].readUtf16String();
          if (!path) return;
          const lower = path.toLowerCase();
          if (
            lower.indexOf('qqmusiccache') === -1 &&
            lower.indexOf('music') === -1 &&
            lower.indexOf('copy_async_entry_test') === -1
          ) {{
            return;
          }}
          sendEvent('CreateFileW_enter', {{
            module: modName,
            path,
            access: args[1].toUInt32(),
            creation: args[4].toUInt32(),
          }});
        }} catch (_) {{}}
      }},
    }});
  }}
}}

hookCreateFile();

const mod = Process.findModuleByName('QQMusic.dll');
if (!mod) {{
  sendEvent('fatal', {{ reason: 'QQMusic.dll not loaded' }});
}} else {{
  const entryAddr = mod.base.add(config.copy_async_entry_rva);
  const chosen = ptr(config.manager_this);
  sendEvent('manager_selected', {{
    ptr: chosen.toString(),
    probe: inspectManager(chosen),
    expected_vtable: mod.base.add(config.manager_vtable_rva).toString(),
    expected_alt_vtable: mod.base.add(config.manager_alt_vtable_rva).toString(),
  }});

  const item0 = buildItem(
    config.first_item_template_hex,
    config.source_url_primary,
    config.source_url_secondary,
    config.source_cache_path,
    config.stream_url,
    config.output_path,
    true,
  );
  const item1 = buildItem(
    config.second_item_template_hex,
    config.source_url_primary,
    config.source_url_secondary,
    config.source_cache_path,
    config.stream_url,
    config.output_path,
    false,
  );
  const vector = buildVector([item0, item1]);
  sendEvent('vector_built', {{
    manager: chosen.toString(),
    vector: vector.vec.toString(),
    begin: vector.base.toString(),
    item_count: 2,
  }});

  try {{
    const fn = new NativeFunction(entryAddr, 'uint32', ['pointer', 'pointer'], 'thiscall');
    const rv = fn(chosen, vector.vec);
    sendEvent('invoke_result', {{ retval: rv }});
  }} catch (e) {{
    sendEvent('invoke_error', {{ error: String(e) }});
  }}
}}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Foreground high-level QQ internal export experiment via copy_async_entry."
    )
    parser.add_argument("--manager-this", required=True, help="Manager this pointer, e.g. 0x146ffdc0")
    parser.add_argument("--source-url-primary", required=True)
    parser.add_argument("--source-url-secondary", required=True)
    parser.add_argument("--source-cache-path", required=True)
    parser.add_argument("--stream-url", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument(
        "--log-dir",
        default=str(Path(__file__).resolve().parents[1] / "_log" / "copy_async_entry_test"),
    )
    parser.add_argument(
        "--i-know-this-may-crash",
        action="store_true",
        help="Required safety acknowledgement. This experiment can hang or crash QQMusic.exe.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.i_know_this_may_crash:
        print(
            "Refusing to run copy_async_entry active experiment without "
            "--i-know-this-may-crash",
            file=sys.stderr,
        )
        return 2
    pid = find_qqmusic_pid()
    if not pid:
        print("QQMusic.exe is not running", file=sys.stderr)
        return 2

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    started_at = int(time.time())
    log_path = log_dir / f"copy_async_entry_test_{started_at}.jsonl"

    output_path = Path(args.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    cfg = {
        "copy_async_entry_rva": QQ_RVAS["copy_async_entry"],
        "manager_vtable_rva": 0xA924,
        "manager_alt_vtable_rva": 0xA8FC,
        "manager_this": args.manager_this,
        "first_item_template_hex": ITEM_TEMPLATE_HEX,
        "second_item_template_hex": SECOND_ITEM_TEMPLATE_HEX,
        "source_url_primary": args.source_url_primary,
        "source_url_secondary": args.source_url_secondary,
        "source_cache_path": args.source_cache_path,
        "stream_url": args.stream_url,
        "output_path": str(output_path),
    }

    session = None
    fh = None
    try:
        device = frida.get_local_device()
        session = device.attach(pid)
        script = session.create_script(build_script_source(cfg))
        fh = log_path.open("w", encoding="utf-8")

        def on_message(message, data):
            record = message["payload"] if message["type"] == "send" else message
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()

        script.on("message", on_message)
        script.load()
        time.sleep(5)
    finally:
        if fh:
            fh.close()
        if session:
            try:
                session.detach()
            except Exception:
                pass

    print(f"log: {log_path}")
    print(f"output_exists: {output_path.exists()}")
    if output_path.exists():
        print(f"output_size: {output_path.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
