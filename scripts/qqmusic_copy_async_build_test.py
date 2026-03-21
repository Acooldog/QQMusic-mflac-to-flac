import argparse
import json
import os
import sys
import time
from pathlib import Path

import frida


QQ_RVAS = {
    "copy_async_build": 0x17EFC0,
}

FIRST_ITEM_TEMPLATE_HEX = (
    "01000000222700008810cd1d70aea91ca40f89790d050000f3d6cf0200000000"
    "f3d6cf02f3d6cf02ba2204015800cd1d0000000008f3b71eb07e9d1ec0180623"
    "0300000000000000a40f8979a40f89790100000002000000050000001f050000"
    "e81c7723020000000000000001000000e27c3700e3000000ffffffffc9000000"
    "8b1a000006000000d7fa03008810cd1d60afa91c00b0a91c301ce114a40f8979"
    "ffffffff00000000000000000000000000000000000000000000000000000000"
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
  try {{ return ptr.readU32(); }} catch (_) {{ return null; }}
}}

function safeReadPointer(ptr) {{
  try {{ return ptr.readPointer(); }} catch (_) {{ return null; }}
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

function inspectFields(ptr, offsets) {{
  if (!ptr || ptr.isNull()) return null;
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

function buildItem(rawHex, url1, url2, cachePath, streamUrl, outPath) {{
  const raw = rawHex.match(/../g).map((x) => parseInt(x, 16));
  const item = Memory.alloc(raw.length);
  item.writeByteArray(raw);
  item.add(0x34).writePointer(Memory.allocUtf16String(url1));
  item.add(0x38).writePointer(Memory.allocUtf16String(url2));
  item.add(0x3c).writePointer(Memory.allocUtf16String(cachePath));
  item.add(0x98).writePointer(Memory.allocUtf16String(streamUrl));
  item.add(0x14c).writePointer(Memory.allocUtf16String(outPath));
  return item;
}}

const manager = ptr(config.manager_this);
const item = buildItem(
  config.first_item_template_hex,
  config.source_url_primary,
  config.source_url_secondary,
  config.source_cache_path,
  config.stream_url,
  config.output_path,
);

sendEvent('before', {{
  manager: manager.toString(),
  manager_probe: inspectFields(manager, [0x28,0x30,0x34,0x40,0x108,0x140,0x148,0x158]),
  item: item.toString(),
  item_probe: inspectFields(item, [0x3c,0x50,0x54,0x58,0x5c,0x60,0x64,0x6c,0x70,0x74,0x7c,0x80,0x84,0x88,0x98,0x12c,0x148,0x14c]),
}});

const mod = Process.findModuleByName('QQMusic.dll');
if (!mod) {{
  sendEvent('fatal', {{ reason: 'QQMusic.dll not loaded' }});
}} else {{
  try {{
    const fn = new NativeFunction(mod.base.add(config.rva), 'uint32', ['pointer', 'pointer'], 'thiscall');
    const rv = fn(manager, item);
    sendEvent('invoke_result', {{ retval: rv }});
  }} catch (e) {{
    sendEvent('invoke_error', {{ error: String(e) }});
  }}
}}

sendEvent('after', {{
  manager: manager.toString(),
  manager_probe: inspectFields(manager, [0x28,0x30,0x34,0x40,0x108,0x140,0x148,0x158]),
}});
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Foreground QQ copy_async_build experiment.")
    parser.add_argument("--manager-this", required=True)
    parser.add_argument("--source-url-primary", required=True)
    parser.add_argument("--source-url-secondary", required=True)
    parser.add_argument("--source-cache-path", required=True)
    parser.add_argument("--stream-url", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument(
        "--log-dir",
        default=str(Path(__file__).resolve().parents[1] / "_log" / "copy_async_build_test"),
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
            "Refusing to run copy_async_build active experiment without "
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
    log_path = log_dir / f"copy_async_build_test_{started_at}.jsonl"

    cfg = {
        "rva": QQ_RVAS["copy_async_build"],
        "manager_this": args.manager_this,
        "first_item_template_hex": FIRST_ITEM_TEMPLATE_HEX,
        "source_url_primary": args.source_url_primary,
        "source_url_secondary": args.source_url_secondary,
        "source_cache_path": args.source_cache_path,
        "stream_url": args.stream_url,
        "output_path": args.output_path,
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
        time.sleep(2)
    finally:
        if fh:
            fh.close()
        if session:
            try:
                session.detach()
            except Exception:
                pass

    print(f"log: {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
