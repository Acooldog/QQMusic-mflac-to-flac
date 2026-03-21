import argparse
import json
import os
import sys
import time
from pathlib import Path

import frida


QQ_RVAS = {
    "deliver_open_path": 0x185110,
}


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

function hookCreateFile(moduleName) {{
  const mod = Process.findModuleByName(moduleName);
  if (!mod) return;
  const addr = mod.findExportByName('CreateFileW');
  if (!addr) return;
  Interceptor.attach(addr, {{
    onEnter(args) {{
      this.path = null;
      try {{
        this.path = args[0].readUtf16String();
      }} catch (_) {{}}
      if (!this.path) return;
      const lower = this.path.toLowerCase();
      if (
        lower.indexOf('qqmusiccache') === -1 &&
        lower.indexOf('direct_internal_test') === -1 &&
        lower.indexOf('music') === -1
      ) {{
        this.path = null;
        return;
      }}
      sendEvent('CreateFileW_enter', {{
        module: moduleName,
        path: this.path,
        access: args[1].toUInt32(),
        creation: args[4].toUInt32(),
      }});
    }},
    onLeave(retval) {{
      if (!this.path) return;
      sendEvent('CreateFileW_leave', {{
        module: moduleName,
        path: this.path,
        retval: retval.toString(),
      }});
    }},
  }});
}}

function writeU32(base, off, value) {{
  base.add(off).writeU32(value >>> 0);
}}

function writePtr(base, off, value) {{
  base.add(off).writePointer(value);
}}

function makeUtf16(text) {{
  return Memory.allocUtf16String(text);
}}

function describeItem(ptr) {{
  const out = {{
    ptr: ptr.toString(),
    fields: {{}},
  }};
  const interesting = [0x34, 0x38, 0x3c, 0x50, 0x54, 0x58, 0x60, 0x64, 0x14c];
  for (const off of interesting) {{
    try {{
      if (off === 0x50 || off === 0x54 || off === 0x58 || off === 0x60 || off === 0x64) {{
        out.fields['0x' + off.toString(16)] = ptr.add(off).readU32();
      }} else {{
        const p = ptr.add(off).readPointer();
        let s = null;
        try {{
          s = p.readUtf16String();
        }} catch (_) {{}}
        out.fields['0x' + off.toString(16)] = {{
          ptr: p.toString(),
          utf16: s,
        }};
      }}
    }} catch (e) {{
      out.fields['0x' + off.toString(16)] = {{ error: String(e) }};
    }}
  }}
  return out;
}}

hookCreateFile('KernelBase.dll');
hookCreateFile('KERNEL32.DLL');

const mod = Process.findModuleByName('QQMusic.dll');
if (!mod) {{
  sendEvent('fatal', {{ reason: 'QQMusic.dll not loaded' }});
}} else {{
  const fnAddr = mod.base.add(config.rva);
  sendEvent('target', {{
    name: config.name,
    address: fnAddr.toString(),
    base: mod.base.toString(),
    rva: '0x' + config.rva.toString(16),
  }});

  const item = Memory.alloc(0x200);
  const zeroBuf = new Uint8Array(0x200);
  item.writeByteArray(zeroBuf);

  const url1 = makeUtf16(config.source_url_primary);
  const url2 = makeUtf16(config.source_url_secondary);
  const cachePath = makeUtf16(config.source_cache_path);
  const outPath = makeUtf16(config.output_path);

  writePtr(item, 0x34, url1);
  writePtr(item, 0x38, url2);
  writePtr(item, 0x3c, cachePath);
  writeU32(item, 0x50, config.field_0x50);
  writeU32(item, 0x54, config.field_0x54);
  writeU32(item, 0x58, config.field_0x58);
  writeU32(item, 0x60, config.field_0x60);
  writeU32(item, 0x64, config.field_0x64);
  writePtr(item, 0x14c, outPath);

  sendEvent('item_built', describeItem(item));

  try {{
    const fn = new NativeFunction(fnAddr, 'uint32', ['pointer'], 'stdcall');
    const rv = fn(item);
    sendEvent('invoke_result', {{ retval: rv }});
  }} catch (e) {{
    sendEvent('invoke_error', {{ error: String(e) }});
  }}
}}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Foreground experiment for QQ internal deliver_open_path.")
    parser.add_argument("--source-url-primary", required=True)
    parser.add_argument("--source-url-secondary", required=True)
    parser.add_argument("--source-cache-path", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--field-0x50", type=int, default=1)
    parser.add_argument("--field-0x54", type=int, default=2)
    parser.add_argument("--field-0x58", type=int, default=5)
    parser.add_argument("--field-0x60", type=int, default=0)
    parser.add_argument("--field-0x64", type=int, default=0)
    parser.add_argument(
        "--log-dir",
        default=str(Path(__file__).resolve().parents[1] / "_log" / "direct_internal_test"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    pid = find_qqmusic_pid()
    if not pid:
        print("QQMusic.exe is not running", file=sys.stderr)
        return 2

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    started_at = int(time.time())
    log_path = log_dir / f"deliver_open_path_test_{started_at}.jsonl"
    output_path = Path(args.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    cfg = {
        "name": "deliver_open_path",
        "rva": QQ_RVAS["deliver_open_path"],
        "source_url_primary": args.source_url_primary,
        "source_url_secondary": args.source_url_secondary,
        "source_cache_path": args.source_cache_path,
        "output_path": str(output_path),
        "field_0x50": args.field_0x50,
        "field_0x54": args.field_0x54,
        "field_0x58": args.field_0x58,
        "field_0x60": args.field_0x60,
        "field_0x64": args.field_0x64,
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
        time.sleep(3)
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
