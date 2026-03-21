import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import frida

QQ_RVAS = {
    "work_ctor": 0x18C300,       # 1018c300
    "type1_parser": 0x64BAD0,    # 1064bad0
    "work_cleanup": 0x180590,    # 10180590
}


def find_qqmusic_pid() -> int | None:
    for line in os.popen('tasklist /FI "IMAGENAME eq QQMusic.exe" /FO CSV /NH').read().splitlines():
        if "QQMusic.exe" not in line:
            continue
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) > 1:
            return int(parts[1])
    return None


def derive_title_hints(sample: Path) -> tuple[str, str]:
    stem = sample.stem
    artist = ""
    title = stem
    if " - " in stem:
        artist, title = stem.split(" - ", 1)
    title = re.sub(r"_[A-Z0-9]+(?:\(\d+\))?$", "", title)
    return artist.strip(), title.strip()


def build_script_source(sample_name: str, artist_hint: str, title_hint: str) -> str:
    qq_rvas_json = json.dumps(QQ_RVAS)
    sample_json = json.dumps(sample_name, ensure_ascii=False)
    artist_json = json.dumps(artist_hint, ensure_ascii=False)
    title_json = json.dumps(title_hint, ensure_ascii=False)
    return f"""
const qqRvas = {qq_rvas_json};
const sampleName = {sample_json};
const artistHint = {artist_json};
const titleHint = {title_json};
let experimentDone = false;

function sendEvent(kind, payload) {{
  send(Object.assign({{ kind, ts: Date.now() / 1000 }}, payload || {{}}));
}}

function normalizeText(s) {{
  if (!s) return '';
  return String(s).toLowerCase()
    .replace(/[_\\-]/g, ' ')
    .replace(/\\s+/g, ' ')
    .trim();
}}

function safeReadPointer(ptr) {{
  try {{
    return ptr.readPointer();
  }} catch (_) {{
    return null;
  }}
}}

function safeReadU32(ptr) {{
  try {{
    return ptr.readU32();
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

function extractStringField(base, off) {{
  if (!base || base.isNull()) return null;
  try {{
    const slot = base.add(off);
    const direct = tryUtf16(slot);
    if (direct) return direct;
    const p1 = safeReadPointer(slot);
    const s1 = tryUtf16(p1);
    if (s1) return s1;
    if (p1 && !p1.isNull()) {{
      const p2 = safeReadPointer(p1);
      const s2 = tryUtf16(p2);
      if (s2) return s2;
    }}
  }} catch (_) {{}}
  return null;
}}

function inspectWork(workPtr) {{
  return {{
    title: extractStringField(workPtr, 0x08),
    singer: extractStringField(workPtr, 0x0c),
    singer_mid: extractStringField(workPtr, 0x10),
    source: extractStringField(workPtr, 0x3c),
    public_info: extractStringField(workPtr, 0x90),
    final_path: extractStringField(workPtr, 0x14c),
    pic_path: extractStringField(workPtr, 0x150),
    promote_path: extractStringField(workPtr, 0x158),
    stream_level: safeReadU32(workPtr.add(0x58)),
    batch_flag: safeReadU32(workPtr.add(0x178)),
  }};
}}

function matchesSample(info) {{
  const titleNorm = normalizeText(info.title);
  const singerNorm = normalizeText(info.singer);
  const finalNorm = normalizeText(info.final_path);
  const sampleNorm = normalizeText(sampleName);
  const wantTitle = normalizeText(titleHint);
  const wantArtist = normalizeText(artistHint);
  const hasAnyHint = !!(wantTitle || wantArtist || sampleNorm);
  if (!hasAnyHint) return true;
  if (wantTitle && titleNorm.indexOf(wantTitle) !== -1) return true;
  if (wantArtist && singerNorm.indexOf(wantArtist) !== -1) return true;
  if (wantTitle && finalNorm.indexOf(wantTitle) !== -1) return true;
  if (sampleNorm && finalNorm.indexOf(sampleNorm) !== -1) return true;
  return false;
}}

const mod = Process.findModuleByName('QQMusic.dll');
if (!mod) {{
  sendEvent('fatal', {{ reason: 'QQMusic.dll not loaded' }});
}} else {{
  const ctorAddr = mod.base.add(qqRvas.work_ctor);
  const parserAddr = mod.base.add(qqRvas.type1_parser);
  const cleanupAddr = mod.base.add(qqRvas.work_cleanup);
  const allocAddr =
    (Module.getExportByName ? Module.getExportByName(null, 'malloc') : null) ||
    (Module.findGlobalExportByName ? Module.findGlobalExportByName('malloc') : null);

  if (!allocAddr) {{
    sendEvent('fatal', {{ reason: 'malloc not found' }});
  }} else {{
    function makeNative(addr, retType, argTypes, abi32) {{
      if (Process.arch === 'ia32' && abi32) {{
        return new NativeFunction(addr, retType, argTypes, abi32);
      }}
      return new NativeFunction(addr, retType, argTypes);
    }}

    const allocFn = makeNative(allocAddr, 'pointer', ['ulong'], 'mscdecl');
    const ctorFn = makeNative(ctorAddr, 'pointer', ['pointer'], 'thiscall');
    const parserFn = makeNative(parserAddr, 'int', ['pointer', 'pointer'], 'stdcall');
    const cleanupFn = makeNative(cleanupAddr, 'void', ['pointer', 'int'], 'thiscall');

    sendEvent('hooked', {{
      qq_base: mod.base.toString(),
      work_ctor: ctorAddr.toString(),
      type1_parser: parserAddr.toString(),
      work_cleanup: cleanupAddr.toString(),
      sample: sampleName,
      artist_hint: artistHint,
      title_hint: titleHint,
      process_arch: Process.arch,
      pointer_size: Process.pointerSize,
    }});

    Interceptor.attach(parserAddr, {{
      onEnter(args) {{
        this.bag = args[0];
        this.realWork = args[1];
      }},
      onLeave(retval) {{
        if (experimentDone) return;
        const realInfo = inspectWork(this.realWork);
        sendEvent('real_parse', {{
          retval: Number(retval.toUInt32()),
          bag: this.bag.toString(),
          work: this.realWork.toString(),
          info: realInfo,
        }});
        if (!matchesSample(realInfo)) {{
          if (realInfo.final_path || realInfo.title || realInfo.singer) {{
            sendEvent('sample_filter_miss', {{
              sample: sampleName,
              artist_hint: artistHint,
              title_hint: titleHint,
              info: realInfo,
            }});
          }}
          return;
        }}

        experimentDone = true;
        let testWork = null;
        try {{
          testWork = allocFn(0x180);
          if (!testWork || testWork.isNull()) {{
            sendEvent('parser_experiment', {{ ok: false, stage: 'alloc_failed' }});
            return;
          }}
          ctorFn(testWork);
          const parseRv = parserFn(this.bag, testWork);
          const testInfo = inspectWork(testWork);
          sendEvent('parser_experiment', {{
            ok: parseRv !== 0,
            parse_retval: parseRv,
            bag: this.bag.toString(),
            test_work: testWork.toString(),
            real_work: this.realWork.toString(),
            info: testInfo,
          }});
          try {{
            cleanupFn(testWork, 1);
          }} catch (cleanupErr) {{
            sendEvent('parser_cleanup_error', {{ error: String(cleanupErr) }});
          }}
        }} catch (e) {{
          sendEvent('parser_experiment', {{
            ok: false,
            stage: 'invoke_failed',
            error: String(e),
            bag: this.bag ? this.bag.toString() : null,
            real_work: this.realWork ? this.realWork.toString() : null,
          }});
        }}
      }}
    }});
  }}
}}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a parser-only QQ internal export experiment using live metadata bags."
    )
    parser.add_argument("--sample", required=True, help="Encrypted QQ sample file path.")
    parser.add_argument("--duration", type=int, default=60, help="Foreground capture duration in seconds.")
    parser.add_argument(
        "--log-dir",
        default=str(Path(__file__).resolve().parents[1] / "_log" / "probe_qqmusic_play"),
        help="Directory for parser experiment logs.",
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

    artist_hint, title_hint = derive_title_hints(sample)
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    started_at = int(time.time())
    log_path = log_dir / f"parser_experiment_{started_at}.jsonl"
    control_path = log_dir / "parser_experiment_control.json"
    stop_flag = log_dir / "parser_experiment_stop.flag"
    if stop_flag.exists():
        stop_flag.unlink()

    meta = {
        "sample": str(sample),
        "artist_hint": artist_hint,
        "title_hint": title_hint,
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
        script = session.create_script(build_script_source(sample.name, artist_hint, title_hint))
        fh = log_path.open("w", encoding="utf-8")

        def on_message(message, data):
            record = message["payload"] if message["type"] == "send" else message
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()

        script.on("message", on_message)
        script.load()

        print(f"QQ parser experiment attached to PID={pid}")
        print(f"log: {log_path}")
        print(f"control: {control_path}")
        print(f"stop flag: {stop_flag}")
        meta["status"] = "running"
        control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

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
                print("parser experiment completed")
        except KeyboardInterrupt:
            meta["status"] = "stopped_by_keyboard"
            control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            print("stopped by Ctrl+C")
    finally:
        if fh:
            fh.close()
        if session:
            session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

