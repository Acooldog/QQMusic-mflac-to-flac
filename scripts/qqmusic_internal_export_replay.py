import argparse
import json
import os
import sys
import time
from pathlib import Path

import frida

QQ_RVAS = {
    "deliver_core": 0x185480,
    "deliver_helper": 0x4B7D60,
}


def find_qqmusic_pid() -> int | None:
    for line in os.popen('tasklist /FI "IMAGENAME eq QQMusic.exe" /FO CSV /NH').read().splitlines():
        if "QQMusic.exe" not in line:
            continue
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) > 1:
            return int(parts[1])
    return None


def build_script_source(sample_name: str, capture_only: bool) -> str:
    sample_json = json.dumps(sample_name, ensure_ascii=False)
    qq_rvas_json = json.dumps(QQ_RVAS)
    capture_only_json = "true" if capture_only else "false"
    return f"""
const sampleName = {sample_json};
const qqRvas = {qq_rvas_json};
const captureOnly = {capture_only_json};
let captured = false;

function sendEvent(kind, payload) {{
  send(Object.assign({{ kind, ts: Date.now() / 1000 }}, payload || {{}}));
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

function interestingValue(ptr) {{
  if (!ptr || ptr.isNull()) return null;
  for (const off of [0x34, 0x38, 0x3c]) {{
    try {{
      const value = safeReadPointer(ptr.add(off));
      const text = tryUtf16(value);
      if (text && text.toLowerCase().indexOf(sampleName.toLowerCase().replace('_h','').replace('_l','')) !== -1) {{
        return text;
      }}
      if (text && text.toLowerCase().indexOf('qqmusiccache') !== -1) {{
        return text;
      }}
    }} catch (_) {{}}
  }}
  try {{
    const direct = tryUtf16(safeReadPointer(ptr));
    if (direct) return direct;
  }} catch (_) {{}}
  return null;
}}

const mod = Process.findModuleByName('QQMusic.dll');
if (!mod) {{
  sendEvent('fatal', {{ reason: 'QQMusic.dll not loaded' }});
}} else {{
  const coreAddr = mod.base.add(qqRvas.deliver_core);
  const helperAddr = mod.base.add(qqRvas.deliver_helper);
  let lastHelper = null;
  sendEvent('hooked', {{
    deliver_core: coreAddr.toString(),
    deliver_helper: helperAddr.toString(),
    base: mod.base.toString(),
    deliver_core_rva: '0x' + qqRvas.deliver_core.toString(16),
    deliver_helper_rva: '0x' + qqRvas.deliver_helper.toString(16),
  }});

  Interceptor.attach(helperAddr, {{
    onEnter(args) {{
      const srcHint = interestingValue(args[2]);
      const outHint = interestingValue(args[4]);
      const ctxHint = interestingValue(args[3]);
      if (!srcHint && !outHint && !ctxHint) return;
      lastHelper = {{
        ecx: this.context.ecx ? this.context.ecx.toString() : null,
        args: [args[0], args[1], args[2], args[3], args[4], args[5]].map(x => x.toString()),
        src_hint: srcHint,
        ctx_hint: ctxHint,
        out_hint: outHint,
      }};
      sendEvent('helper_captured', lastHelper);
    }}
  }});

  Interceptor.attach(coreAddr, {{
    onEnter(args) {{
      if (captured) return;
      const srcHint = interestingValue(args[0]);
      const outHint = interestingValue(args[1]);
      if (!srcHint && !outHint) return;
      captured = true;
      this.saved = {{
        ecx: this.context.ecx ? this.context.ecx.toString() : null,
        args: [args[0], args[1], args[2], args[3], args[4], args[5]].map(x => x.toString()),
        src_hint: srcHint,
        out_hint: outHint,
        helper_snapshot: lastHelper,
      }};
      sendEvent('candidate_captured', this.saved);
    }},
    onLeave(retval) {{
      if (!this.saved || captureOnly) return;
      try {{
        const fn = new NativeFunction(
          coreAddr,
          'uint32',
          ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
          'thiscall'
        );
        const rv = fn(
          ptr(this.saved.ecx),
          ptr(this.saved.args[0]),
          ptr(this.saved.args[1]),
          ptr(this.saved.args[2]),
          ptr(this.saved.args[3]),
          ptr(this.saved.args[4]),
          ptr(this.saved.args[5])
        );
        sendEvent('reinvoke_result', {{ retval: rv }});
      }} catch (e) {{
        sendEvent('reinvoke_error', {{ error: String(e) }});
      }}
    }}
  }});
}}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture a replay candidate for QQ internal export.")
    parser.add_argument("--sample", required=True, help="Encrypted QQ sample file path for context.")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds.")
    parser.add_argument(
        "--log-dir",
        default=str(Path(__file__).resolve().parents[1] / "_log" / "probe_qqmusic_play"),
        help="Directory for replay logs.",
    )
    parser.add_argument(
        "--attempt-reinvoke",
        action="store_true",
        help="Experimental and risky: call deliver_core again with captured live pointers.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.attempt_reinvoke:
        print(
            "Refusing to run --attempt-reinvoke from the default script path. "
            "This path is known to hang or crash QQMusic.exe. "
            "Keep using foreground capture-only probes until the context model is complete.",
            file=sys.stderr,
        )
        return 2
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
    log_path = log_dir / f"replay_internal_{started_at}.jsonl"
    candidate_path = log_dir / f"replay_internal_{started_at}.candidate.json"
    control_path = log_dir / "replay_internal_control.json"
    stop_flag = log_dir / "replay_internal_stop.flag"
    if stop_flag.exists():
        stop_flag.unlink()

    meta = {
        "sample": str(sample),
        "started_at": started_at,
        "duration_sec": args.duration,
        "log_path": str(log_path),
        "candidate_path": str(candidate_path),
        "status": "starting",
        "pid": pid,
        "stop_flag": str(stop_flag),
        "attempt_reinvoke": bool(args.attempt_reinvoke),
    }
    control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    session = None
    fh = None
    captured_candidate = None
    try:
        device = frida.get_local_device()
        session = device.attach(pid)
        script = session.create_script(build_script_source(sample.name, not args.attempt_reinvoke))
        fh = log_path.open("w", encoding="utf-8")

        def on_message(message, data):
            nonlocal captured_candidate
            record = message["payload"] if message["type"] == "send" else message
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            if record.get("kind") == "candidate_captured":
                captured_candidate = record

        script.on("message", on_message)
        script.load()

        print(f"Internal replay capture attached to PID={pid}")
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
                print("replay capture completed")
        except KeyboardInterrupt:
            meta["status"] = "stopped_by_keyboard"
            control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            print("stopped by Ctrl+C")

        if captured_candidate:
            candidate_path.write_text(json.dumps(captured_candidate, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"candidate: {candidate_path}")
        else:
            print("no candidate captured")
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
