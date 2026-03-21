import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import frida

QQ_RVAS = {
    "decrypt_cache_file": 0x1845C0,
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


def build_script_source(sample_name: str, artist_hint: str, title_hint: str, output_path: str) -> str:
    return f"""
const decryptRva = {QQ_RVAS['decrypt_cache_file']};
const sampleName = {json.dumps(sample_name, ensure_ascii=False)};
const artistHint = {json.dumps(artist_hint, ensure_ascii=False)};
const titleHint = {json.dumps(title_hint, ensure_ascii=False)};
const targetOutputPath = {json.dumps(output_path, ensure_ascii=False)};
let redirectDone = false;
let allocatedOutput = null;

function sendEvent(kind, payload) {{
  send(Object.assign({{ kind, ts: Date.now() / 1000 }}, payload || {{}}));
}}

function normalizeText(s) {{
  if (!s) return '';
  return String(s).toLowerCase().replace(/[_\\-]/g, ' ').replace(/\\s+/g, ' ').trim();
}}

function tryUtf16(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const s = ptr.readUtf16String();
    if (!s || s.length === 0 || s.length > 520) return null;
    return s;
  }} catch (_) {{ return null; }}
}}

function safeReadPointer(ptr) {{
  try {{ return ptr.readPointer(); }} catch (_) {{ return null; }}
}}

function extractStringField(base, off) {{
  if (!base || base.isNull()) return null;
  try {{
    const slot = base.add(off);
    const p1 = safeReadPointer(slot);
    const s1 = tryUtf16(p1);
    if (s1) return s1;
    const direct = tryUtf16(slot);
    if (direct) return direct;
  }} catch (_) {{}}
  return null;
}}

function matchesSample(srcPath, outPath) {{
  const srcNorm = normalizeText(srcPath);
  const outNorm = normalizeText(outPath);
  const sampleNorm = normalizeText(sampleName);
  const titleNorm = normalizeText(titleHint);
  const artistNorm = normalizeText(artistHint);
  if (sampleNorm && (srcNorm.indexOf(sampleNorm) !== -1 || outNorm.indexOf(sampleNorm) !== -1)) return true;
  if (titleNorm && (srcNorm.indexOf(titleNorm) !== -1 || outNorm.indexOf(titleNorm) !== -1)) return true;
  if (artistNorm && (srcNorm.indexOf(artistNorm) !== -1 || outNorm.indexOf(artistNorm) !== -1)) return true;
  return false;
}}

const mod = Process.findModuleByName('QQMusic.dll');
if (!mod) {{
  sendEvent('fatal', {{ reason: 'QQMusic.dll not loaded' }});
}} else {{
  const fnAddr = mod.base.add(decryptRva);
  sendEvent('hooked', {{ address: fnAddr.toString(), qq_base: mod.base.toString(), target_output: targetOutputPath }});
  Interceptor.attach(fnAddr, {{
    onEnter(args) {{
      this.srcObj = args[0];
      this.outObj = args[1];
      this.srcPath = extractStringField(this.srcObj, 0x0);
      this.outPath = extractStringField(this.outObj, 0x0);
      this.coverPath = extractStringField(this.outObj, 0x4);
      if (!redirectDone && matchesSample(this.srcPath, this.outPath)) {{
        allocatedOutput = Memory.allocUtf16String(targetOutputPath);
        this.outObj.writePointer(allocatedOutput);
        redirectDone = true;
        this.redirected = true;
        sendEvent('redirect_applied', {{
          src_path: this.srcPath,
          original_output: this.outPath,
          new_output: targetOutputPath,
          cover_path: this.coverPath,
        }});
      }}
    }},
    onLeave(retval) {{
      if (this.redirected) {{
        sendEvent('redirect_result', {{
          retval: Number(retval.toUInt32()),
          src_path: this.srcPath,
          final_output: targetOutputPath,
          cover_path: this.coverPath,
        }});
      }}
    }}
  }});
}}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description='Foreground live decrypt_cache_file redirect experiment.')
    parser.add_argument('--sample', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--duration', type=int, default=60)
    args = parser.parse_args()

    sample = Path(args.sample)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    artist_hint, title_hint = derive_title_hints(sample)

    pid = find_qqmusic_pid()
    if pid is None:
        print('QQMusic.exe not running', file=sys.stderr)
        return 2

    log_dir = Path('_log') / 'probe_qqmusic_play'
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    log_path = log_dir / f'decrypt_redirect_{stamp}.jsonl'
    control_path = log_dir / 'decrypt_redirect_control.json'
    stop_flag = log_dir / 'decrypt_redirect_stop.flag'
    if stop_flag.exists():
        stop_flag.unlink()

    control = {
        'sample': str(sample),
        'output': str(output),
        'artist_hint': artist_hint,
        'title_hint': title_hint,
        'started_at': stamp,
        'duration_sec': args.duration,
        'log_path': str(log_path.resolve()),
        'status': 'running',
        'pid': pid,
        'stop_flag': str(stop_flag.resolve()),
    }
    control_path.write_text(json.dumps(control, ensure_ascii=False, indent=2), encoding='utf-8')

    session = frida.attach(pid)
    script = session.create_script(build_script_source(sample.name, artist_hint, title_hint, str(output)))

    def on_message(message, _data):
        with log_path.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(message, ensure_ascii=False) + '\n')

    script.on('message', on_message)
    script.load()
    try:
        end_at = time.time() + args.duration
        while time.time() < end_at:
            if stop_flag.exists():
                control['status'] = 'stopped_by_flag'
                break
            time.sleep(0.2)
        else:
            control['status'] = 'completed'
    except KeyboardInterrupt:
        control['status'] = 'stopped_by_keyboard'
    finally:
        control_path.write_text(json.dumps(control, ensure_ascii=False, indent=2), encoding='utf-8')
        try:
            script.unload()
        except Exception:
            pass
        session.detach()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
