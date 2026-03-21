import argparse
import json
import os
import re
import time
import sys
from pathlib import Path

import frida

QQ_RVAS = {
    "work_ctor": 0x18C300,
    "work_fill": 0x18C4B0,
    "work_cleanup": 0x180590,
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
  try {{ return ptr.readPointer(); }} catch (_) {{ return null; }}
}}

function safeReadU32(ptr) {{
  try {{ return ptr.readU32(); }} catch (_) {{ return null; }}
}}

function tryUtf16(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const s = ptr.readUtf16String();
    if (!s || s.length === 0 || s.length > 520) return null;
    return s;
  }} catch (_) {{ return null; }}
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
  const fillAddr = mod.base.add(qqRvas.work_fill);
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
    const fillFn = makeNative(fillAddr, 'int', ['pointer', 'pointer', 'pointer', 'int', 'int'], 'thiscall');
    const cleanupFn = makeNative(cleanupAddr, 'void', ['pointer', 'int'], 'thiscall');

    sendEvent('hooked', {{
      qq_base: mod.base.toString(),
      work_ctor: ctorAddr.toString(),
      work_fill: fillAddr.toString(),
      work_cleanup: cleanupAddr.toString(),
      sample: sampleName,
      artist_hint: artistHint,
      title_hint: titleHint,
      process_arch: Process.arch,
      pointer_size: Process.pointerSize,
    }});

    Interceptor.attach(fillAddr, {{
      onEnter(args) {{
        this.realWork = this.context.ecx;
        this.record = args[0];
        this.sub = args[1];
        this.extra = args[2];
        this.mode = args[3].toUInt32 ? Number(args[3].toUInt32()) : Number(args[3]);
      }},
      onLeave(retval) {{
        if (experimentDone) return;
        const realInfo = inspectWork(this.realWork);
        sendEvent('real_fill', {{
          retval: Number(retval.toUInt32()),
          work: this.realWork.toString(),
          record: this.record.toString(),
          sub: this.sub.toString(),
          extra: this.extra.toString(),
          mode: this.mode,
          info: realInfo,
        }});
        if (!matchesSample(realInfo)) {{
          sendEvent('sample_filter_bypassed', {{
            reason: 'accept_first_live_fill',
            info: realInfo,
          }});
        }}

        experimentDone = true;
        let testWork = null;
        try {{
          testWork = allocFn(0x180);
          if (!testWork || testWork.isNull()) {{
            sendEvent('fill_experiment', {{ ok: false, stage: 'alloc_failed' }});
            return;
          }}
          ctorFn(testWork);
          const fillRv = fillFn(testWork, this.record, this.sub, Number(this.extra), this.mode);
          const testInfo = inspectWork(testWork);
          sendEvent('fill_experiment', {{
            ok: fillRv !== 0,
            fill_retval: fillRv,
            real_work: this.realWork.toString(),
            test_work: testWork.toString(),
            record: this.record.toString(),
            sub: this.sub.toString(),
            extra: this.extra.toString(),
            mode: this.mode,
            info: testInfo,
          }});
          try {{ cleanupFn(testWork, 1); }} catch (cleanupErr) {{
            sendEvent('fill_cleanup_error', {{ error: String(cleanupErr) }});
          }}
        }} catch (e) {{
          sendEvent('fill_experiment', {{
            ok: false,
            stage: 'invoke_failed',
            error: String(e),
            record: this.record.toString(),
            sub: this.sub.toString(),
            extra: this.extra.toString(),
            mode: this.mode,
          }});
          if (testWork && !testWork.isNull()) {{
            try {{ cleanupFn(testWork, 1); }} catch (_) {{}}
          }}
        }}
      }}
    }});
  }}
}}
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--sample', required=True)
    parser.add_argument('--duration', type=int, default=60)
    args = parser.parse_args()

    sample = Path(args.sample)
    artist_hint, title_hint = derive_title_hints(sample)

    pid = find_qqmusic_pid()
    if pid is None:
        print('QQMusic.exe not running', file=sys.stderr)
        return 2

    log_dir = Path('_log') / 'probe_qqmusic_play'
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    log_path = log_dir / f'fill_experiment_{stamp}.jsonl'
    control_path = log_dir / 'fill_experiment_control.json'
    stop_flag = log_dir / 'fill_experiment_stop.flag'
    if stop_flag.exists():
        stop_flag.unlink()

    control = {
        'sample': str(sample),
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
    script = session.create_script(build_script_source(sample.name, artist_hint, title_hint))

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
