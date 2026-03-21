import argparse
import json
import os
import sys
import time
from pathlib import Path

import frida


def find_qqmusic_pid() -> int | None:
    for line in os.popen('tasklist /FI "IMAGENAME eq QQMusic.exe" /FO CSV /NH').read().splitlines():
        if "QQMusic.exe" not in line:
            continue
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) > 1:
            return int(parts[1])
    return None


def build_script_source(sample_name: str, modules: list[str], export_limit: int) -> str:
    modules_json = json.dumps([m.lower() for m in modules], ensure_ascii=False)
    sample_json = json.dumps(sample_name, ensure_ascii=False)
    return f"""
const sampleName = {sample_json};
const moduleAllowList = {modules_json};
const interestingExt = /\\.(mgg|mflac|mmp4|mp3|flac|wav|m4a|ogg|aac)$/i;
const counts = {{}};
const handlePaths = {{}};
const targetedArgHooks = {{
  'qmp_flac.dll!Init': 4,
  'qmp_flac.dll!SetCallBack': 6,
  'qmp_flac.dll!QMP_FLAC__metadata_simple_iterator_init': 6,
  'qmp_flac.dll!QMP_FLAC__metadata_set_album_art': 6,
  'qmp_flac.dll!QMP_FLAC__import_pic_from': 4,
  'qmp_flac.dll!QMP_FLAC__metadata_get_album_art': 4
}};

function sendEvent(kind, payload) {{
  send(Object.assign({{ kind, ts: Date.now()/1000 }}, payload || {{}}));
}}

function limited(key, limit) {{
  const v = (counts[key] || 0) + 1;
  counts[key] = v;
  return v <= limit;
}}

function bt(ctx) {{
  try {{
    return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 10).map(addr => {{
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

function maybePath(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    return ptr.readUtf16String();
  }} catch (_) {{
    return null;
  }}
}}

function maybeAnsi(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const s = ptr.readCString();
    if (!s || s.length === 0 || s.length > 520) return null;
    return s;
  }} catch (_) {{
    return null;
  }}
}}

function maybeUtf16(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const s = ptr.readUtf16String();
    if (!s || s.length === 0 || s.length > 520) return null;
    return s;
  }} catch (_) {{
    return null;
  }}
}}

function normalizePath(path) {{
  if (!path) return null;
  return String(path).replace(/^\\\\\\?\\\\/, '');
}}

function isInterestingPath(path) {{
  const value = normalizePath(path);
  if (!value) return false;
  return (
    value.indexOf(sampleName) !== -1 ||
    interestingExt.test(value) ||
    value.indexOf('C:\\\\Users\\\\01080\\\\Music') !== -1 ||
    value.indexOf('O:\\\\QKKDecrypt UI\\\\i') !== -1
  );
}}

function rememberHandle(handle, path) {{
  try {{
    if (!handle || handle.isNull()) return;
    const normalized = normalizePath(path);
    if (!normalized) return;
    handlePaths[handle.toString()] = normalized;
  }} catch (_) {{}}
}}

function lookupHandle(handle) {{
  try {{
    if (!handle || handle.isNull()) return null;
    return handlePaths[handle.toString()] || null;
  }} catch (_) {{
    return null;
  }}
}}

function closeHandle(handle) {{
  try {{
    if (!handle || handle.isNull()) return;
    delete handlePaths[handle.toString()];
  }} catch (_) {{}}
}}

function unicodeStringToString(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const len = ptr.readU16();
    const bufferOffset = Process.pointerSize === 8 ? 8 : 4;
    const buf = ptr.add(bufferOffset).readPointer();
    if (!buf || buf.isNull() || len === 0) return null;
    return buf.readUtf16String(len / 2);
  }} catch (_) {{
    return null;
  }}
}}

function objectAttributesPath(ptr) {{
  try {{
    if (!ptr || ptr.isNull()) return null;
    const nameOffset = Process.pointerSize === 8 ? 16 : 8;
    const namePtr = ptr.add(nameOffset).readPointer();
    return unicodeStringToString(namePtr);
  }} catch (_) {{
    return null;
  }}
}}

function summarizeArgs(args, count) {{
  const out = [];
  for (let i = 0; i < count; i++) {{
    const ptr = args[i];
    const ansi = normalizePath(maybeAnsi(ptr));
    const utf16 = normalizePath(maybeUtf16(ptr));
    const interestingAnsi = ansi && (isInterestingPath(ansi) || ansi.toLowerCase().indexOf('flac') !== -1 || ansi.toLowerCase().indexOf('album') !== -1 || ansi.toLowerCase().indexOf('pic') !== -1);
    const interestingUtf16 = utf16 && (isInterestingPath(utf16) || utf16.toLowerCase().indexOf('flac') !== -1 || utf16.toLowerCase().indexOf('album') !== -1 || utf16.toLowerCase().indexOf('pic') !== -1);
    out.push({{
      index: i,
      value: ptr ? ptr.toString() : null,
      ansi: interestingAnsi ? ansi : null,
      utf16: interestingUtf16 ? utf16 : null
    }});
  }}
  return out;
}}

function hookFunction(prefix, address, exportName, limit) {{
  if (!address) return;
  const name = prefix + '!' + exportName;
  sendEvent('hooked', {{ name, address: address.toString() }});
  Interceptor.attach(address, {{
    onEnter(args) {{
      this.capture = limited(name, limit || {export_limit});
      if (this.capture) {{
        const payload = {{ name, backtrace: bt(this.context) }};
        if (targetedArgHooks[name]) {{
          payload.args = summarizeArgs(args, targetedArgHooks[name]);
        }}
        sendEvent('call_enter', payload);
      }}
    }},
    onLeave(retval) {{
      if (this.capture) {{
        const out = {{ name }};
        try {{ out.retval = retval.toUInt32(); }} catch (_) {{}}
        sendEvent('call_leave', out);
      }}
    }}
  }});
}}

function hookModule(module) {{
  const lower = module.name.toLowerCase();
  if (lower === 'qqmusiccommon.dll') {{
    for (const exp of module.enumerateExports()) {{
      if (exp.name.indexOf('EncAndDesMediaFile') !== -1) {{
        hookFunction('QQMusicCommon', exp.address, exp.name, {export_limit});
      }}
    }}
    return;
  }}
  if (moduleAllowList.indexOf(lower) !== -1) {{
    for (const exp of module.enumerateExports()) {{
      hookFunction(module.name, exp.address, exp.name, {export_limit});
    }}
  }}
}}

Process.attachModuleObserver({{
  onAdded(module) {{
    hookModule(module);
  }}
}});

for (const module of Process.enumerateModules()) {{
  hookModule(module);
}}

function hookCreateFileExport(moduleName, exportName) {{
  const addr = Module.findExportByName(moduleName, exportName);
  if (!addr) return;
  Interceptor.attach(addr, {{
    onEnter(args) {{
      this.path = normalizePath(maybePath(args[0]));
      this.capture = isInterestingPath(this.path) && limited(moduleName + '!' + exportName, 120);
      if (this.capture) {{
        sendEvent(exportName, {{ module: moduleName, path: this.path, backtrace: bt(this.context) }});
      }}
    }},
    onLeave(retval) {{
      if (this.capture) {{
        rememberHandle(retval, this.path);
      }}
    }}
  }});
}}

for (const moduleName of ['KERNEL32.DLL', 'KernelBase.dll']) {{
  hookCreateFileExport(moduleName, 'CreateFileW');
}}

function hookPathExport(moduleName, fn) {{
  const addr = Module.findExportByName(moduleName, fn);
  if (!addr) return;
  Interceptor.attach(addr, {{
    onEnter(args) {{
      const src = normalizePath(maybePath(args[0]));
      const dst = fn === 'DeleteFileW' ? null : normalizePath(maybePath(args[1]));
      const blob = (src || '') + ' ' + (dst || '');
      this.capture = (isInterestingPath(src) || isInterestingPath(dst) || interestingExt.test(blob)) && limited(moduleName + '!' + fn, 80);
      if (this.capture) {{
        sendEvent(fn, {{ module: moduleName, src, dst, backtrace: bt(this.context) }});
      }}
    }}
  }});
}}

for (const moduleName of ['KERNEL32.DLL', 'KernelBase.dll']) {{
  for (const fn of ['MoveFileExW', 'CopyFileW', 'DeleteFileW', 'ReplaceFileW']) {{
    hookPathExport(moduleName, fn);
  }}
}}

function hookWriteExport(moduleName, fn) {{
  const addr = Module.findExportByName(moduleName, fn);
  if (!addr) return;
  Interceptor.attach(addr, {{
    onEnter(args) {{
      this.len = args[2].toUInt32();
      const path = lookupHandle(args[0]);
      this.capture = ((path && isInterestingPath(path)) || this.len >= 1024) && limited(moduleName + '!' + fn, 120);
      if (this.capture) {{
        sendEvent(fn, {{ module: moduleName, path, length: this.len, backtrace: bt(this.context) }});
      }}
    }}
  }});
}}

for (const moduleName of ['KERNEL32.DLL', 'KernelBase.dll']) {{
  hookWriteExport(moduleName, 'WriteFile');
}}

const ntCreateFile = Module.findExportByName('ntdll.dll', 'NtCreateFile');
if (ntCreateFile) {{
  Interceptor.attach(ntCreateFile, {{
    onEnter(args) {{
      this.fileHandlePtr = args[0];
      this.path = normalizePath(objectAttributesPath(args[2]));
      this.capture = isInterestingPath(this.path) && limited('ntdll!NtCreateFile', 120);
      if (this.capture) {{
        sendEvent('NtCreateFile', {{ path: this.path, backtrace: bt(this.context) }});
      }}
    }},
    onLeave(retval) {{
      if (this.capture && retval.toInt32() >= 0) {{
        try {{
          rememberHandle(this.fileHandlePtr.readPointer(), this.path);
        }} catch (_) {{}}
      }}
    }}
  }});
}}

const ntWriteFile = Module.findExportByName('ntdll.dll', 'NtWriteFile');
if (ntWriteFile) {{
  Interceptor.attach(ntWriteFile, {{
    onEnter(args) {{
      this.len = args[6].toUInt32();
      const path = lookupHandle(args[0]);
      this.capture = ((path && isInterestingPath(path)) || this.len >= 1024) && limited('ntdll!NtWriteFile', 120);
      if (this.capture) {{
        sendEvent('NtWriteFile', {{ path, length: this.len, backtrace: bt(this.context) }});
      }}
    }}
  }});
}}

const closeHandleAddr = Module.findExportByName('KERNEL32.DLL', 'CloseHandle');
if (closeHandleAddr) {{
  Interceptor.attach(closeHandleAddr, {{
    onEnter(args) {{
      closeHandle(args[0]);
    }}
  }});
}}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="手动操作型 QQMusic 探针：挂到 QQMusic.exe 上，记录转换/播放相关调用。",
    )
    parser.add_argument("--sample", required=True, help="目标加密文件路径，用于聚焦相关文件操作。")
    parser.add_argument("--duration", type=int, default=120, help="探针持续时间，默认 120 秒。")
    parser.add_argument(
        "--log-dir",
        default=str(Path(__file__).resolve().parents[1] / "_log" / "probe_qqmusic_play"),
        help="日志输出目录。",
    )
    parser.add_argument(
        "--open-sample",
        action="store_true",
        help="启动探针后自动让 QQ 音乐打开样本；默认关闭，便于手动操作。",
    )
    parser.add_argument(
        "--modules",
        nargs="*",
        default=["QMP_OGG.dll", "QMP_FLAC.dll", "QMP_MP3.dll", "QMP_AAC.dll", "QMP_ALAC.dll"],
        help="额外导出级探测的解码模块列表。",
    )
    parser.add_argument(
        "--export-limit",
        type=int,
        default=40,
        help="每个导出函数最多记录多少次 enter/leave，默认 40。",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sample = Path(args.sample).expanduser()
    if not sample.exists():
        print(f"样本不存在: {sample}", file=sys.stderr)
        return 2

    pid = find_qqmusic_pid()
    if not pid:
        print("未检测到 QQMusic.exe，请先启动 QQ 音乐。", file=sys.stderr)
        return 2

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    started_at = int(time.time())
    log_path = log_dir / f"probe_manual_{started_at}.jsonl"
    stop_flag = log_dir / "probe_manual_stop.flag"
    control_path = log_dir / "probe_manual_control.json"
    if stop_flag.exists():
        stop_flag.unlink()

    meta = {
        "sample": str(sample),
        "started_at": started_at,
        "duration_sec": args.duration,
        "log_path": str(log_path),
        "stop_flag": str(stop_flag),
        "status": "starting",
        "pid": pid,
        "modules": args.modules,
        "open_sample": bool(args.open_sample),
    }
    control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    session = None
    fh = None
    try:
        device = frida.get_local_device()
        session = device.attach(pid)
        script = session.create_script(build_script_source(sample.name, args.modules, args.export_limit))
        fh = log_path.open("w", encoding="utf-8")

        def on_message(message, data):
            rec = message["payload"] if message["type"] == "send" else message
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()

        script.on("message", on_message)
        script.load()

        meta["status"] = "running"
        control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

        print(f"探针已启动，PID={pid}")
        print(f"日志文件: {log_path}")
        print(f"状态文件: {control_path}")
        print(f"停止标记: {stop_flag}")

        if args.open_sample:
            os.startfile(str(sample))
            print("已让 QQ 音乐尝试打开样本。")
        else:
            print("现在请在 QQ 音乐里手动进行播放 / 购买 / 转换操作。")

        deadline = time.time() + args.duration
        while time.time() < deadline:
            if stop_flag.exists():
                meta["status"] = "stopped_by_flag"
                control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
                print("检测到停止标记，探针提前结束。")
                break
            time.sleep(1)
        else:
            meta["status"] = "completed"
            control_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            print("探针已按时结束。")
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
