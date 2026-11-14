#!/usr/bin/env python3
"""
DUMPTOOL V8 - Ultimate Android Binary & Game Engine Analysis Framework
Features: Real-time streaming dump, custom selection, true whole-lib pseudocode,
and automated UE4 security hooks & protection offset extractor.
"""
import argparse
import json
import mmap
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ========= COLORS =========
CYAN   = "\033[0;36m"
GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
WHITE  = "\033[0;37m"
RESET  = "\033[0m"

# ========= SETTINGS =========
DEFAULT_TARGET = "/storage/emulated/0/she5/"
SCRIPT_DIR = Path(__file__).resolve().parent
OUT_EXT = "c"                     
MARK = "DUMPSEC_9f3a_"            
ANALYSIS = {"fast": "aa", "normal": "aaa", "deep": "aaaa"}

TASKS = {
    "elf":         ("ELF HEADERS & INFO",          "iI", "quick"),
    "sections":    ("SECTION HEADERS",             "iS", "quick"),
    "segments":    ("SEGMENTS MAP",                "oS", "quick"),
    "imports":     ("IMPORTED SYMBOLS",            "ii", "quick"),
    "exports":     ("EXPORTED SYMBOLS",            "iE", "quick"),
    "symbols":     ("LOCAL & GLOBAL SYMBOLS",      "is", "quick"),
    "reloc":       ("RELOCATIONS TABLE",           "ir", "quick"),
    "dynamic":     ("DYNAMIC SECTION",             "il\n?e\nid", "quick"),
    "memory":      ("VIRTUAL MEMORY MAP",          "om", "quick"),
    "plt_got":     ("PLT & GOT TABLES",            "i~plt\ni~got", "quick"),
    "eh_frame":    ("EXCEPTION FRAMES (.eh_frame)","iS~eh_frame", "quick"),
    "ctors_dtors": ("CONSTRUCTORS & DESTRUCTORS",  "i~init\ni~fini", "quick"),
    "jni":         ("JNI FUNCTIONS & REGISTRATIONS","is~Java_\n?e\nis~JNI_OnLoad\nis~JNI_OnUnload", "quick"),
    "entry":       ("ENTRYPOINT DISASM",           "s entry0\naf\npdf", "quick"),
    "cfg":         ("CONTROL FLOW GRAPH (CFG)",    "s entry0\naf\nagf", "quick"),
    "strings":     ("ALL STRINGS (ASCII/UTF-16)",  "izz", "static_slow"),
    "functions":   ("FULL FUNCTION LIST (afl)",    "afl", "analysis"),
    "callgraph":   ("CROSS CALL GRAPH",            "agCd", "analysis"),
    "xrefs":       ("CROSS REFERENCES (XREFS)",    "axt @@ sym.*", "analysis"),
    "disasm":      ("ALL FUNCTIONS DISASM",        "pdf @@f", "analysis"),
    "entropy":     ("BINARY ENTROPY SCAN",         "p=e", "quick"),
}

FULL_ORDER = [
    "elf", "sections", "segments", "imports", "exports", "symbols", 
    "reloc", "dynamic", "memory", "plt_got", "eh_frame", "ctors_dtors",
    "jni", "strings", "functions", "callgraph", "xrefs", "cfg", "entry", "entropy"
]

PRINT_LOCK = threading.Lock()
PROCS = []


def say(msg):
    with PRINT_LOCK:
        print(msg, flush=True)


def clear():
    print("\033[2J\033[H", end="", flush=True)


def ensure_r2():
    if shutil.which("r2"):
        return
    print(f"{CYAN}[+] Installing radare2...{RESET}")
    subprocess.call(["pkg", "install", "-y", "radare2"])
    if not shutil.which("r2"):
        sys.exit(f"{RED}[!] radare2 is not installed or failed to install.{RESET}")


def banner():
    print(f"""{RED}
╔══════════════════════════════════════════════════════════╗
║          ██████╗ ██╗   ██╗███╗   ███╗██████╗             ║
║          ██╔══██╗██║   ██║████╗ ████║██╔══██╗            ║
║          ██║  ██║██║   ██║██╔████╔██║██████╔╝            ║
║          ██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝             ║
║          ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║                 ║
║          ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝                 ║
║               DUMPTOOL V8 - UE4 HOOK & PRO               ║
║         Advanced Android Binary & Game Analyzer          ║
╚══════════════════════════════════════════════════════════╝
{RESET}""")


def find_libs(target):
    libs = []
    if os.path.isfile(target):
        return [target]
    for root, _, files in os.walk(target):
        for f in files:
            if f.endswith(".so"):
                libs.append(os.path.join(root, f))
    libs.sort()
    return libs


def pick_lib(libs, target):
    shown = libs
    while True:
        print(f"{CYAN}[*] Found libraries:{RESET}")
        for i, lib in enumerate(shown, 1):
            try:
                size = os.path.getsize(lib) / (1024 * 1024)
            except OSError:
                size = 0
            rel = os.path.relpath(lib, target) if os.path.isdir(target) else lib
            print(f"{WHITE}[{i}] {rel}  ({size:,.2f} MB){RESET}")
        ans = input("\nChoose lib number (or type text to filter): ").strip()
        if ans.isdigit() and 1 <= int(ans) <= len(shown):
            return shown[int(ans) - 1]
        if ans and not ans.isdigit():
            hits = [l for l in libs if ans.lower() in os.path.basename(l).lower()]
            if hits:
                shown = hits
                continue
        print(f"{RED}[!] Invalid choice{RESET}\n")


def kill_all():
    for p in PROCS:
        if p.poll() is None:
            p.terminate()


def outdir_for(lib):
    d = SCRIPT_DIR / f"dump_{Path(lib).stem}"
    d.mkdir(exist_ok=True)
    return d


def elf_load_segments(path):
    with open(path, "rb") as f:
        hdr = f.read(64)
        if hdr[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        e = "<" if hdr[5] == 1 else ">"
        if hdr[4] == 2:
            is64, fmt = True, e + "IIQQQQQQ"
            phoff = struct.unpack_from(e + "Q", hdr, 0x20)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", hdr, 0x36)
        else:
            is64, fmt = False, e + "IIIIIIII"
            phoff = struct.unpack_from(e + "I", hdr, 0x1C)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", hdr, 0x2A)
        f.seek(phoff)
        data = f.read(phentsize * phnum)
    segs = []
    for i in range(phnum):
        t = struct.unpack_from(fmt, data, i * phentsize)
        if is64:
            ptype, _, off, vaddr, _, filesz, _, _ = t
        else:
            ptype, off, vaddr, _, filesz, _, _, _ = t
        if ptype == 1 and filesz:
            segs.append((off, vaddr, filesz))
    return segs


def file_to_vaddr(segs, off):
    for s_off, s_va, s_size in segs:
        if s_off <= off < s_off + s_size:
            return s_va + off - s_off
    return None


# ========= MULTITHREADED STREAMING STRING SEARCH =========
def locate_single_string(mm, size, segs, name):
    exact, partial = [], []
    pat = name.encode("utf-8")
    pos, n = mm.find(pat), 0
    max_scan = 150000
    while pos != -1 and n < max_scan:
        n += 1
        end = pos + len(pat)
        before = mm[pos - 1] if pos > 0 else 0
        after = mm[end] if end < size else 0
        (exact if before == 0 and after == 0 else partial).append(pos)
        pos = mm.find(pat, pos + 1)

    wpat = name.encode("utf-16-le")
    pos, n = mm.find(wpat), 0
    while pos != -1 and n < max_scan:
        n += 1
        end = pos + len(wpat)
        if pos >= 2 and mm[pos - 2:pos] == b"\0\0" and mm[end:end + 2] == b"\0\0":
            exact.append(pos)
        pos = mm.find(wpat, pos + 1)

    kind, hits = "none", []
    if exact:
        kind, hits = "exact", exact
    elif partial:
        kind, hits = "partial", partial[:20]

    vas = []
    for h in hits:
        va = file_to_vaddr(segs, h)
        if va is not None and va not in vas:
            vas.append(va)
    return name, (vas, kind if vas else "none")


def locate_strings(lib, names):
    segs = elf_load_segments(lib)
    found = {}
    with open(lib, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        size = len(mm)
        max_workers = min(32, (os.cpu_count() or 4) * 2)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(locate_single_string, mm, size, segs, name) for name in names]
            for future in as_completed(futures):
                name, res = future.result()
                found[name] = res
    return found


def parse_entries(text):
    entries, seen = [], set()
    for line in text.replace(",", "\n").splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(r"0x[0-9a-fA-F]+\s*//\s*(.*)$", s)
        if m:
            label = m.group(1)
        elif s.startswith("//"):
            entries.append(("header", s.lstrip("/ ").strip()))
            continue
        elif re.fullmatch(r"0x[0-9a-fA-F]+", s):
            continue
        else:
            label = s
        label = re.sub(r"\s*\(.*\)\s*$", "", label).strip()
        if label and label not in seen:
            seen.add(label)
            entries.append(("name", label))
    return entries


def find_by_string(lib, mode):
    entries = parse_entries(read_names_input())
    names = [t for k, t in entries if k == "name"]
    if not names:
        say(f"{RED}[!] No valid names provided{RESET}")
        return

    say(f"{CYAN}[*] Multithreaded scanning for {len(names)} targets in {os.path.basename(lib)}...{RESET}")
    try:
        found = locate_strings(lib, names)
    except (OSError, ValueError) as e:
        say(f"{RED}[!] {e}{RESET}")
        return

    addrs = sorted({a for vas, _ in found.values() for a in vas})
    refs = {}
    if addrs:
        ana = ANALYSIS[mode] + ("\naar" if mode == "fast" else "")
        lines = []
        for i, a in enumerate(addrs):
            lines += [f"?e {MARK}x{i}", f"axtj @ 0x{a:x}"]
        say(f"{CYAN}[*] Resolving xrefs for {len(addrs)} memory addresses...{RESET}")
        sections = run_r2_capture(lib, ana, lines)
        for i, a in enumerate(addrs):
            refs[a] = parse_json_list(sections.get(f"x{i}", []))

    results, ok = {}, 0
    for name in names:
        vas, kind = found[name]
        funcs, nofunc = {}, []
        for a in vas:
            for r in refs.get(a, []):
                fa = r.get("fcn_addr")
                if fa:
                    funcs[fa] = funcs.get(fa, 0) + 1
                elif r.get("from"):
                    nofunc.append(r["from"])
        tag = " (partial)" if kind == "partial" else ""
        out = []
        if funcs:
            ok += 1
            order = sorted(funcs.items(), key=lambda kv: (-kv[1], kv[0]))
            shown = order[:10]
            for i, (fa, cnt) in enumerate(shown, 1):
                extra = f" #{i}/{len(order)} ({cnt} refs)" if len(order) > 1 else ""
                out.append((GREEN, f"0x{fa:X} // {name}{extra}{tag}"))
        elif nofunc:
            ok += 1
            for fr in sorted(set(nofunc))[:10]:
                out.append((YELLOW, f"0x{fr:X} // {name} (xref, no fcn){tag}"))
        elif vas:
            out.append((YELLOW, f"// {name}: string @ 0x{vas[0]:X} (no xref){tag}"))
        else:
            out.append((RED, f"// {name}: NOT FOUND"))
        results[name] = out

    lines_out, pending = [], None
    for kind, text in entries:
        if kind == "header":
            pending = text
            continue
        if pending is not None:
            lines_out += [(WHITE, ""), (CYAN, f"// {pending}")]
            pending = None
        lines_out += results[text]

    say("")
    for color, text in lines_out:
        say(f"{color}{text}{RESET}")
    say(f"\n{CYAN}[*] Successfully resolved {ok}/{len(names)} names.{RESET}")

    out_dir = outdir_for(lib)
    out_path = out_dir / f"dump_{Path(lib).stem}_offsets.txt"
    cpp_path = out_dir / f"Offsets.h"
    
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(t for _, t in lines_out).lstrip("\n") + "\n")
    
    with open(cpp_path, "w", encoding="utf-8") as f:
        f.write("#pragma once\n#include <cstdint>\n\n// Auto-generated by DUMPTOOL V8\nnamespace Offsets {\n")
        for color, text in lines_out:
            if "//" in text and "0x" in text:
                parts = text.split("//")
                addr = parts[0].strip()
                name = re.sub(r'[\s\(\)\#\/\.\-\+]+', '_', parts[1].strip()).strip('_')
                f.write(f"    constexpr uintptr_t {name} = {addr};\n")
        f.write("}\n")

    say(f"{GREEN}[✔] Saved text report -> {out_path}{RESET}")
    say(f"{GREEN}[✔] Saved C++ Header -> {cpp_path}{RESET}")


def read_names_input():
    print(f"{CYAN}Enter String name(s): comma separated, a .txt file path, "
          f"or type 'paste' for multi-line{RESET}")
    raw = input("> ").strip().strip("'\"")
    if not raw:
        return ""
    if raw.lower() == "paste":
        print(f"{CYAN}Paste your list, type 'done' on a new line when finished:{RESET}")
        buf = []
        while True:
            line = input()
            if line.strip().lower() == "done":
                break
            buf.append(line)
        return "\n".join(buf)
    path = os.path.expanduser(raw)
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    return raw


def parse_json_list(lines):
    txt = "".join(lines)
    i, j = txt.find("["), txt.rfind("]")
    if i == -1 or j < i:
        return []
    try:
        data = json.loads(txt[i:j + 1])
    except ValueError:
        return []
    return [d for d in data if isinstance(d, dict)]


def run_r2_capture(lib, ana_cmd, lines):
    fd, script = tempfile.mkstemp(suffix=".r2")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(([ana_cmd] if ana_cmd else []) + lines) + "\n")
    cmd = ["r2", "-q",
           "-e", "scr.color=0",
           "-e", "scr.interactive=false",
           "-e", "bin.relocs.apply=true",
           "-i", script, lib]

    sections, cur = {}, None
    stop, t0 = threading.Event(), time.time()

    def ticker():
        while not stop.wait(15):
            say(f"{YELLOW}[~] r2 analysis working... {int(time.time() - t0)}s{RESET}")

    threading.Thread(target=ticker, daemon=True).start()
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True,
                             encoding="utf-8", errors="replace")
        PROCS.append(p)
        for line in p.stdout:
            if line.startswith(MARK):
                cur = line[len(MARK):].strip()
                sections[cur] = []
            elif cur is not None:
                sections[cur].append(line)
        p.wait()
    except KeyboardInterrupt:
        kill_all()
        raise
    finally:
        stop.set()
        try:
            os.unlink(script)
        except OSError:
            pass
    return sections


# ========= STREAMING INCREMENTAL RUN GROUP =========
def run_group_streaming(items, lib, outdir, ana_cmd=None):
    libname = Path(lib).stem
    titles = {tag: title for tag, title, _ in items}

    lines = [ana_cmd] if ana_cmd else []
    for tag, _, cmd in items:
        lines.append(f"?e {MARK}{tag}")
        lines.extend(cmd.split("\n"))

    fd, script = tempfile.mkstemp(suffix=".r2")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")

    cmd = ["r2", "-q",
           "-e", "scr.color=0",
           "-e", "scr.interactive=false",
           "-e", "bin.relocs.apply=true",
           "-i", script, lib]

    out, out_path, wrote, t_sec = None, None, 0, time.time()
    total_tasks = len(items)
    completed_tasks = 0

    def close_section():
        nonlocal out, wrote, completed_tasks
        if out is None:
            return
        out.close()
        took = time.time() - t_sec
        completed_tasks += 1
        pct = int((completed_tasks / total_tasks) * 100) if total_tasks > 0 else 100
        if wrote:
            say(f"{GREEN}[{pct}%] [✔] Saved {out_path.name}  ({wrote} lines, {took:.1f}s){RESET}")
        else:
            say(f"{YELLOW}[{pct}%] [!] Empty result: {out_path.name}{RESET}")
        out = None

    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True,
                             encoding="utf-8", errors="replace")
        PROCS.append(p)
        for line in p.stdout:
            if line.startswith(MARK):
                close_section()
                tag = line[len(MARK):].strip()
                out_path = outdir / f"dump_{libname}_{tag}.{OUT_EXT}"
                out = open(out_path, "w", encoding="utf-8")
                out.write(f"===== {titles.get(tag, tag)} =====\n\n")
                wrote, t_sec = 0, time.time()
            elif out is not None:
                out.write(line)
                out.flush()
                wrote += 1
        p.wait()
    finally:
        close_section()
        try:
            os.unlink(script)
        except OSError:
            pass


def run_jobs_streaming(jobs, lib):
    outdir = outdir_for(lib)
    t0 = time.time()
    say(f"{CYAN}[*] Starting real-time incremental stream dumping...{RESET}")
    try:
        for items, ana in jobs:
            run_group_streaming(items, lib, outdir, ana)
    except KeyboardInterrupt:
        kill_all()
        raise
    say(f"{CYAN}[*] All dumps completed in {time.time() - t0:.1f}s -> {outdir}{RESET}")


def run_tasks_custom(tags_to_run, lib, mode):
    quick, slow, ana = [], [], []
    for t in tags_to_run:
        if t not in TASKS:
            continue
        title, cmd, kind = TASKS[t]
        {"quick": quick, "static_slow": slow, "analysis": ana}[kind].append((t, title, cmd))

    jobs = [(g, None) for g in (quick, slow) if g]
    if ana:
        jobs.append((ana, ANALYSIS[mode]))
        say(f"{CYAN}[*] Analysis mode loaded: {mode} ({ANALYSIS[mode]}){RESET}")
    run_jobs_streaming(jobs, lib)


# ========= NEW OPTION 9: PSEUDOCODE MENU & UE4 SECURITY HOOK EXTRACTOR =========
def pseudocode_menu(lib, mode):
    print(f"\n{CYAN}============================================================{RESET}")
    print(f"{CYAN}               PSEUDOCODE & UE4 HOOK EXTRACTOR               {RESET}")
    print(f"{CYAN}============================================================{RESET}")
    print(f"{WHITE} [1] Single Offset / Function Pseudocode{RESET}")
    print(f"{WHITE} [2] Entire Library Pseudocode + Extract UE4 Security Hooks{RESET}")
    choice = input("Choose sub-option [1-2]: ").strip()
    
    if choice == "1":
        disasm_single_function(lib, mode)
    elif choice == "2":
        dump_entire_lib_pseudocode_and_hooks(lib, mode)
    else:
        say(f"{RED}[!] Invalid choice{RESET}")


def disasm_single_function(lib, mode):
    raw = input("Function name or address (e.g. 0x1a2b0 or ClientMoveSpeedCheck): ").strip()
    if not raw:
        return
    target = raw if raw.lower().startswith(("0x", "entry")) or "." in raw else f"sym.{raw}"
    cmd = f"af @ {target}\npdf @ {target}\n?e\n?e PSEUDO_CODE\npdc @ {target}"
    run_jobs_streaming([([(f"func_single", f"PSEUDOCODE {raw}", cmd)], ANALYSIS[mode])], lib)


def dump_entire_lib_pseudocode_and_hooks(lib, mode):
    say(f"{CYAN}[*] Starting entire library true pseudocode extraction & UE4 security hook analysis...{RESET}")
    out_dir = outdir_for(lib)
    libname = Path(lib).stem
    all_pseudo_path = out_dir / f"dump_{libname}_entire_pseudocode.c"
    hooks_path = out_dir / f"UE4_Security_Hooks.h"
    
    ana_cmd = ANALYSIS[mode]
    script_content = f"{ana_cmd}\n?e MARK_PSEUDO\npdc @@f\n?e MARK_HOOKS\naflj\n"
    
    fd, script = tempfile.mkstemp(suffix=".r2")
    with os.fdopen(fd, "w") as f:
        f.write(script_content)
        
    cmd = ["r2", "-q", "-e", "scr.color=0", "-e", "scr.interactive=false", "-i", script, lib]
    
    say(f"{CYAN}[*] Decompiling entire library (Streaming live to file)...{RESET}")
    
    current_section = None
    hooks_json_lines = []
    
    with open(all_pseudo_path, "w", encoding="utf-8") as pseudo_file:
        pseudo_file.write(f"// Entire Library Pseudocode Dump for {libname}\n// Generated by DUMPTOOL V8\n\n")
        
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
        PROCS.append(p)
        
        for line in p.stdout:
            if "MARK_PSEUDO" in line:
                current_section = "pseudo"
                continue
            elif "MARK_HOOKS" in line:
                current_section = "hooks"
                continue
            
            if current_section == "pseudo":
                pseudo_file.write(line)
                pseudo_file.flush()
            elif current_section == "hooks":
                hooks_json_lines.append(line)
        p.wait()
        
    try:
        os.unlink(script)
    except OSError:
        pass
        
    say(f"{GREEN}[✔] Entire library pseudocode successfully saved to: {all_pseudo_path}{RESET}")
    
    # Analyze functions for UE4 security, anti-cheat, and hook signatures
    say(f"{CYAN}[*] Filtering and parsing functions for UE4 security & hook offsets...{RESET}")
    try:
        json_text = "".join(hooks_json_lines)
        i, j = json_text.find("["), json_text.rfind("]")
        if i != -1 and j > i:
            funcs = json.loads(json_text[i:j+1])
            
            security_keywords = [
                "check", "auth", "security", "encrypt", "decrypt", "anti", "cheat", 
                "hook", "speed", "teleport", "processevent", "gnames", "gworld", 
                "net", "ack", "verify", "signature", "integrity", "bypass"
            ]
            
            hook_count = 0
            with open(hooks_path, "w", encoding="utf-8") as hook_file:
                hook_file.write("#pragma once\n#include <cstdint>\n\n// Extracted UE4 Security, Anti-Cheat & Potential Hook Offsets\n// Generated by DUMPTOOL V8\nnamespace UE4SecurityHooks {\n")
                
                for fcn in funcs:
                    name = fcn.get("name", "")
                    offset = fcn.get("offset", 0)
                    size = fcn.get("size", 0)
                    
                    lower_name = name.lower()
                    if any(kw in lower_name for kw in security_keywords):
                        hook_count += 1
                        clean_name = re.sub(r'[\s\(\)\#\/\.\-\+]+', '_', name).strip('_')
                        hook_file.write(f"    // Function: {name} (Size: {size} bytes)\n")
                        hook_file.write(f"    constexpr uintptr_t {clean_name} = 0x{offset:X};\n\n")
                        
                hook_file.write("}\n")
                
            say(f"{GREEN}[✔] Extracted {hook_count} security/hook offsets into separate file: {hooks_path}{RESET}")
        else:
            say(f"{YELLOW}[!] Could not parse function JSON for hook extraction.{RESET}")
    except Exception as e:
        say(f"{RED}[!] Error during security hook filtering: {e}{RESET}")


# ========= INTERACTIVE SELECTION MENU =========
MENU = f"""
{YELLOW}
============================================================
              DUMPTOOL V8 - CONTROL PANEL
============================================================
 [1] FULL MASSIVE DUMP (All Tasks with Live Streaming)
 [2] CHOOSE SPECIFIC DUMPS (Interactive Custom Selection)
 [3] EXPORT SYMBOLS, IMPORTS & EXPORTS DUMP
 [4] EXTRACT ALL STRINGS (ASCII & UTF-16 Streaming)
 [5] CALL GRAPH & FUNCTIONS TOPOLOGY
 [6] XREFS ANALYSIS (Cross References)
 [7] FULL FUNCTION LIST (afl)
 [8] JNI FUNCTIONS & EXPORTS SCAN
 [9] PSEUDOCODE (Single Offset vs Entire Lib + UE4 Security Hooks)
 [10] GAME ENGINE SIGNATURE SCAN (UE4/UE5 & Unity)
 [11] CHANGE ANALYSIS MODE (Current: <mode>)
 [12] FIND OFFSETS BY STRING NAMES (Generates C++ Header)
 [0] EXIT
============================================================
{RESET}
"""

def custom_dump_selection(lib, mode):
    print(f"\n{CYAN}Available Dump Tasks:{RESET}")
    keys = list(TASKS.keys())
    for idx, key in enumerate(keys, 1):
        title = TASKS[key][0]
        print(f"{WHITE} [{idx:2d}] {key:<12} -> {title}{RESET}")
    
    ans = input("\nEnter numbers separated by space or comma (e.g. 1,2,5 or 'all'): ").strip()
    if not ans:
        return
    if ans.lower() == 'all':
        run_tasks_custom(FULL_ORDER, lib, mode)
        return
    
    selected_tags = []
    for part in re.split(r'[\s,]+', ans):
        if part.isdigit():
            num = int(part)
            if 1 <= num <= len(keys):
                selected_tags.append(keys[num - 1])
    
    if selected_tags:
        say(f"{GREEN}[+] Running custom dump for: {', '.join(selected_tags)}{RESET}")
        run_tasks_custom(selected_tags, lib, mode)
    else:
        say(f"{RED}[!] No valid tasks selected.{RESET}")


def main():
    ensure_r2()
    banner()

    parser = argparse.ArgumentParser(description="DUMPTOOL V8 - Streaming Android Binary & UE4 Hook Analyzer")
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET, help="Path to .so library or folder")
    parser.add_argument("--all", action="store_true", help="Run full dump automatically")
    parser.add_argument("--mode", choices=["fast", "normal", "deep"], default="fast", help="Analysis depth mode")
    args = parser.parse_args()

    libs = find_libs(args.target)
    if not libs:
        sys.exit(f"{RED}[!] No .so libraries found in target path: {args.target}{RESET}")

    lib = libs[0] if len(libs) == 1 else pick_lib(libs, args.target)
    mode = args.mode

    if args.all:
        run_tasks_custom(FULL_ORDER, lib, mode)
        return

    while True:
        print(MENU.replace("<mode>", mode))
        print(f"{WHITE}Active Library: {os.path.basename(lib)} | Mode: {mode} ({ANALYSIS[mode]}){RESET}")
        opt = input("Choose option [0-12]: ").strip().lower()
        
        if opt == "1":
            run_tasks_custom(FULL_ORDER, lib, mode)
        elif opt == "2":
            custom_dump_selection(lib, mode)
        elif opt == "3":
            run_tasks_custom(["symbols", "imports", "exports", "plt_got"], lib, mode)
        elif opt == "4":
            run_tasks_custom(["strings"], lib, mode)
        elif opt == "5":
            run_tasks_custom(["callgraph"], lib, mode)
        elif opt == "6":
            run_tasks_custom(["xrefs"], lib, mode)
        elif opt == "7":
            run_tasks_custom(["functions"], lib, mode)
        elif opt == "8":
            run_tasks_custom(["jni"], lib, mode)
        elif opt == "9":
            pseudocode_menu(lib, mode)
        elif opt == "10":
            auto_scan_game_engines(lib)
        elif opt == "11":
            mode = "normal" if mode == "fast" else ("deep" if mode == "normal" else "fast")
            say(f"{GREEN}[+] Analysis mode switched to: {mode}{RESET}")
        elif opt == "12":
            find_by_string(lib, mode)
        elif opt == "0" or opt == "exit":
            say(f"{CYAN}[*] Exiting DUMPTOOL V8. Goodbye!{RESET}")
            sys.exit(0)
        else:
            say(f"{RED}[!] Invalid option selected. Try again.{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        kill_all()
        print(f"\n{RED}[!] Interrupted by user. Exiting...{RESET}")
        sys.exit(0)