#!/usr/bin/env python3
"""
DUMPTOOL V4 - Android Binary Analysis Framework (radare2 based)

Usage:
    python text.py                       # interactive menu (default folder)
    python text.py /path/to/dir_or_lib.so
    python text.py lib.so --all --mode fast     # non-interactive full dump

Menu option [12]: give string name(s) (e.g. ClientMoveSpeedCheck) and the tool
searches them in the lib, follows the xrefs and prints the function offsets.
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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ========= COLORS =========
CYAN   = "\033[0;36m"
GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
WHITE  = "\033[0;37m"
RESET  = "\033[0m"

# ========= SETTINGS =========
DEFAULT_TARGET = "/storage/emulated/0/Download/Telegram/she5/"
SCRIPT_DIR = Path(__file__).resolve().parent
OUT_EXT = "c"                     # extension of the dump files
MARK = "DUMPSEC_9f3a_"            # section marker used to split r2 output
ANALYSIS = {"fast": "aa", "normal": "aaa", "deep": "aaaa"}

# tag: (title, r2 commands (one per line), kind)
#   quick       -> needs no analysis, runs in one fast process
#   static_slow -> needs no analysis but is heavy (own process, runs in parallel)
#   analysis    -> needs analysis (analysis runs ONCE for the whole group)
TASKS = {
    "elf":       ("ELF INFO",          "iI", "quick"),
    "sections":  ("SECTIONS",          "iS", "quick"),
    "imports":   ("IMPORTS",           "ii", "quick"),
    "exports":   ("EXPORTS",           "iE", "quick"),
    "symbols":   ("SYMBOLS",           "is", "quick"),
    "reloc":     ("RELOCATIONS",       "ir", "quick"),
    "dynamic":   ("DYNAMIC",           "il\n?e\nid", "quick"),
    "memory":    ("MEMORY MAP",        "om", "quick"),
    "jni":       ("JNI FUNCTIONS",     "is~Java_\n?e\nis~JNI_OnLoad\nis~JNI_OnUnload", "quick"),
    "entry":     ("ENTRYPOINT DISASM", "s entry0\naf\npdf", "quick"),
    "cfg":       ("CFG",               "s entry0\naf\nagf", "quick"),
    "strings":   ("STRINGS",           "izz", "static_slow"),
    "functions": ("FUNCTION LIST",     "afl", "analysis"),
    "callgraph": ("CALL GRAPH",        "agCd", "analysis"),
    "xrefs":     ("XREFS",             "axt @@ sym.*", "analysis"),
    "disasm":    ("ALL FUNCTIONS DISASM", "pdf @@f", "analysis"),
}

FULL_ORDER = ["elf", "sections", "imports", "exports", "symbols", "strings",
              "reloc", "dynamic", "memory", "jni", "functions", "callgraph",
              "xrefs", "cfg", "entry"]

PRINT_LOCK = threading.Lock()
PROCS = []


def say(msg):
    with PRINT_LOCK:
        print(msg, flush=True)


def clear():
    print("\033[2J\033[H", end="", flush=True)


# ========= SETUP =========
def ensure_r2():
    """Only radare2 is really needed (the old coreutils/findutils/util-linux
    checks failed on every run and re-ran `pkg install` each time)."""
    if shutil.which("r2"):
        return
    print(f"{CYAN}[+] Installing radare2{RESET}")
    subprocess.call(["pkg", "install", "-y", "radare2"])
    if not shutil.which("r2"):
        sys.exit(f"{RED}[!] radare2 is not installed{RESET}")


def banner():
    print(f"""{RED}
╔══════════════════════════════════════════════════════════╗
║          ██████╗ ██╗   ██╗███╗   ███╗██████╗             ║
║          ██╔══██╗██║   ██║████╗ ████║██╔══██╗            ║
║          ██║  ██║██║   ██║██╔████╔██║██████╔╝            ║
║          ██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝             ║
║          ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║                 ║
║          ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝                 ║
║                  DUMPTOOL V4 - ADVANCED                  ║
║           Android Binary Analysis Framework              ║
╚══════════════════════════════════════════════════════════╝
{RESET}""")


# ========= FIND LIBS =========
def find_libs(target):
    libs = []
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
                size = os.path.getsize(lib) / 1024
            except OSError:
                size = 0
            rel = os.path.relpath(lib, target)
            print(f"{WHITE}[{i}] {rel}  ({size:,.0f} KB){RESET}")
        ans = input("\nChoose lib number (or type text to filter): ").strip()
        if ans.isdigit() and 1 <= int(ans) <= len(shown):
            return shown[int(ans) - 1]
        if ans and not ans.isdigit():
            hits = [l for l in libs if ans.lower() in os.path.basename(l).lower()]
            if hits:
                shown = hits
                continue
        print(f"{RED}[!] Invalid choice{RESET}\n")


# ========= r2 ENGINE =========
def kill_all():
    for p in PROCS:
        if p.poll() is None:
            p.terminate()


def outdir_for(lib):
    d = SCRIPT_DIR / f"dump_{Path(lib).stem}"
    d.mkdir(exist_ok=True)
    return d


def run_group(items, lib, outdir, ana_cmd=None):
    """Run ONE r2 process for a group of tasks. Analysis (if any) runs once,
    then every task is executed in the same session and its output is split
    into its own file using section markers."""
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

    def close_section():
        nonlocal out, wrote
        if out is None:
            return
        out.close()
        took = time.time() - t_sec
        if wrote:
            say(f"{GREEN}[✔] Saved {out_path}  ({took:.1f}s){RESET}")
        else:
            say(f"{YELLOW}[!] Empty result: {out_path}{RESET}")
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
                wrote += 1
        p.wait()
    finally:
        close_section()
        try:
            os.unlink(script)
        except OSError:
            pass


def run_jobs(jobs, lib):
    """jobs: list of (items, analysis_cmd). Jobs run in parallel."""
    outdir = outdir_for(lib)
    t0 = time.time()
    stop = threading.Event()

    def ticker():
        while not stop.wait(10):
            say(f"{YELLOW}[~] working... {int(time.time() - t0)}s{RESET}")

    threading.Thread(target=ticker, daemon=True).start()
    try:
        with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            futures = [ex.submit(run_group, items, lib, outdir, ana)
                       for items, ana in jobs]
            try:
                for f in futures:
                    f.result()
            except KeyboardInterrupt:
                kill_all()
                raise
    finally:
        stop.set()
    say(f"{CYAN}[*] Done in {time.time() - t0:.1f}s -> {outdir}{RESET}")


def run_tasks(tags, lib, mode):
    quick, slow, ana = [], [], []
    for t in tags:
        title, cmd, kind = TASKS[t]
        {"quick": quick, "static_slow": slow, "analysis": ana}[kind].append((t, title, cmd))

    jobs = [(g, None) for g in (quick, slow) if g]
    if ana:
        jobs.append((ana, ANALYSIS[mode]))
        say(f"{CYAN}[*] Analysis mode: {mode} ({ANALYSIS[mode]}) - runs once{RESET}")
    say(f"{CYAN}[*] Running {len(jobs)} parallel r2 job(s)...{RESET}")
    run_jobs(jobs, lib)


def disasm_function(lib):
    raw = input("Function name or address (0x1a2b0 / Java_com_x_y): ").strip()
    if not re.fullmatch(r"[\w.$+\-]+", raw or ""):
        say(f"{RED}[!] Invalid name/address{RESET}")
        return
    if raw.lower().startswith(("0x", "entry")) or "." in raw:
        target = raw
    else:
        target = f"sym.{raw}"
    safe = re.sub(r"\W", "_", raw)
    cmd = f"af @ {target}\npdf @ {target}\n?e\n?e PSEUDO_CODE\npdc @ {target}"
    run_jobs([([(f"func_{safe}", f"FUNCTION {raw}", cmd)], None)], lib)


# ========= FIND OFFSET BY STRING NAME =========
MAX_SCAN = 200000      # safety cap of raw hits per name (very generic names)
MAX_PARTIAL = 30       # max "contains" hits kept when no exact string exists
MAX_FUNCS = 10         # max functions printed per name


def parse_entries(text):
    """Turn the user's input into [("header", txt) | ("name", txt)].
    Accepts plain names, comma separated names, or lines in the same style
    as the offsets list:  '0x5FE8A40 // ClientMoveSpeedCheck'
    ('// Group' lines are kept as headers, duplicate names are dropped)."""
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
        label = re.sub(r"\s*\(.*\)\s*$", "", label).strip()   # drop "(Simple)"
        if label and label not in seen:
            seen.add(label)
            entries.append(("name", label))
    return entries


def elf_load_segments(path):
    """PT_LOAD segments of an ELF (32/64 bit) -> [(file_off, vaddr, filesz)]."""
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
        if ptype == 1 and filesz:          # PT_LOAD
            segs.append((off, vaddr, filesz))
    return segs


def file_to_vaddr(segs, off):
    for s_off, s_va, s_size in segs:
        if s_off <= off < s_off + s_size:
            return s_va + off - s_off
    return None


def locate_strings(lib, names):
    """Search every name directly in the file (fast, no r2) and convert the
    file offsets to virtual addresses.
    Returns {name: (list_of_vaddr, kind)}, kind = exact | partial | none.
    exact   = a whole NUL-terminated string (ASCII or UTF-16)
    partial = only found inside a longer string (used when no exact hit)."""
    segs = elf_load_segments(lib)
    found = {}
    with open(lib, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        size = len(mm)
        for name in names:
            exact, partial = [], []
            pat = name.encode("utf-8")
            pos, n = mm.find(pat), 0
            while pos != -1 and n < MAX_SCAN:
                n += 1
                end = pos + len(pat)
                before = mm[pos - 1] if pos > 0 else 0
                after = mm[end] if end < size else 0
                (exact if before == 0 and after == 0 else partial).append(pos)
                pos = mm.find(pat, pos + 1)

            wpat = name.encode("utf-16-le")
            pos, n = mm.find(wpat), 0
            while pos != -1 and n < MAX_SCAN:
                n += 1
                end = pos + len(wpat)
                if pos >= 2 and mm[pos - 2:pos] == b"\0\0" and mm[end:end + 2] == b"\0\0":
                    exact.append(pos)
                pos = mm.find(wpat, pos + 1)

            kind, hits = "none", []
            if exact:
                kind, hits = "exact", exact
            elif partial:
                kind, hits = "partial", partial[:MAX_PARTIAL]
            vas = []
            for h in hits:
                va = file_to_vaddr(segs, h)
                if va is not None and va not in vas:
                    vas.append(va)
            found[name] = (vas, kind if vas else "none")
    return found


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
    """One r2 session: analysis runs once, then the given commands.
    Returns {tag: [output lines]} split on `?e MARK<tag>` markers."""
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
        while not stop.wait(10):
            say(f"{YELLOW}[~] working... {int(time.time() - t0)}s{RESET}")

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


def read_names_input():
    """Ask for names: comma separated / .txt file path / 'paste' (multi-line)."""
    print(f"{CYAN}String name(s): comma separated, a .txt file path, "
          f"or 'paste' for a full list{RESET}")
    raw = input("> ").strip().strip("'\"")
    if not raw:
        return ""
    if raw.lower() == "paste":
        print(f"{CYAN}Paste the list, then type 'done' on a new line{RESET}")
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


def find_by_string(lib, mode):
    entries = parse_entries(read_names_input())
    names = [t for k, t in entries if k == "name"]
    if not names:
        say(f"{RED}[!] No names given{RESET}")
        return

    say(f"{CYAN}[*] Searching {len(names)} name(s) in {os.path.basename(lib)} ...{RESET}")
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
        say(f"{CYAN}[*] Resolving xrefs of {len(addrs)} string(s) - analysis "
            f"{mode} ({ANALYSIS[mode]}) runs once{RESET}")
        sections = run_r2_capture(lib, ana, lines)
        for i, a in enumerate(addrs):
            refs[a] = parse_json_list(sections.get(f"x{i}", []))

    # ---- build the result lines (colour, text) ----
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
        tag = " (partial match)" if kind == "partial" else ""
        out = []
        if funcs:
            ok += 1
            order = sorted(funcs.items(), key=lambda kv: (-kv[1], kv[0]))
            shown = order[:MAX_FUNCS]
            for i, (fa, cnt) in enumerate(shown, 1):
                extra = f" #{i}/{len(order)} ({cnt} ref{"s" if cnt > 1 else ""})" if len(order) > 1 else ""
                out.append((GREEN, f"0x{fa:X} // {name}{extra}{tag}"))
            if len(order) > len(shown):
                out.append((YELLOW, f"// ... +{len(order) - len(shown)} more function(s) for {name}"))
        elif nofunc:
            ok += 1
            for fr in sorted(set(nofunc))[:MAX_FUNCS]:
                out.append((YELLOW, f"0x{fr:X} // {name} (xref, no function){tag}"))
        elif vas:
            out.append((YELLOW, f"// {name}: string @ 0x{vas[0]:X} but no xref "
                                f"(try mode deep / data table){tag}"))
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
    say(f"\n{CYAN}[*] Resolved {ok}/{len(names)} name(s){RESET}")

    out_path = outdir_for(lib) / f"dump_{Path(lib).stem}_offsets.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(t for _, t in lines_out).lstrip("\n") + "\n")
    say(f"{GREEN}[✔] Saved {out_path}{RESET}")


# ========= MENU =========
MENU = f"""
{YELLOW}
[1] FULL ADVANCED DUMP (ALL, parallel)
[2] SYMBOLS
[3] STRINGS
[4] CALL GRAPH
[5] XREFS
[6] FUNCTION LIST
[7] ENTRYPOINT DISASM
[8] JNI FUNCTIONS (Java_* / JNI_OnLoad)
[9] DISASM + PSEUDO-CODE OF ONE FUNCTION
[10] DISASM ALL FUNCTIONS (big!)
[11] CHANGE ANALYSIS MODE (fast / normal / deep)
[12] FIND OFFSET BY STRING NAME (e.g. ClientMoveSpeedCheck)
[0] EXIT
{RESET}
"""

SIMPLE = {"2": ["symbols"], "3": ["strings"], "4": ["callgraph"], "5": ["xrefs"],
          "6": ["functions"], "7": ["entry"], "8": ["jni"], "10": ["disasm"]}


def menu_loop(lib, mode):
    while True:
        print(MENU)
        print(f"{WHITE}Lib: {os.path.basename(lib)} | mode: {mode} "
              f"({ANALYSIS[mode]}){RESET}")
        opt = input("Choose option: ").strip().lower()
        try:
            if opt in ("0", "q"):
                print(f"{CYAN}Bye 👋{RESET}")
                return
            elif opt == "1":
                tags = FULL_ORDER + (["disasm"] if mode == "deep" else [])
                run_tasks(tags, lib, mode)
            elif opt in SIMPLE:
                run_tasks(SIMPLE[opt], lib, mode)
            elif opt == "9":
                disasm_function(lib)
            elif opt == "12":
                find_by_string(lib, mode)
            elif opt == "11":
                m = input("Mode [fast/normal/deep]: ").strip().lower()
                if m in ANALYSIS:
                    mode = m
                else:
                    say(f"{RED}[!] Invalid mode{RESET}")
            else:
                say(f"{RED}[!] Invalid option{RESET}")
        except KeyboardInterrupt:
            kill_all()
            say(f"\n{RED}[!] Interrupted{RESET}")
        input(f"\n{CYAN}Press ENTER to return to menu...{RESET}")
        clear()


def main():
    ap = argparse.ArgumentParser(description="DUMPTOOL V4 (radare2)")
    ap.add_argument("path", nargs="?", default=DEFAULT_TARGET,
                    help="a .so file or a folder containing .so files")
    ap.add_argument("--mode", choices=ANALYSIS, default="normal",
                    help="analysis depth: fast=aa, normal=aaa, deep=aaaa")
    ap.add_argument("--all", action="store_true",
                    help="run the full dump and exit (no menu)")
    args = ap.parse_args()

    ensure_r2()
    clear()
    banner()

    if os.path.isfile(args.path):
        lib = args.path
    else:
        libs = find_libs(args.path)
        if not libs:
            sys.exit(f"{RED}[!] No .so files found in {args.path}{RESET}")
        if args.all and len(libs) > 1:
            sys.exit(f"{RED}[!] --all needs a single .so file path{RESET}")
        lib = libs[0] if len(libs) == 1 and args.all else pick_lib(libs, args.path)

    if args.all:
        tags = FULL_ORDER + (["disasm"] if args.mode == "deep" else [])
        run_tasks(tags, lib, args.mode)
        return

    menu_loop(lib, args.mode)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        kill_all()
        print(f"\n{RED}[!] Exit{RESET}")
