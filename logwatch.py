#!/usr/bin/env python3
"""
logwatch - live log and command watcher for your Linux laptop
-------------------------------------------------------------
Run with no arguments to get an interactive  log>  prompt:

    scan [--hours 24]     scan recent logs + your shell history for red flags
    watch                 LIVE tail: alerts appear the moment something happens
    check <command>       analyze a command line WITHOUT running it
    clean [--days 7]      preview old logs to delete (add --apply to delete)
    sources | stats | rules | hook | add <file> | addroot <dir> | help | quit

Also works one-shot (good for cron):
    python3 logwatch.py scan --hours 48
    python3 logwatch.py watch --notify
    python3 logwatch.py check "curl http://x.sh | sh"
    python3 logwatch.py clean --days 7 --apply --yes
    python3 logwatch.py clean --days 7 --apply --yes --system     (needs sudo)

Reading /var/log/auth.log usually needs root or the 'adm' group:
    sudo python3 logwatch.py        or:  sudo usermod -aG adm $USER  (then re-login)

Standard library only. Static pattern matching: it reports red flags, it cannot
prove a machine is clean. Cleaning is DRY-RUN unless you pass --apply.
"""

import argparse
import collections
import datetime as dt
import gzip
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time

try:
    import readline  # noqa: F401  (arrow-key history in the prompt)
except ImportError:
    readline = None

HOME = os.path.expanduser("~")
STATE_DIR = os.environ.get("LOGWATCH_HOME", os.path.join(HOME, ".logwatch"))
CONFIG = os.path.join(STATE_DIR, "config.json")
TTY = sys.stdout.isatty()
UNI = (sys.stdout.encoding or "").lower().startswith("utf")

SEV_COLOR = {"HIGH": "1;91", "MED": "93", "LOW": "96", "INFO": "2"}
SEV_ORDER = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3}


def paint(text, code):
    return f"\033[{code}m{text}\033[0m" if TTY else str(text)


def sev_tag(sev):
    return paint(f"{sev:<4}", SEV_COLOR[sev])


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def tilde(path):
    return "~" + path[len(HOME):] if path.startswith(HOME + os.sep) else path


def spark(values):
    chars = "▁▂▃▄▅▆▇█" if UNI else ".:-=+*#@"
    top = max(values) if values else 0
    if top == 0:
        return chars[0] * len(values)
    return "".join(chars[min(len(chars) - 1, int(v / top * (len(chars) - 1) + 0.5))] if v else chars[0]
                   for v in values)


# =====================================================================
# Detection rules
# =====================================================================
def R(name, sev, pattern, hint, flags=re.I):
    return (name, sev, re.compile(pattern, flags), hint)


LOG_RULES = [
    R("Root login accepted over SSH", "HIGH", r"Accepted \w+(?:-\w+)? for root\b",
      "Disable root SSH login (PermitRootLogin no)."),
    R("User not allowed to use sudo", "HIGH", r"NOT in sudoers|is not in the sudoers file",
      "Someone tried sudo without permission."),
    R("Log cleared or truncated", "HIGH", r"log (?:file )?(?:was )?(?:cleared|truncated)|audit log.*cleared|"
      r"Journal file .* corrupted", "Attackers wipe logs to hide tracks. Investigate."),
    R("New user account created", "HIGH", r"new user: name=|useradd\[\d+\]: new user|Adding user ",
      "Verify you created this account."),
    R("User added to admin group", "HIGH", r"add '[^']*' to (?:shadow )?group '(?:sudo|wheel|admin|root)'",
      "Privilege grant. Verify it was you."),
    R("Failed login", "MED", r"Failed password|authentication failure|Invalid user|FAILED LOGIN|Failed publickey|"
      r"maximum authentication attempts|PAM \d+ more authentication failures",
      "Repeated failures from one IP means brute force."),
    R("Wrong sudo password", "MED", r"incorrect password attempts?|sudo:.*authentication failure",
      "Check who is at the keyboard."),
    R("su to root", "MED", r"pam_unix\(su(?:-l)?:session\): session opened for user root",
      "Root shell opened."),
    R("SSH probe or scan", "MED", r"Did not receive identification string|Bad protocol version identification|"
      r"Unable to negotiate|kex_exchange_identification|Connection closed by (?:invalid|authenticating) user",
      "Typical of internet scanners. Keep SSH patched, use keys."),
    R("Firewall block", "MED", r"UFW BLOCK|iptables.*DROP", "Traffic your firewall rejected."),
    R("Crash or out-of-memory", "MED", r"segfault at|general protection fault|core dumped|Out of memory: Kill|"
      r"oom-kill|kernel BUG", "Crashes can be bugs, or exploitation attempts."),
    R("Crontab changed", "MED", r"crontab\[\d+\]: \(\w+\) (?:REPLACE|BEGIN EDIT|DELETE)",
      "Cron is a common persistence trick. Verify the change."),
    R("Network sniffing mode", "MED", r"entered promiscuous mode", "NIC is capturing all traffic."),
    R("Kernel module not verified", "MED", r"module verification failed", "Unsigned kernel module loaded."),
    R("sudo command run", "LOW", r"sudo:.*COMMAND=", "Audit trail of privileged commands."),
    R("Successful SSH login", "LOW", r"Accepted (?:password|publickey|keyboard-interactive)",
      "Make sure you recognize the source IP."),
    R("USB device attached", "LOW", r"New USB device found|usb \d+-[\d.]+: new .*USB", "New hardware connected."),
]

CMD_RULES = [
    R("Download piped into a shell", "HIGH", r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
      "Runs unseen code from the internet. Download, read it, then run."),
    R("Remote content eval'd", "HIGH", r"\beval\s+[\"']?\$\(\s*(?:curl|wget)\b", "Executes whatever the server sends."),
    R("Decoded payload piped to a shell", "HIGH", r"base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba|z)?sh\b",
      "Classic malware dropper pattern."),
    R("Reverse shell", "HIGH", r"/dev/tcp/\d|bash\s+-i\s*>&|\bnc(?:at)?\s+(?:-\w*e|-c)\s|mkfifo\s+\S+\s*;?\s*nc",
      "Gives a remote machine control of this one."),
    R("Wipes a disk", "HIGH", r"\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|hd|vd)|\bmkfs(?:\.\w+)?\s+/dev/|>\s*/dev/sd[a-z]",
      "Destroys data on a whole device."),
    R("Fork bomb", "HIGH", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Freezes the machine."),
    R("Covers tracks (history or logs)", "HIGH", r"\bhistory\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|"
      r"\bshred\b[^\n]*(?:/var/log|history)|>\s*/var/log/\S+|\brm\b[^\n]*(?:/var/log/|\.bash_history)",
      "Erasing evidence is an attacker habit."),
    R("Adds an SSH key (backdoor risk)", "HIGH", r">>\s*\S*\.ssh/authorized_keys",
      "Grants permanent remote login. Verify the key is yours."),
    R("Disables a security control", "HIGH", r"\bsetenforce\s+0|\bufw\s+disable|\bsystemctl\s+(?:stop|disable|mask)\s+"
      r"(?:ufw|firewalld|apparmor|auditd|fail2ban)|\biptables\s+-F\b", "Turns protection off."),
    R("World-writable permissions (777)", "MED", r"\bchmod\s+(?:-\S+\s+)*(?:0?777|a\+rwx)\b",
      "Anyone on the system can modify these files."),
    R("Sets the setuid bit", "MED", r"\bchmod\s+(?:-\S+\s+)*(?:[ugoa]*\+s\b|[2467]\d{3}\b)",
      "Setuid binaries run as their owner (privilege escalation vector)."),
    R("Passwordless sudo", "MED", r"NOPASSWD", "Weakens privilege boundaries."),
    R("Creates a user or changes root password", "MED", r"\b(?:useradd|adduser)\b|usermod\s+-aG\s+(?:sudo|wheel)|"
      r"\bpasswd\s+root\b", "Verify it was intentional."),
    R("Downloads then runs a file", "MED", r"\b(?:curl|wget)\b[^\n]*(?:-o|-O)\s*\S+[^\n]*&&\s*(?:chmod\s+\+x|bash|sh\b|\./)",
      "Read the file before running it."),
    R("Installs a package from a URL", "MED", r"(?:pip3?|npm)\s+install\s+(?:git\+)?https?://",
      "Unpinned code from an arbitrary host."),
    R("Writes to crontab", "MED", r"\bcrontab\s+(?:-e\b|-\s*$|-\s)|\|\s*crontab\b", "Possible persistence."),
    R("Root shell via sudo", "LOW", r"\bsudo\s+(?:su\b|-i\b|-s\b|bash\b|sh\b)", "Fine if intentional."),
    R("Security or hacking tool", "LOW", r"\b(?:nmap|masscan|sqlmap|hydra|nikto|john|hashcat|aircrack-ng|metasploit|msfconsole)\b",
      "Fine on your own lab. Never on systems you do not own."),
]

SAFE_RM_NAMES = {"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*", "/home", "/etc", "/usr", "/var",
                 "/boot", "/bin", "/lib", "/sbin", "/opt", "/root", "/home/*", "/etc/*", "/usr/*", "/var/*"}


def dangerous_rm(cmd):
    """True for recursive rm aimed at a system directory or your home."""
    for seg in re.split(r"[;&|]+", cmd):
        try:
            tokens = shlex.split(seg)
        except ValueError:
            tokens = seg.split()
        while tokens and tokens[0] in ("sudo", "command", "time", "nohup"):
            tokens = tokens[1:]
        if not tokens or tokens[0] != "rm":
            continue
        flags = [t for t in tokens[1:] if t.startswith("-")]
        recursive = "--recursive" in flags or any("r" in f.lower() for f in flags if not f.startswith("--"))
        if "--no-preserve-root" in flags:
            return True
        if recursive and any(t.rstrip("/") in {x.rstrip("/") for x in SAFE_RM_NAMES} or t in SAFE_RM_NAMES
                             for t in tokens[1:] if not t.startswith("-")):
            return True
    return False


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FROM_IP_RE = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b")
USER_RE = re.compile(r"(?:Invalid user|for invalid user|for)\s+(\S+)\s+from\s", re.I)


class Alert:
    __slots__ = ("sev", "rule", "hint", "line", "ip", "user", "ts", "src")

    def __init__(self, sev, rule, hint, line, ip=None, user=None, ts=None, src=""):
        self.sev, self.rule, self.hint, self.line = sev, rule, hint, line
        self.ip, self.user, self.ts, self.src = ip, user, ts, src


class Detector:
    """Shared by scan and watch so `stats` covers everything this session."""

    def __init__(self, burst_limit=5, window=60):
        self.limit, self.window = burst_limit, window
        self.lines = 0
        self.by_rule = collections.Counter()
        self.by_sev = collections.Counter()
        self.ips = collections.Counter()
        self.hits = collections.defaultdict(collections.deque)
        self.users = collections.defaultdict(set)
        self.last = {}

    def feed(self, line, kind="log", ts=None, src=""):
        self.lines += 1
        alerts = []
        ip = user = None
        if kind == "log":
            m = FROM_IP_RE.search(line) or IP_RE.search(line)
            ip = m.group(1) if m and m.groups() else (m.group(0) if m else None)
            u = USER_RE.search(line)
            user = u.group(1) if u else None
        rules = CMD_RULES if kind == "cmd" else LOG_RULES
        for name, sev, rx, hint in rules:
            if rx.search(line):
                alerts.append(Alert(sev, name, hint, line, ip, user, ts, src))
        if kind == "cmd" and dangerous_rm(line):
            alerts.append(Alert("HIGH", "Recursive delete of a system or home directory",
                                "This can destroy your system or all your files.", line, None, None, ts, src))
        if kind == "log" and ip and any(a.rule == "Failed login" for a in alerts):
            now = ts if ts else time.time()
            dq = self.hits[ip]
            dq.append(now)
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if user:
                self.users[ip].add(user)
            if len(dq) >= self.limit and now - self.last.get(("b", ip), -1e18) > self.window:
                self.last[("b", ip)] = now
                alerts.append(Alert("HIGH", "Brute-force burst",
                                    f"{len(dq)} failed logins from {ip} within {self.window}s. "
                                    "Block it (ufw deny from IP) and use SSH keys.", line, ip, user, ts, src))
            if len(self.users[ip]) >= 5 and now - self.last.get(("s", ip), -1e18) > 3600:
                self.last[("s", ip)] = now
                alerts.append(Alert("HIGH", "Username spraying",
                                    f"{ip} tried {len(self.users[ip])} different usernames.", line, ip, user, ts, src))
        for a in alerts:
            self.by_rule[a.rule] += 1
            self.by_sev[a.sev] += 1
            if a.ip and a.sev in ("HIGH", "MED"):
                self.ips[a.ip] += 1
        return alerts


# =====================================================================
# Timestamps and sources
# =====================================================================
ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
CLASSIC_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")


def parse_ts(line):
    m = ISO_RE.match(line)
    try:
        if m:
            base = dt.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}")
            tz = m.group(3)
            if not tz:
                return base.timestamp()
            if tz == "Z":
                return base.replace(tzinfo=dt.timezone.utc).timestamp()
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            off = dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
            return base.replace(tzinfo=dt.timezone(sign * off)).timestamp()
        m = CLASSIC_RE.match(line)
        if m:
            now = dt.datetime.now()
            t = dt.datetime.strptime(f"{now.year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")
            if t > now + dt.timedelta(days=1):
                t = t.replace(year=now.year - 1)
            return t.timestamp()
    except ValueError:
        return None
    return None


class Source:
    def __init__(self, kind, path=None, label=None):
        self.kind, self.path = kind, path
        self.label = label or (os.path.basename(path) if path else kind)


LOG_CANDIDATES = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages",
                  "/var/log/kern.log", "/var/log/ufw.log", "/var/log/fail2ban.log"]
HIST_CANDIDATES = [os.path.join(HOME, ".bash_history"), os.path.join(HOME, ".zsh_history"),
                   os.path.join(HOME, ".local", "share", "fish", "fish_history")]


def load_config():
    try:
        with open(CONFIG, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        cfg = {}
    cfg.setdefault("files", [])
    cfg.setdefault("roots", [])
    return cfg


def save_config(cfg):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(CONFIG, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
    except OSError as e:
        print(paint(f"Could not save config: {e}", "91"))


def discover(extra_files=None, only_files=False, with_cmds=True, with_journal=True):
    """Return (sources, notes). only_files=True means use ONLY extra_files."""
    sources, notes = [], []
    extra = list(extra_files or [])
    if not only_files:
        extra += load_config()["files"]
        got_system = False
        for p in LOG_CANDIDATES:
            if os.path.exists(p):
                if os.access(p, os.R_OK):
                    sources.append(Source("log", p))
                    got_system = True
                else:
                    notes.append(f"{p}: permission denied (run with sudo, or: sudo usermod -aG adm $USER)")
        if not got_system and with_journal and shutil.which("journalctl"):
            sources.append(Source("journal", label="journalctl"))
            notes.append("No readable /var/log files, using journalctl "
                         "(add yourself to the 'adm' or 'systemd-journal' group to see everything).")
        elif not got_system and not shutil.which("journalctl"):
            notes.append("No readable system logs and no journalctl found. Use: add <file>")
        if with_cmds:
            sources += [Source("cmd", p) for p in HIST_CANDIDATES if os.path.isfile(p) and os.access(p, os.R_OK)]
    for p in extra:
        p = os.path.expanduser(p)
        if os.path.isfile(p) and os.access(p, os.R_OK):
            kind = "cmd" if re.search(r"history", os.path.basename(p), re.I) else "log"
            sources.append(Source(kind, p))
        else:
            notes.append(f"{p}: not found or unreadable")
    return sources, notes


def norm_cmd(line):
    """Return (command, ts) from bash, zsh-extended or fish history lines."""
    m = re.match(r"^: (\d+):\d+;(.*)$", line)
    if m:
        return m.group(2), float(m.group(1))
    m = re.match(r"^- cmd: (.*)$", line)
    if m:
        return m.group(1), None
    if re.match(r"^#\d{9,}$", line) or not line.strip() or line.startswith("  when:"):
        return None, None
    return line, None


def read_tail(path, max_bytes=5_000_000):
    if path.endswith(".gz"):
        with gzip.open(path, "rt", errors="replace") as fh:
            return fh.read().splitlines()[-50000:]
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if size > max_bytes:
            fh.seek(-max_bytes, os.SEEK_END)
            fh.readline()
        data = fh.read()
    return data.decode("utf-8", "replace").splitlines()


# =====================================================================
# scan
# =====================================================================
def do_scan(det, sources, hours):
    cutoff = time.time() - hours * 3600
    events = []
    per_source = []
    for s in sources:
        try:
            if s.kind == "journal":
                p = subprocess.run(["journalctl", "--since", f"{hours} hours ago", "-o", "short-iso",
                                    "--no-pager", "-q"], capture_output=True, text=True, errors="replace",
                                   timeout=90)
                lines = p.stdout.splitlines()
            else:
                lines = read_tail(s.path, 5_000_000 if s.kind == "log" else 1_000_000)
                if s.kind == "cmd":
                    lines = lines[-3000:]
        except (OSError, subprocess.SubprocessError) as e:
            per_source.append((s.label, 0, f"error: {e}"))
            continue
        n = 0
        for raw in lines:
            if s.kind == "cmd":
                text, ts = norm_cmd(raw)
                if text is None or (ts and ts < cutoff):
                    continue
                n += 1
                events += det.feed(text, "cmd", ts, s.label)
            else:
                ts = parse_ts(raw)
                if ts and ts < cutoff:
                    continue
                n += 1
                events += det.feed(raw, "log", ts, s.label)
        per_source.append((s.label, n, ""))
    return events, per_source, cutoff


def print_scan(events, per_source, hours, cutoff):
    print(paint(f"\nlogwatch scan: last {hours}h", "1"))
    print("=" * 72)
    for label, n, err in per_source:
        print(f"  {label:<18} {n:>7} lines  {paint(err, '91') if err else ''}")
    groups = collections.defaultdict(list)
    for a in events:
        groups[(a.sev, a.rule)].append(a)
    if not groups:
        print(paint("\n✔ No known red flags in this window." if UNI else "\nNo known red flags in this window.", "92"))
        print(paint("Heuristic scan, not a guarantee.", "2"))
        return
    print()
    for (sev, rule), items in sorted(groups.items(), key=lambda kv: (SEV_ORDER[kv[0][0]], -len(kv[1]))):
        ips = collections.Counter(a.ip for a in items if a.ip)
        extra = ""
        if ips:
            extra = "  top IPs: " + ", ".join(f"{ip} ({n})" for ip, n in ips.most_common(3))
        print(f"{sev_tag(sev)} {paint(rule, '1')}  x{len(items)}{extra}")
        print(paint(f"       {items[0].hint}", "2"))
        ex = items[-1].line.strip()
        print(f"       e.g. {ex[:110]}")
    buckets = [0] * 24
    width = hours * 3600 / 24
    for a in events:
        if a.ts and a.ts >= cutoff and a.sev in ("HIGH", "MED"):
            buckets[min(23, int((a.ts - cutoff) / width))] += 1
    if any(buckets):
        print(f"\nHIGH/MED activity (oldest to newest, {hours / 24:.1f}h per bar):  {spark(buckets)}")
    high = sum(1 for a in events if a.sev == "HIGH")
    med = sum(1 for a in events if a.sev == "MED")
    print("=" * 72)
    if high:
        print(paint(f"{high} HIGH, {med} MED findings. Review the HIGH items first.", "1;91"))
    else:
        print(paint(f"{med} MED findings, nothing HIGH.", "93"))


# =====================================================================
# watch (live)
# =====================================================================
class FileTail:
    def __init__(self, src):
        self.src, self.path = src, src.path
        self.f = open(self.path, "r", encoding="utf-8", errors="replace")
        self.f.seek(0, os.SEEK_END)
        self.ino = os.fstat(self.f.fileno()).st_ino
        self.buf = ""

    def poll(self):
        try:
            st = os.stat(self.path)
            if st.st_ino != self.ino or st.st_size < self.f.tell():  # rotated or truncated
                self.f.close()
                self.f = open(self.path, "r", encoding="utf-8", errors="replace")
                self.ino = os.fstat(self.f.fileno()).st_ino
        except OSError:
            return []
        chunk = self.f.read()
        if not chunk:
            return []
        self.buf += chunk
        *lines, self.buf = self.buf.split("\n")
        return lines

    def close(self):
        self.f.close()


class ProcTail:
    def __init__(self, src, cmd):
        self.src = src
        self.q = queue.Queue()
        self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                  errors="replace", bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.q.put(line.rstrip("\n"))

    def poll(self):
        out = []
        while True:
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                return out

    def close(self):
        self.p.terminate()


def notify(alert):
    sys.stdout.write("\a")
    if shutil.which("notify-send"):
        try:
            subprocess.Popen(["notify-send", "-u", "critical", f"logwatch: {alert.rule}",
                              (alert.ip or "") + " " + alert.line[:120]],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass


def do_watch(det, sources, show_all=False, notify_on=False, duration=None):
    tails = []
    for s in sources:
        try:
            if s.kind == "journal":
                tails.append(ProcTail(s, ["journalctl", "-f", "-n", "0", "-o", "short-iso", "--no-pager", "-q"]))
            else:
                tails.append(FileTail(s))
        except OSError as e:
            print(paint(f"Cannot watch {s.label}: {e}", "91"))
    if not tails:
        print("Nothing to watch. Use: add <file>, or run with sudo.")
        return
    names = ", ".join(t.src.label for t in tails)
    print(paint(f"LIVE: watching {names}", "1") + paint("   (Ctrl+C to stop)", "2"))
    if any(t.src.kind == "cmd" for t in tails):
        print(paint("Tip: shells only write history on exit. Run `hook` to see how to make it instant.", "2"))
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if UNI else "|/-\\"
    recent = collections.deque()
    session = collections.Counter()
    start = time.time()
    last_draw = 0.0
    tick = 0
    width = shutil.get_terminal_size((100, 20)).columns

    def clear():
        if TTY:
            sys.stdout.write("\r\033[K")

    def draw():
        now = time.time()
        while recent and now - recent[0] > 60:
            recent.popleft()
        bins = [0] * 12
        for t in recent:
            bins[min(11, int((now - t) // 5))] += 1
        bins.reverse()
        line = (f"{frames[tick % len(frames)]} live | lines {session['lines']} | "
                f"alerts {session['alerts']} ({session['HIGH']} high) | last 60s {spark(bins)}")
        sys.stdout.write("\r\033[K" + line[: width - 1])
        sys.stdout.flush()

    try:
        while True:
            for t in tails:
                for raw in t.poll():
                    if t.src.kind == "cmd":
                        text, ts = norm_cmd(raw)
                        if text is None:
                            continue
                        alerts = det.feed(text, "cmd", None, t.src.label)
                        shown = text
                    else:
                        alerts = det.feed(raw, "log", None, t.src.label)
                        shown = raw
                    session["lines"] += 1
                    for a in alerts:
                        session["alerts"] += 1
                        session[a.sev] += 1
                        recent.append(time.time())
                        clear()
                        who = " ".join(x for x in (f"ip={a.ip}" if a.ip else "", f"user={a.user}" if a.user else "") if x)
                        print(f"[{time.strftime('%H:%M:%S')}] {sev_tag(a.sev)} {paint(a.rule, '1')}  {who}"
                              f"  {paint('<- ' + a.src, '2')}")
                        print(paint("           " + shown.strip()[: max(40, width - 14)], "2"))
                        if a.sev == "HIGH":
                            print(paint("           " + a.hint, "93"))
                            if notify_on:
                                notify(a)
                    if show_all and not alerts:
                        clear()
                        print(paint("           " + shown.strip()[: max(40, width - 14)], "2"))
            now = time.time()
            if TTY and now - last_draw > 0.15:
                tick += 1
                draw()
                last_draw = now
            if duration and now - start >= duration:
                break
            time.sleep(0.15)
    except KeyboardInterrupt:
        pass
    finally:
        clear()
        for t in tails:
            t.close()
    print(paint(f"\nStopped. {session['lines']} lines, {session['alerts']} alerts "
                f"({session['HIGH']} high) in {time.time() - start:.0f}s.", "1"))


# =====================================================================
# check (analyze a command line without running it)
# =====================================================================
def do_check(det, text):
    text = text.strip()
    if not text:
        print("Usage: check <command line>   (it is analyzed, never executed)")
        return
    alerts = det.feed(text, "cmd", None, "check")
    if not alerts:
        print(paint("✔ " if UNI else "", "92") + "No risky patterns found in that command.")
        print(paint("Static check only. Still read what a command does before you run it.", "2"))
        return
    for a in sorted(alerts, key=lambda x: SEV_ORDER[x.sev]):
        print(f"{sev_tag(a.sev)} {paint(a.rule, '1')}")
        print(paint(f"       {a.hint}", "2"))
    worst = min(alerts, key=lambda x: SEV_ORDER[x.sev]).sev
    verdict = {"HIGH": "DO NOT RUN THIS unless you fully understand it.",
               "MED": "Be careful: review before running.", "LOW": "Probably fine if intentional."}[worst]
    print(paint(verdict, SEV_COLOR[worst]))


# =====================================================================
# clean
# =====================================================================
LOGISH = re.compile(r"\.log(?:\.\d+)?(?:\.(?:gz|bz2|xz|zst))?$|\.log\.old$|^\.xsession-errors(?:\.old)?$", re.I)
ROTATED = re.compile(r"\.(?:gz|bz2|xz|zst|old|bak|\d+)$", re.I)
PROTECTED_PREFIXES = ("wtmp", "btmp", "lastlog", "faillog", "utmp")


def walk_files(root, maxdepth):
    root = os.path.abspath(root)
    base = root.count(os.sep)
    for dp, dn, fn in os.walk(root, followlinks=False):
        if dp.count(os.sep) - base >= maxdepth:
            dn[:] = []
        dn[:] = [d for d in dn if not os.path.islink(os.path.join(dp, d))]
        for f in fn:
            yield os.path.join(dp, f)


def clean_candidates(days, roots, system):
    """Yield (path, size, age_days). Never yields symlinks, active logs or recent files."""
    cutoff = time.time() - days * 86400
    uid = os.getuid()
    out = []
    state = os.path.abspath(STATE_DIR)
    for root, depth in roots:
        if not os.path.isdir(root):
            continue
        for p in walk_files(root, depth):
            if os.path.abspath(p).startswith(state + os.sep):
                continue
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not (os.path.isfile(p) and not os.path.islink(p)) or st.st_uid != uid or st.st_mtime > cutoff:
                continue
            if LOGISH.search(os.path.basename(p)):
                out.append((p, st.st_size, (time.time() - st.st_mtime) / 86400))
    if system:
        for p in walk_files("/var/log", 3):
            parts = p.split(os.sep)
            if "journal" in parts or "audit" in parts:
                continue
            name = os.path.basename(p)
            if name.startswith(PROTECTED_PREFIXES) or not ROTATED.search(name):
                continue
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if os.path.islink(p) or not os.path.isfile(p) or st.st_mtime > cutoff:
                continue
            out.append((p, st.st_size, (time.time() - st.st_mtime) / 86400))
    return sorted(out, key=lambda x: -x[2])


def do_clean(days, apply, yes, archive, system, roots_override):
    if roots_override:
        roots = [(os.path.expanduser(r), 6) for r in roots_override]
    else:
        roots = [(os.path.join(HOME, ".npm", "_logs"), 3), (os.path.join(HOME, ".cache"), 4),
                 (os.path.join(HOME, ".local", "share", "xorg"), 2), (os.path.join(HOME, ".local", "state"), 4),
                 (os.path.join(HOME, ".pm2", "logs"), 2), (os.path.join(HOME, ".config"), 4), ("/tmp", 2),
                 (HOME, 0)] + [(r, 5) for r in load_config()["roots"]]
    if system and os.geteuid() != 0:
        print(paint("--system needs root. Re-run with: sudo python3 logwatch.py clean --system ...", "91"))
        system = False
    items = clean_candidates(days, roots, system)
    print(paint(f"\nlogwatch clean: log files not modified in {days}+ days", "1"))
    print("=" * 72)
    if not items:
        print("Nothing to clean.")
    for p, size, age in items[:60]:
        print(f"  {age:>6.1f}d  {human(size):>9}  {tilde(p)}")
    if len(items) > 60:
        print(paint(f"  ... and {len(items) - 60} more", "2"))
    total = sum(s for _, s, _ in items)
    print("=" * 72)
    print(f"{len(items)} file(s), {human(total)}. Active logs, symlinks and recent files are never touched.")
    journal_note = system and shutil.which("journalctl")
    if system and journal_note:
        print(f"Journal: will run `journalctl --vacuum-time={days}d` when applied.")
    if not apply:
        print(paint("DRY RUN: nothing deleted. Add --apply to delete.", "93"))
        return
    if not items and not journal_note:
        return
    if not yes:
        if not sys.stdin.isatty():
            print("Refusing to delete without confirmation. Pass --yes for non-interactive use.")
            return
        if input(f"Type DELETE to {'archive and ' if archive else ''}remove these {len(items)} file(s): ").strip() != "DELETE":
            print("Cancelled. Nothing deleted.")
            return
    os.makedirs(STATE_DIR, exist_ok=True)
    arch_dir = os.path.join(STATE_DIR, "archive", time.strftime("%Y%m%d-%H%M%S"))
    freed = done = failed = 0
    with open(os.path.join(STATE_DIR, "clean.log"), "a", encoding="utf-8") as audit:
        for p, size, _ in items:
            try:
                if archive:
                    os.makedirs(arch_dir, exist_ok=True)
                    dest = os.path.join(arch_dir, p.lstrip(os.sep).replace(os.sep, "__") + ".gz")
                    with open(p, "rb") as src, gzip.open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
                os.remove(p)
                freed += size
                done += 1
                audit.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} DELETED {p} ({size} bytes)\n")
            except OSError as e:
                failed += 1
                audit.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} FAILED  {p}: {e}\n")
    if system and journal_note:
        subprocess.run(["journalctl", f"--vacuum-time={days}d"], check=False)
    print(paint(f"Deleted {done} file(s), freed {human(freed)}" + (f", {failed} failed" if failed else "") + ".", "92"))
    if archive and done:
        print(f"Compressed copies kept in {tilde(arch_dir)}")
    print(f"Audit trail: {tilde(os.path.join(STATE_DIR, 'clean.log'))}")


# =====================================================================
# prompt and CLI
# =====================================================================
HELP = """Commands:
  scan [--hours N] [--file F]      scan recent logs and shell history
  watch [--all] [--notify]         LIVE alerts (Ctrl+C to stop)
  check <command line>             analyze a command without running it
  clean [--days 7] [--apply]       preview / delete old logs (dry-run by default)
  sources                          show what is being read (and what is blocked)
  stats                            totals for this session
  rules                            list detection rules
  hook                             make shell history update instantly
  add <file> | addroot <dir>       remember an extra log file / clean folder
  help | quit"""


def cmd_sources(det, a):
    sources, notes = discover()
    for s in sources:
        extra = ""
        if s.path:
            try:
                extra = f"{human(os.path.getsize(s.path))}, modified {time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(s.path)))}"
            except OSError:
                pass
        print(f"  {s.kind:<8} {s.label:<18} {extra}")
    for n in notes:
        print(paint("  ! " + n, "93"))
    if not sources:
        print("  No sources found.")


def cmd_scan(det, a):
    files = a.file or []
    sources, notes = discover(files, only_files=bool(files), with_journal=not a.no_journal)
    for n in notes:
        print(paint("! " + n, "93"))
    if not sources:
        print("Nothing to scan.")
        return
    events, per_source, cutoff = do_scan(det, sources, a.hours)
    print_scan(events, per_source, a.hours, cutoff)


def cmd_watch(det, a):
    files = a.file or []
    sources, notes = discover(files, only_files=bool(files), with_cmds=not a.no_cmds)
    for n in notes:
        print(paint("! " + n, "93"))
    do_watch(det, sources, a.all, a.notify, a.duration)


def cmd_check(det, a):
    do_check(det, " ".join(a.text))


def cmd_clean(det, a):
    do_clean(a.days, a.apply, a.yes, a.archive, a.system, a.root)


def cmd_stats(det, a):
    print(f"Lines examined this session: {det.lines}")
    print(f"Alerts: {det.by_sev['HIGH']} high, {det.by_sev['MED']} medium, {det.by_sev['LOW']} low")
    for rule, n in det.by_rule.most_common(8):
        print(f"  {n:>5}  {rule}")
    if det.ips:
        print("Top suspicious IPs: " + ", ".join(f"{ip} ({n})" for ip, n in det.ips.most_common(5)))


def cmd_rules(det, a):
    for title, rules in (("Log rules", LOG_RULES), ("Command rules", CMD_RULES)):
        print(paint(title, "1"))
        for name, sev, _, _ in sorted(rules, key=lambda r: SEV_ORDER[r[1]]):
            print(f"  {sev_tag(sev)} {name}")
    print(f"  {sev_tag('HIGH')} Recursive delete of a system or home directory")
    print(f"  {sev_tag('HIGH')} Brute-force burst / Username spraying (behavioral)")


def cmd_hook(det, a):
    print("Shells only save history when they exit, so live command watching lags. Add one of these:\n")
    print("  bash (~/.bashrc):   shopt -s histappend; PROMPT_COMMAND='history -a'")
    print("  zsh  (~/.zshrc):    setopt INC_APPEND_HISTORY")
    print("  fish:               nothing needed, it writes immediately\n")
    print("Then open a new terminal. `watch` will flag risky commands the moment you press Enter.")


def cmd_add(det, a):
    cfg = load_config()
    p = os.path.abspath(os.path.expanduser(a.path))
    key = "files" if a.what == "file" else "roots"
    if (a.what == "file" and not os.path.isfile(p)) or (a.what == "dir" and not os.path.isdir(p)):
        print(paint(f"{p} does not exist.", "91"))
        return
    if p not in cfg[key]:
        cfg[key].append(p)
        save_config(cfg)
    print(f"Saved. {len(cfg[key])} extra {key}: {', '.join(tilde(x) for x in cfg[key])}")


def build_parser():
    p = argparse.ArgumentParser(prog="logwatch", description="Live log and command watcher")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan recent logs")
    s.add_argument("--hours", type=float, default=24)
    s.add_argument("--file", action="append", help="scan only this file (repeatable)")
    s.add_argument("--no-journal", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("watch", help="live tail with alerts")
    s.add_argument("--file", action="append", help="watch only this file (repeatable)")
    s.add_argument("--all", action="store_true", help="also print non-alert lines")
    s.add_argument("--notify", action="store_true", help="bell + desktop notification on HIGH")
    s.add_argument("--no-cmds", action="store_true", help="do not watch shell history")
    s.add_argument("--duration", type=float, help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("check", help="analyze a command line without running it")
    s.add_argument("text", nargs="+")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("clean", help="delete old logs (dry-run unless --apply)")
    s.add_argument("--days", type=float, default=7)
    s.add_argument("--apply", action="store_true", help="actually delete")
    s.add_argument("--yes", action="store_true", help="skip the confirmation prompt (for cron)")
    s.add_argument("--archive", action="store_true", help="keep gzip copies in ~/.logwatch/archive")
    s.add_argument("--system", action="store_true", help="also rotated logs in /var/log + journal (needs sudo)")
    s.add_argument("--root", action="append", help="clean only this folder (repeatable)")
    s.set_defaults(fn=cmd_clean)

    for name, fn, hlp in (("sources", cmd_sources, "list log sources"), ("stats", cmd_stats, "session totals"),
                          ("rules", cmd_rules, "list detection rules"), ("hook", cmd_hook, "live shell history")):
        sub.add_parser(name, help=hlp).set_defaults(fn=fn)

    s = sub.add_parser("add", help="remember an extra log file")
    s.add_argument("path")
    s.set_defaults(fn=cmd_add, what="file")
    s = sub.add_parser("addroot", help="remember an extra folder for clean")
    s.add_argument("path")
    s.set_defaults(fn=cmd_add, what="dir")
    return p


def interactive(det, parser):
    print(paint("logwatch", "1") + "  live log + command watcher.  Type 'help'. Ctrl+C stops a live watch.")
    sources, notes = discover()
    print(f"Reading: {', '.join(s.label for s in sources) or 'nothing yet'}")
    for n in notes:
        print(paint("! " + n, "93"))
    while True:
        try:
            line = input(paint("log> ", "92") if TTY else "log> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        word = line.split(None, 1)[0]
        if word in ("quit", "exit", "q"):
            break
        if word == "help":
            print(HELP)
            continue
        try:
            if word == "check":
                do_check(det, line[len("check"):])
                continue
            args = parser.parse_args(shlex.split(line))
        except SystemExit:
            continue
        except ValueError as e:
            print(f"Parse error: {e}")
            continue
        if not getattr(args, "fn", None):
            print(HELP)
            continue
        try:
            args.fn(det, args)
        except KeyboardInterrupt:
            print()
        except (OSError, subprocess.SubprocessError) as e:
            print(paint(f"Error: {e}", "91"))


def main():
    parser = build_parser()
    args = parser.parse_args()
    det = Detector()
    if not args.cmd:
        interactive(det, parser)
        return
    args.fn(det, args)


if __name__ == "__main__":
    main()
