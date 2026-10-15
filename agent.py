"""ScamShield local agent: watches your clipboard and/or an email inbox and warns you about scams.
Everything runs on THIS device. Nothing is sent anywhere. Reuses the same ML + rules + URL engine as the web app.

  python agent.py                          hotkey + automatic notification checking (Windows, default)
  python agent.py --notifications          check every incoming Windows notification
  python agent.py --hotkey                 highlight text anywhere and press Ctrl+Alt+K (default mode)
  python agent.py --screen                 read the active window (OCR) so ANY app is checked, even when it is open in front
  python agent.py --clipboard              copy any message (WhatsApp Web, SMS mirror, Telegram...) to check it
  python agent.py --email                  watch your inbox (set IMAP_USER and IMAP_PASS first)
  python agent.py --clipboard --email      both
Suspicious items are saved to cases.db, so they show up in the web app's History and Dashboard.
"""
import argparse, difflib, email, html, imaplib, json, os, re, sys, threading, time
from collections import Counter, deque
from email import policy
from pathlib import Path
import shutil, sqlite3, tempfile
import app  # same engine as the web app, no server needed

DEBUG = False
SERVER, SERVER_KEY = "", ""

def push(payload):
    """Optional: send ONLY flagged results (short snippet, score, reasons) to a dashboard server. Analysis itself stays on this device."""
    if not SERVER: return
    def go():
        try:
            import urllib.request
            rq = urllib.request.Request(SERVER.rstrip("/") + "/api/ingest", json.dumps(payload).encode(), {"Content-Type": "application/json", "x-key": SERVER_KEY})
            urllib.request.urlopen(rq, timeout=8).read()
        except Exception as e: print("Dashboard push failed:", e)
    threading.Thread(target=go, daemon=True).start()
LEVELS = ["Safe", "Low", "Medium", "High", "Critical"]

VERDICT = {"Low": "slightly suspicious", "Medium": "suspicious", "High": "likely malicious", "Critical": "almost certainly malicious"}
def meter(score):
    n = round(score / 10); return "█" * n + "░" * (10 - n)

_toast = (set(), 0.0)
def notify(title, msg):
    global _toast
    _toast = (set(re.findall(r"\w+", (title + " " + msg).lower())), time.time())  # lets the screen reader ignore our own popup
    print(f"\a[ALERT] {title} | {msg.splitlines()[0] if msg else ''}")
    try:
        from winotify import Notification
        Notification(app_id="ScamShield", title=title, msg=msg[:250], duration="long").show()
    except Exception:
        try:
            from plyer import notification
            notification.notify(title=title, message=msg[:250], app_name="ScamShield", timeout=12)
        except Exception: pass

_last = ("", 0.0)
def handle(text, source, min_level, always=False, app_name=""):
    global _last
    if text == _last[0] and time.time() - _last[1] < 5: return None  # avoid double alerts
    _last = (text, time.time())
    res = app.analyze(text)
    print(f"[{source}] {res['level']} ({res['score']}) {text[:60]!r}")
    if res["level"] == "Safe":  # privacy: safe items are never stored
        if always: notify("ScamShield: looks safe", f"No strong scam indicators ({res['score']}/100). Stay cautious with unexpected requests.")
        return res
    st = (res["scam_type"] or {}).get("name", "")
    with app.db() as c:
        c.execute("INSERT INTO cases(ts,type,text,score,level,factors,urls,stype) VALUES(?,?,?,?,?,?,?,?)",
                  (time.strftime("%Y-%m-%d %H:%M:%S"), source, (f"[{app_name}] {text}" if app_name else text)[:300], res["score"], res["level"],
                   json.dumps(res["factors"]), json.dumps([u["domain"] for u in res["urls"]]), st))
    push({"type": source, "text": (f"[{app_name}] " if app_name else "") + text[:160], "score": res["score"], "level": res["level"],
          "factors": res["factors"][:4], "domains": [u["domain"] for u in res["urls"]], "scam_type": st})
    if LEVELS.index(res["level"]) >= LEVELS.index(min_level):
        why = "; ".join(f["label"] for f in res["factors"][:2])
        notify(f"ScamShield{' · ' + app_name if app_name else ''}: {res['level']} risk",
               f"{meter(res['score'])} {res['score']}% unsafe, {VERDICT[res['level']]}\n{st or 'Suspicious message'}. {why}\n{app.NEXT[res['level']]}")
    return res

def email_text(raw):
    m = email.message_from_bytes(raw, policy=policy.default)
    head = f"From: {m.get('From', '')}\n" + (f"Reply-To: {m['Reply-To']}\n" if m.get("Reply-To") else "") + f"Subject: {m.get('Subject', '')}\n\n"
    part, body = m.get_body(preferencelist=("plain", "html")), ""
    if part:
        body = part.get_content()
        if part.get_content_type() == "text/html":
            links = re.findall(r"href=[\"'](https?://[^\"']+)", body)
            body = html.unescape(re.sub(r"<[^>]+>", " ", body)) + "\n" + "\n".join(links)
    return head + body

def hotkey_check(min_level):
    import pyperclip
    from pynput.keyboard import Controller, Key
    k = Controller(); time.sleep(0.35)
    for m in (Key.shift, Key.alt, Key.ctrl): k.release(m)  # let go of the hotkey modifiers
    pyperclip.copy("")
    with k.pressed(Key.ctrl): k.press("c"); k.release("c")  # copy the highlighted text
    time.sleep(0.25)
    t = pyperclip.paste().strip()
    if len(t) < 5: return notify("ScamShield", "Nothing selected. Highlight a message first, then press the hotkey.")
    handle(t, "agent-hotkey", min_level, always=True)

def start_hotkey(min_level, combo):
    from pynput import keyboard
    keyboard.GlobalHotKeys({combo: lambda: threading.Thread(target=hotkey_check, args=(min_level,), daemon=True).start()}).start()
    print(f"Hotkey active: highlight a message in any app and press {combo}")

WPN = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "Notifications" / "wpndatabase.db"
SKIP_APPS = ("Windows.SystemToast", "SecHealthUI", "Microsoft.Windows.", "ScamShield", "python")

def app_label(pid):
    return (re.split(r"[_!]", pid or "")[0].split(".")[-1] or "App")

def read_new_notifications(db_path, last_id):
    """Reads toast notifications newer than last_id from a COPY of Windows' notification database."""
    tmp = Path(tempfile.mkdtemp()); items = []
    try:
        for ext in ("", "-wal"):
            f = Path(str(db_path) + ext)
            if f.exists(): shutil.copyfile(f, tmp / ("w.db" + ext))
        c = sqlite3.connect(tmp / "w.db")
        rows = c.execute("SELECT n.Id, n.Payload, h.PrimaryId FROM Notification n LEFT JOIN NotificationHandler h "
                         "ON h.RecordId = n.HandlerId WHERE n.Type='toast' AND n.Id > ? ORDER BY n.Id", (last_id,)).fetchall()
        mx = c.execute("SELECT COALESCE(MAX(Id), 0) FROM Notification").fetchone()[0]; c.close()
    finally: shutil.rmtree(tmp, ignore_errors=True)
    for i, payload, pid in rows:
        raw = payload if isinstance(payload, str) else (payload or b"")
        if isinstance(raw, bytes):
            try: raw = raw.decode("utf-8")
            except UnicodeDecodeError: raw = raw.decode("utf-16", errors="ignore")
        texts = [html.unescape(t).strip() for t in re.findall(r"<text[^>]*>(.*?)</text>", raw, re.S)]
        texts = [t for t in texts if t]
        if texts: items.append((i, pid or "", texts[0], " ".join(texts[1:])))
    return max(mx, last_id), items

def watch_notifications(min_level, every=3, db_path=WPN):
    if os.name != "nt" or not Path(db_path).exists():
        return print("Notification watcher needs Windows 10/11 (notification database not found).")
    last, _ = read_new_notifications(db_path, 0)  # start from now, ignore old notifications
    print("Watching Windows notifications (WhatsApp, Chrome, Phone Link, mail apps...).")
    while True:
        try:
            last, items = read_new_notifications(db_path, last)
            for _, pid, title, body in items:
                if any(x.lower() in pid.lower() for x in SKIP_APPS) or title.startswith("ScamShield"): continue
                text = title + "\n" + body
                if len(text.strip()) >= 12: handle(text, "agent-notification", min_level, app_name=app_label(pid))
        except Exception as e: print("Notification read failed:", e)
        time.sleep(every)


# ---------- screen watcher: reads the text of the ACTIVE window (OCR), so any app is checked even while it is open in front ----------
SCREEN_SKIP = ("scamshield", "phishguard", "cmd.exe", "command prompt", "powershell", "windows terminal", "python.exe")

def win_key(title): return re.sub(r"\d+", "", title).strip().lower()   # "(2) WhatsApp" and "(3) WhatsApp" are the same window
def _norm(s): return re.sub(r"[^\w\u0900-\u0DFF]+", "", s.lower())   # keeps Hindi/Indic vowel signs

class ScreenState:
    """Per window: remembers the most times each line was on screen AT ONCE, so scrolling old lines back into view is ignored,
    but the same message arriving again (a second identical scam text) still counts as new."""
    def __init__(self): self.maxc = {}
    def _key(self, keys, n):
        if n in keys: return n
        if len(n) >= 12:
            d = re.findall(r"\d{2,}", n)   # different amounts/OTPs/numbers mean a different message (single digits are often OCR slips)
            for c in keys:
                if abs(len(c) - len(n)) <= max(3, len(n) // 8) and re.findall(r"\d{2,}", c) == d and difflib.SequenceMatcher(None, n, c).ratio() >= 0.88: return c
        return n
    def new_lines(self, title, lines):
        k = win_key(title); first = k not in self.maxc
        mc = self.maxc.setdefault(k, {})
        tw, tt = _toast; own = time.time() - tt < 20
        cur, text_of = Counter(), {}
        for ln in lines:
            ln = ln.strip(); n = _norm(ln)
            if len(n) < 4: continue
            key = self._key(mc, n); cur[key] += 1; text_of.setdefault((key, cur[key]), ln)
        out = []
        for key, c in cur.items():
            for i in range(mc.get(key, 0) + 1, c + 1):
                ln = text_of[(key, i)]; words = re.findall(r"\w+", ln.lower())
                if own and words and sum(w in tw for w in words) / len(words) >= 0.7: continue   # that is our own popup
                out.append(ln)
            mc[key] = max(mc.get(key, 0), c)
        while len(mc) > 800: mc.pop(next(iter(mc)))
        return [] if first else out   # first look at a window is only a baseline

def screen_step(st, title, lines, min_level):
    new = st.new_lines(title, lines); text = "\n".join(new)
    if DEBUG: print(f"[screen] {len(lines)} lines read, {len(new)} new: {text[:70]!r}")
    if not new or len(new) > 12 or len(text) < 20 or len(text.split()) < 4: return None  # >12 new lines = scroll / page change
    handle(text[:600], "agent-screen", min_level, app_name=title[:30])
    return text

def make_ocr(lang):
    langs = [l.strip() for l in str(lang).split(",") if l.strip()] or ["en"]
    try:
        import winocr   # Windows' built-in offline OCR: one language per pass, results are merged
        bad = set()
        def run(img):
            out = []
            for l in langs:
                if l in bad: continue
                try: r = winocr.recognize_pil_sync(img, l)
                except Exception as e:
                    bad.add(l); print(f"OCR language '{l}' unavailable. Add that Windows language pack with 'optical character recognition': {e}"); continue
                ls = r["lines"] if isinstance(r, dict) else r.lines
                out += [(x["text"] if isinstance(x, dict) else x.text) for x in ls]
            return out
        print("Screen OCR: Windows built-in OCR, languages:", ", ".join(langs)); return run
    except Exception:
        try:
            from rapidocr_onnxruntime import RapidOCR
            import numpy as np
            eng = RapidOCR()
            def run(img):
                res, _ = eng(np.array(img.convert("RGB")))
                return [r[1] for r in sorted(res or [], key=lambda r: (round(r[0][0][1] / 12), r[0][0][0]))]
            print("Screen OCR: RapidOCR"); return run
        except Exception:
            print("Screen watcher needs an OCR engine. Run:  pip install winocr pillow   (or: pip install rapidocr-onnxruntime pillow)")

def foreground_window():
    import ctypes, ctypes.wintypes
    u = ctypes.windll.user32; h = u.GetForegroundWindow()
    if not h or u.IsIconic(h): return None
    n = u.GetWindowTextLengthW(h); buf = ctypes.create_unicode_buffer(n + 1); u.GetWindowTextW(h, buf, n + 1)
    r = ctypes.wintypes.RECT(); u.GetWindowRect(h, ctypes.byref(r))
    return buf.value, (r.left, r.top, r.right, r.bottom)

def watch_screen(min_level, every=3, lang="en"):
    if os.name != "nt": return print("Screen watcher needs Windows.")
    import ctypes
    try: ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try: ctypes.windll.user32.SetProcessDPIAware()
        except Exception: pass
    ocr = make_ocr(lang)
    if not ocr: return
    from PIL import ImageGrab
    st, prev, shown = ScreenState(), {}, set()
    print("Watching the active window on screen (any app, even when open in front). Everything stays on this device.")
    while True:
        try:
            w = foreground_window()
            if w and w[0].strip() and not any(x in w[0].lower() for x in SCREEN_SKIP):
                img = ImageGrab.grab(bbox=w[1], all_screens=True)
                small = img.convert("L").resize((192, 108)).tobytes(); k = win_key(w[0]); p, t0 = prev.get(k, (None, 0))
                changed = sum(abs(x - y) > 20 for x, y in zip(p, small)) if p else 10 ** 9
                if changed >= 10 or time.time() - t0 > 15:   # something changed (even a short message), or a periodic re-read
                    prev[k] = (small, time.time())
                    screen_step(st, w[0], ocr(img), min_level)
        except Exception as e:
            if str(e) not in shown: shown.add(str(e)); print("Screen read failed:", e)
        time.sleep(every)

def watch_clipboard(min_level):
    import pyperclip
    last = pyperclip.paste()
    print("Watching clipboard. Copy any message to check it. Ctrl+C to stop.")
    while True:
        try: cur = pyperclip.paste()
        except Exception: cur = last
        t = cur.strip()
        if cur != last and len(t) >= 12 and (" " in t or "http" in t):  # skips passwords/single tokens
            handle(t, "agent-clipboard", min_level)
        last = cur; time.sleep(1)

def watch_email(min_level, every):
    host, user, pw = os.getenv("IMAP_HOST", "imap.gmail.com"), os.getenv("IMAP_USER"), os.getenv("IMAP_PASS")
    if not (user and pw): sys.exit("Set IMAP_USER and IMAP_PASS first (use an app password, not your main password).")
    seen = set(); print(f"Watching inbox of {user} every {every}s (read-only; mail stays unread).")
    while True:
        try:
            M = imaplib.IMAP4_SSL(host); M.login(user, pw); M.select("INBOX", readonly=True)
            _, d = M.uid("search", None, "UNSEEN")
            for uid in d[0].split()[-20:]:
                if uid in seen: continue
                seen.add(uid)
                _, data = M.uid("fetch", uid, "(BODY.PEEK[])")
                handle(email_text(data[0][1]), "agent-email", min_level)
            M.logout()
        except Exception as e: print("Email check failed:", e)
        time.sleep(every)

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="ScamShield local agent")
    p.add_argument("--server", default="", help="dashboard URL to push flagged detections to, e.g. https://your-app.onrender.com"); p.add_argument("--ingest-key", default="", help="ingest key (must match INGEST_KEY on the server)")
    p.add_argument("--debug", action="store_true", help="print what the screen reader sees"); p.add_argument("--clipboard", action="store_true"); p.add_argument("--email", action="store_true")
    p.add_argument("--notifications", action="store_true", help="check every incoming Windows notification")
    p.add_argument("--hotkey", action="store_true", help="highlight text anywhere, press the hotkey to check it")
    p.add_argument("--screen", action="store_true", help="read the active window with OCR so any app is checked, even when open in front")
    p.add_argument("--screen-interval", type=int, default=3, help="seconds between screen checks")
    p.add_argument("--ocr-lang", default="en,hi", help="Windows OCR languages, comma separated, e.g. en,hi,mr,bn,ta,te (each needs its Windows language pack)")
    p.add_argument("--key", default="<ctrl>+<alt>+k", help="hotkey combo, pynput format")
    p.add_argument("--min-level", default="Medium", choices=LEVELS[1:], help="lowest level that triggers a popup")
    p.add_argument("--interval", type=int, default=60, help="email check interval in seconds")
    a = p.parse_args(); DEBUG = a.debug; SERVER, SERVER_KEY = a.server, a.ingest_key
    if not (a.clipboard or a.email or a.hotkey or a.notifications or a.screen): a.hotkey, a.notifications = True, os.name == "nt"
    try:
        if a.email: threading.Thread(target=watch_email, args=(a.min_level, a.interval), daemon=True).start()
        if a.notifications: threading.Thread(target=watch_notifications, args=(a.min_level,), daemon=True).start()
        if a.screen: threading.Thread(target=watch_screen, args=(a.min_level, a.screen_interval, a.ocr_lang), daemon=True).start()
        if a.hotkey: start_hotkey(a.min_level, a.key)
        if a.clipboard: watch_clipboard(a.min_level)
        else:
            while True: time.sleep(3600)
    except KeyboardInterrupt: print("Stopped.")