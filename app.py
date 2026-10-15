import re, json, sqlite3, difflib, time, socket, ipaddress
from collections import Counter
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse
import os
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tldextract

BASE = Path(__file__).parent
DB = BASE / "cases.db"
app = FastAPI(title="PhishGuard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
ext_ = tldextract.TLDExtract(suffix_list_urls=())  # bundled suffix list, works offline
F = lambda c, l, p: {"category": c, "label": l, "points": p}

BRANDS = {"sbi": "sbi", "hdfc": "hdfcbank", "icici": "icicibank", "paytm": "paytm", "amazon": "amazon",
          "flipkart": "flipkart", "paypal": "paypal", "google": "google", "microsoft": "microsoft",
          "netflix": "netflix", "apple": "apple", "fedex": "fedex", "irctc": "irctc", "phonepe": "phonepe"}
TRUSTED = {"com", "in", "co.in", "org", "net", "gov.in"}
BAD_TLDS = {"xyz", "top", "tk", "click", "icu", "buzz", "gq", "ml", "cf", "ga", "work", "rest", "site", "online"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd", "shorturl.at"}
LEET = str.maketrans("10534", "loset")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|rb\.gy|cutt\.ly|is\.gd)/\S+", re.I)

RULES = [  # (category, regex, points, explanation)
    ("urgency", r"\b(urgent(ly)?|immediately|within \d+ (hours?|hrs|minutes?)|expires?|expired|last chance|act now|suspended|blocked|disconnected?|today only)\b", 20, "Urgency / time-pressure language"),
    ("credentials", r"\b(kyc|verify your (account|identity|details)|update your (pan|aadhaar|account|details)|(share|send|enter|confirm) (your )?(otp|password|pin|cvv))\b", 22, "Asks for credentials, KYC or OTP"),
    ("reward", r"\b(you('ve| have)? won|lottery|congratulations|prize|cashback|reward|kbc|lucky draw)\b", 20, "Unrealistic reward / prize bait"),
    ("money", r"(processing fee|registration fee|send (rs\.?|₹)\s?\d|gift card|bitcoin|crypto|pay (the )?pending|\bupi\b.*\b(send|pay)\b|\b(send|pay)\b.*\bupi\b)", 15, "Requests money or payment"),
    ("threat", r"\b(legal action|arrest|police|penalty|fir\b|court notice|account (will be )?(closed|frozen))\b", 15, "Threat / fear tactic"),
    ("job", r"(part[- ]time job|work from home|earn (rs\.?|₹)\s?[\d,]+\s*(/|per) ?day|lik(e|ing) youtube( videos)?|telegram group)", 30, "Too-good-to-be-true job offer"),
    ("friend", r"(are you free\??|emergency|urgent(ly)? need (rs\.?|₹|money))", 12, "Emergency / friend-impersonation pattern"),
    ("parcel", r"(held at customs|customs (duty|fee|charges?)|(delivery|redelivery|release) fee|parcel (is )?(held|on hold)|package (is )?(held|on hold))", 15, "Parcel / courier fee demand"),
    ("generic", r"\b(dear (customer|user|sir/madam|account holder))\b", 6, "Generic greeting (mass-sent)"),
    ("urgency", r"(ghante me|ghante mein|band ho jayega|band ho jaega|turant|तुरंत|बंद हो जाएगा|घंटे में)", 20, "Urgency / time-pressure language (Hinglish/Hindi)"),
    ("reward", r"(badhai ho|jeeta hai|inaam|बधाई|इनाम|जीता)", 20, "Prize bait (Hinglish/Hindi)"),
    ("money", r"(bhejein|upi kar|transfer kar|shulk|भेजें|शुल्क|ट्रांसफर)", 15, "Requests money (Hinglish/Hindi)"),
]

# Indian-language scam cues: Hindi, Marathi, Bengali, Tamil, Telugu, Gujarati, Punjabi, Kannada, Malayalam, Urdu
_ML = {
 "urgency": (20, "Urgency / time-pressure language (Indian languages)", ["तुरंत", "तत्काल", "आत्ताच", "तात्काळ", "ब्लॉक हो", "बंद हो जाएगी", "बंद होणार", "कट जाएगा", "निलंबित", "ঘণ্টার মধ্যে", "এখনই", "অবিলম্বে", "ব্লক হয়ে", "உடனே", "உடனடியாக", "முடக்கப்படும்", "వెంటనే", "బ్లాక్ అవుతుంది", "તરત", "હમણાં જ", "ਤੁਰੰਤ", "ತಕ್ಷಣ", "ഉടൻ", "فوری", "فوراً", "بلاک"]),
 "credentials": (22, "Asks for credentials, KYC or OTP (Indian languages)", ["केवाईसी", "ओटीपी", "पैन कार्ड", "आधार", "सत्यापित", "अपडेट करें", "अपडेट करा", "কেওয়াইসি", "ওটিপি", "আপডেট করুন", "கேஒய்சி", "புதுப்பிக்கவும்", "ఓటీపీ", "అప్డేట్ చేయండి", "ઓટીપી", "અપડેટ કરો", "ਓਟੀਪੀ", "ಅಪ್‌ಡೇಟ್", "ഒടിപി", "അപ്ഡേറ്റ്", "اپ ڈیٹ", "او ٹی پی"]),
 "reward": (20, "Unrealistic reward / prize bait (Indian languages)", ["लॉटरी", "अभिनंदन", "बक्षीस", "লটারি", "পুরস্কার", "অভিনন্দন", "லாட்டரி", "பரிசு", "வாழ்த்துக்கள்", "లాటరీ", "బహుమతి", "అభినందనలు", "લોટરી", "ઇનામ", "ਲਾਟਰੀ", "ਇਨਾਮ", "ਵਧਾਈ", "ಲಾಟರಿ", "ಬಹುಮಾನ", "ലോട്ടറി", "സമ്മാനം", "لاٹری", "انعام", "مبارک"]),
 "money": (15, "Requests money or payment (Indian languages)", ["रुपये भेजें", "पैसे भेजें", "पाठवा", "টাকা পাঠান", "পাঠান", "அனுப்பவும்", "கட்டணம்", "పంపండి", "రుసుము", "મોકલો", "ਭੇਜੋ", "ਫੀਸ", "ಕಳುಹಿಸಿ", "ಶುಲ್ಕ", "അയയ്ക്കുക", "ഫീസ്", "بھیجیں", "فیس"]),
 "threat": (15, "Threat / fear tactic (Indian languages)", ["गिरफ्तार", "पुलिस", "जुर्माना", "कानूनी कार्रवाई", "अटक", "গ্রেপ্তার", "জরিমানা", "கைது", "அபராதம்", "అరెస్ట్", "జరిమానా", "ધરપકડ", "ਗ੍ਰਿਫਤਾਰ", "ಬಂಧನ", "അറസ്റ്റ്", "گرفتار"]),
}
RULES.append(("credentials", r"((ओटीपी|पिन|सीवीवी|पासवर्ड).{0,30}(साझा करें|शेयर करें|बताएं|बताइए|भेज दें)|(साझा करें|शेयर करें|बताएं|बताइए).{0,30}(ओटीपी|पिन|सीवीवी))", 25, "Asks you to share OTP/PIN (Hindi)"))
for _c, (_p, _l, _w) in _ML.items(): RULES.append((_c, "(" + "|".join(map(re.escape, _w)) + ")", _p, _l))

_SCRIPTS = [("Devanagari (Hindi/Marathi)", 0x900, 0x97F), ("Bengali", 0x980, 0x9FF), ("Gurmukhi (Punjabi)", 0xA00, 0xA7F), ("Gujarati", 0xA80, 0xAFF),
            ("Tamil", 0xB80, 0xBFF), ("Telugu", 0xC00, 0xC7F), ("Kannada", 0xC80, 0xCFF), ("Malayalam", 0xD00, 0xD7F), ("Urdu/Arabic", 0x600, 0x6FF)]
def detect_lang(text):
    best, n = "Latin (English/Hinglish)", sum(c.isascii() and c.isalpha() for c in text)
    for name, lo, hi in _SCRIPTS:
        c = sum(lo <= ord(ch) <= hi for ch in text)
        if c > n: best, n = name, c
    return best

MODEL = None
def mask(t):
    """Hide URLs and numbers so the ML learns wording only (URLs are scored by the URL engine)."""
    return re.sub(r"\d+", "0", re.sub(r"(?:https?://|www\.)\S+|\b(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|is\.gd)/\S+", " URL ", t))

def load_model():
    """Trains on data/seed.csv + data/train.csv (any column order; columns named text,label or label,text)."""
    global MODEL
    try:
        import pandas as pd
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline, make_union
        parts = []
        for n in ("seed.csv", "train.csv"):
            f = BASE / "data" / n
            if not f.exists(): continue
            d = pd.read_csv(f, encoding="utf-8", encoding_errors="replace")
            if {"text", "label"} <= set(d.columns): d = d[["label", "text"]]
            else: d = d.iloc[:, :2]; d.columns = ["label", "text"]
            parts.append(d)
        d = pd.concat(parts).dropna()
        y = d.label.astype(str).str.lower().isin(["spam", "1", "phishing", "scam"])
        vec = make_union(TfidfVectorizer(token_pattern=r"(?u)[\w\u0900-\u0DFF\u200c\u200d]+", ngram_range=(1, 2), sublinear_tf=True),  # keeps Hindi/Indic vowel signs inside words
                         TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True, min_df=2))  # works for any script, typos, Hinglish
        MODEL = make_pipeline(vec,
                              LogisticRegression(max_iter=1000, class_weight="balanced", C=3)).fit(d.text.astype(str).map(mask), y)
        print("ML model trained on", len(d), "rows")
    except Exception as e:
        print("ML model skipped:", e)
load_model()

def domain_age_days(domain):
    try:
        import whois
        c = whois.whois(domain).creation_date
        c = c[0] if isinstance(c, list) else c
        return (time.time() - c.timestamp()) / 86400
    except Exception:
        return None

def _public(host):
    try: return all(ipaddress.ip_address(a[4][0]).is_global for a in socket.getaddrinfo(host, None))
    except Exception: return False

def unmask(url, hops=5):
    """Follow redirects safely (public hosts only, no body download) and return the chain."""
    chain = [url]
    try:
        import httpx
        with httpx.Client(timeout=4, follow_redirects=False, headers={"User-Agent": "Mozilla/5.0"}) as c:
            for _ in range(hops):
                if not _public(urlparse(chain[-1]).hostname or ""): break
                with c.stream("GET", chain[-1]) as r:
                    loc = r.headers.get("location")
                    if r.status_code in (301, 302, 303, 307, 308) and loc: chain.append(str(httpx.URL(chain[-1]).join(loc)))
                    else: break
    except Exception: pass
    return chain

def analyze_url(u, deep=False):
    f = []
    url = u if u.lower().startswith("http") else "http://" + u
    p = urlparse(url); host = (p.hostname or "").lower(); e = ext_(host)
    raw, norm = e.domain, e.domain.translate(LEET)
    if p.scheme != "https": f.append(F("url", "Link does not use HTTPS", 8))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): f.append(F("url", "Uses a raw IP address instead of a domain", 25))
    if "@" in p.netloc: f.append(F("url", "Contains '@' trick that hides the real destination", 25))
    if e.registered_domain in SHORTENERS: f.append(F("url", f"URL shortener ({e.registered_domain}) hides the destination", 15))
    if e.suffix in BAD_TLDS: f.append(F("url", f"Frequently abused TLD (.{e.suffix})", 10))
    if host.startswith("xn--") or ".xn--" in host: f.append(F("url", "Punycode (possible look-alike characters)", 20))
    if e.subdomain.count(".") >= 2: f.append(F("url", "Excessive subdomains", 10))
    if raw.count("-") >= 2: f.append(F("url", "Many hyphens in domain", 8))
    if len(url) > 75: f.append(F("url", "Unusually long URL", 5))
    if re.search(r"(login|verify|secure|update|kyc|account)", p.path.lower()) and e.registered_domain not in SHORTENERS:
        f.append(F("url", "Sensitive keyword in URL path", 6))
    genuine = any(raw == off and e.suffix in TRUSTED for off in BRANDS.values())
    if not genuine:
        for k, off in BRANDS.items():
            if norm == off and raw != off: f.append(F("url", f"Look-alike of '{off}' using character swaps", 35)); break
            elif k in norm and k not in raw: f.append(F("url", f"Look-alike of brand '{k}' using character swaps (e.g. 1 for l)", 35)); break
            elif k in raw or k in e.subdomain: f.append(F("url", f"Uses brand '{k}' in a domain the brand doesn't own", 32)); break
            elif raw != off and difflib.SequenceMatcher(None, raw, off).ratio() >= 0.85: f.append(F("url", f"Typosquat of '{off}'", 30)); break
    meta = {}
    if deep and e.registered_domain:
        age = domain_age_days(e.registered_domain)
        if age is not None:
            meta["domain_age_days"] = int(age)
            if age < 30: f.append(F("metadata", f"Domain registered only {int(age)} days ago", 30))
            elif age < 180: f.append(F("metadata", f"Young domain ({int(age)} days old)", 15))
    if deep and host:
        ch = unmask(url)
        if len(ch) > 1:
            meta["chain"] = ch
            if ext_(urlparse(ch[-1]).hostname or "").registered_domain != e.registered_domain:
                fin = analyze_url(ch[-1], False)
                f.append(F("redirect", f"Redirects to {fin['domain']}", 12 + min(25, sum(x["points"] for x in fin["factors"]) // 2)))
    return {"url": u, "domain": e.registered_domain or host, "label": raw, "factors": f, "meta": meta}

def check_headers(msg):
    f = []; name, addr = parseaddr(msg.get("From", "")); d = ext_(addr.split("@")[-1])
    for k, off in BRANDS.items():
        if k in name.lower() and d.domain != off:
            f.append(F("header", f"Sender name says '{name}' but address is from {d.registered_domain}", 30)); break
    _, ra = parseaddr(msg.get("Reply-To", ""))
    if ra and ext_(ra.split("@")[-1]).registered_domain != d.registered_domain:
        f.append(F("header", "Reply-To domain differs from sender domain", 15))
    return f

SCAM_TYPES = [  # name, Hindi name, regex, tip, Hindi tip
 ("Bank / KYC phishing", "बैंक / KYC फ़िशिंग", r"kyc|verify your|\botp\b|\bpin\b|bank|net ?banking|account (is )?(blocked|suspended)", "Banks never ask for OTP, PIN or KYC through links or SMS. Call the number printed on your card.", "बैंक कभी लिंक या SMS पर OTP, PIN, KYC नहीं मांगता। कार्ड पर छपे नंबर पर कॉल करें।"),
 ("Lottery / prize scam", "लॉटरी / इनाम ठगी", r"lottery|prize|\bwon\b|kbc|cashback|reward|lucky", "You cannot win a contest you never entered, and real prizes never need a fee.", "जिस प्रतियोगिता में भाग नहीं लिया उसमें इनाम नहीं मिलता, और असली इनाम के लिए फीस नहीं लगती।"),
 ("Utility disconnection scam", "बिजली / बिल ठगी", r"electricity|disconnect|power cut|\bgas\b|water|\bbill\b", "Check dues only in the official provider app or website, never via the number in the message.", "बिल सिर्फ आधिकारिक ऐप/वेबसाइट पर जांचें, मैसेज में दिए नंबर पर नहीं।"),
 ("Parcel / courier scam", "पार्सल / कूरियर ठगी", r"parcel|courier|customs|delivery fee|package|fedex|india post", "Track parcels only on the courier's official site. Never pay a 'release fee' from a message.", "पार्सल सिर्फ कूरियर की आधिकारिक साइट पर ट्रैक करें। मैसेज से 'रिलीज़ फीस' न दें।"),
 ("Fake job / task scam", "फ़र्ज़ी जॉब / टास्क ठगी", r"\bjob\b|work from home|earn|telegram|youtube", "Genuine employers never charge you or pay for liking videos. Do not join the group.", "असली कंपनियां पैसे नहीं मांगतीं और वीडियो लाइक करने के पैसे नहीं देतीं। ग्रुप से न जुड़ें।"),
 ("Friend-in-need impersonation", "दोस्त बनकर ठगी", r"are you free|emergency|send on this upi|need (money|rs|₹)", "Call the person on their known number to confirm before sending any money.", "पैसे भेजने से पहले उस व्यक्ति को उसके पुराने नंबर पर कॉल करके पुष्टि करें।"),
 ("Tax-refund / government scam", "टैक्स / सरकारी ठगी", r"income tax|refund|aadhaar|pan card|police|arrest|court", "Government departments never demand payment or details over SMS, WhatsApp or calls.", "सरकारी विभाग SMS, WhatsApp या कॉल पर पैसे या जानकारी नहीं मांगते।"),
]
def classify(text, score, has_url):
    if score < 15: return None
    best, n = None, 0
    for name, hi, pat, tip, tip_hi in SCAM_TYPES:
        c = len(re.findall(pat, text))
        if c > n: best, n = {"name": name, "hi": hi, "tip": tip, "tip_hi": tip_hi}, c
    if not best and (has_url or score >= 35):
        best = {"name": "Suspicious link / phishing", "hi": "संदिग्ध लिंक / फ़िशिंग", "tip": "Do not open the link. Type the official site address yourself instead.", "tip_hi": "लिंक न खोलें। आधिकारिक साइट का पता खुद टाइप करें।"}
    return best

LEVELS = [(15, "Safe"), (35, "Low"), (60, "Medium"), (80, "High"), (101, "Critical")]
WARN = {"Safe": "No strong scam indicators found. Stay cautious with unexpected requests.",
        "Low": "A few minor warning signs. Double-check the sender before acting.",
        "Medium": "Suspicious. Do not click links or share details until you verify through an official channel.",
        "High": "Likely a scam. Do NOT click links, reply, or share OTP/PIN/payment details.",
        "Critical": "Almost certainly phishing/scam. Do not interact. Report it (cybercrime.gov.in / 1930) and delete."}

def analyze(text, deep=False):
    msg, body = None, text
    if re.match(r"\s*(from|subject|reply-to|to|date):", text, re.I):
        msg = Parser().parsestr(text.strip())
        body = msg.get("subject", "") + "\n" + (msg.get_payload() if not msg.is_multipart() else "")
    factors, spans = [], []
    if msg: factors += check_headers(msg)
    cats = set()
    for cat, pat, pts, label in RULES:
        ms = [m.group(0) for m in re.finditer(pat, body, re.I)]
        if ms:
            extra = min(10, 5 * (len({m.lower() for m in ms}) - 1))  # several different phrases of the same tactic
            factors.append(F(cat, label, pts + extra)); spans += ms; cats.add(cat)
    cats.discard("generic")
    if len(cats) >= 2:  # several different scam signals together is far stronger evidence than one
        factors.append(F("combo", f"{len(cats)} different scam tactics combined in one message", min(24, 12 * (len(cats) - 1))))
    urls = [analyze_url(u.rstrip(".,);"), deep) for u in dict.fromkeys(URL_RE.findall(text))]
    for u in urls: factors += u["factors"]
    low = body.lower()
    for k, off in BRANDS.items():
        if re.search(rf"\b{k}\b", low) and urls and not any(u["label"] == off for u in urls):
            factors.append(F("impersonation", f"Mentions '{k.upper()}' but links point elsewhere", 25)); spans.append(k); break
    if MODEL and len(body.strip()) > 10:
        pr = float(MODEL.predict_proba([mask(body)])[0][1])
        if pr > 0.55: factors.append(F("ml", f"ML classifier: {int(pr*100)}% scam-like wording", int(pr * 30)))
    score = min(100, sum(x["points"] for x in factors))
    level = next(n for t, n in LEVELS if score < t)
    kind = "email" if msg else ("url" if urls and len(text.split()) == 1 else "message")
    return {"type": kind, "score": score, "level": level, "warning": WARN[level],
            "factors": sorted(factors, key=lambda x: -x["points"]), "highlights": list(dict.fromkeys(spans)), "urls": urls,
            "lang": detect_lang(text), "scam_type": classify(low + " " + " ".join(u["url"].lower() for u in urls), score, bool(urls))}

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, ts TEXT, type TEXT, text TEXT, score INT, level TEXT, factors TEXT, urls TEXT, stype TEXT)")
    try: c.execute("ALTER TABLE cases ADD COLUMN stype TEXT")
    except sqlite3.OperationalError: pass
    return c

class Req(BaseModel):
    text: str
    deep: bool = False

@app.post("/api/analyze")
def api_analyze(r: Req):
    res = analyze(r.text, r.deep)
    with db() as c:
        cur = c.execute("INSERT INTO cases(ts,type,text,score,level,factors,urls,stype) VALUES(?,?,?,?,?,?,?,?)",
                        (time.strftime("%Y-%m-%d %H:%M:%S"), res["type"], r.text[:1000], res["score"], res["level"],
                         json.dumps(res["factors"]), json.dumps([u["domain"] for u in res["urls"]]), (res["scam_type"] or {}).get("name", "")))
    return {**res, "id": cur.lastrowid}

@app.get("/api/check")  # lightweight endpoint for a future browser extension
def api_check(url: str):
    r = analyze(url); return {"level": r["level"], "score": r["score"], "warning": r["warning"]}

@app.get("/api/history")
def history(q: str = "", level: str = ""):
    sql, a = "SELECT * FROM cases WHERE 1=1", []
    if q: sql += " AND (text LIKE ? OR urls LIKE ?)"; a += [f"%{q}%"] * 2
    if level: sql += " AND level=?"; a.append(level)
    with db() as c:
        rows = c.execute(sql + " ORDER BY id DESC LIMIT 200", a).fetchall()
    return [{**dict(r), "factors": json.loads(r["factors"]), "urls": json.loads(r["urls"])} for r in rows]

@app.get("/api/stats")
def stats():
    with db() as c: rows = c.execute("SELECT ts,level,urls,type,stype FROM cases").fetchall()
    alld = Counter(d for r in rows if r["level"] != "Safe" for d in json.loads(r["urls"]))
    doms = Counter(d for r in rows if r["level"] in ("Medium", "High", "Critical") for d in json.loads(r["urls"]))
    return {"total": len(rows), "levels": Counter(r["level"] for r in rows), "types": Counter(r["type"] for r in rows),
            "daily": sorted(Counter(r["ts"][:10] for r in rows).items())[-7:], "top_domains": doms.most_common(5),
            "scam_types": Counter(r["stype"] for r in rows if r["stype"]).most_common(),
            "campaigns": [(d, n) for d, n in alld.most_common(5) if n >= 2]}

NEXT = {"Critical": "Delete it, block the sender, and report it (1930 / cybercrime.gov.in). Do not click or reply.",
        "High": "Do not click or reply. Block the sender and report it.",
        "Medium": "Verify through the official app, website or number on your card before acting.",
        "Low": "Double-check the sender before acting.",
        "Safe": "No action needed."}
TIPS = {t[0]: t[3] for t in SCAM_TYPES}

VERDICT = {"Safe": "Not malicious", "Low": "Probably safe", "Medium": "Suspicious",
           "High": "Malicious", "Critical": "Malicious"}
def verdict(res):
    """Plain-language answer: is it malicious, and how unsafe (0-100%)."""
    lvl = res["level"]
    return {"malicious": lvl in ("High", "Critical"), "suspicious": lvl in ("Medium", "High", "Critical"),
            "verdict": VERDICT[lvl], "unsafe_percent": res["score"], "level": lvl, "next": NEXT[lvl],
            "reasons": [f["label"] for f in res["factors"][:3]],
            "scam_type": (res["scam_type"] or {}).get("name", "")}

class Notif(BaseModel):
    app: str = ""
    title: str = ""
    text: str = ""

@app.post("/api/notification")  # lets any device (phone automation, other tools) push a notification for scoring
def api_notification(n: Notif):
    body = f"{n.title}\n{n.text}".strip()
    res = analyze(body)
    if res["level"] != "Safe":  # privacy: safe notifications are never stored
        with db() as c:
            c.execute("INSERT INTO cases(ts,type,text,score,level,factors,urls,stype) VALUES(?,?,?,?,?,?,?,?)",
                      (time.strftime("%Y-%m-%d %H:%M:%S"), "notification", body[:1000], res["score"], res["level"],
                       json.dumps(res["factors"]), json.dumps([u["domain"] for u in res["urls"]]), (res["scam_type"] or {}).get("name", "")))
    return verdict(res)

class Bulk(BaseModel):
    messages: list[str]

@app.post("/api/bulk")
def api_bulk(r: Bulk):
    msgs = [m.strip() for m in r.messages if m and m.strip()][:200]
    out = []
    with db() as c:
        for t in msgs:
            res = analyze(t)
            st = (res["scam_type"] or {}).get("name", "")
            c.execute("INSERT INTO cases(ts,type,text,score,level,factors,urls,stype) VALUES(?,?,?,?,?,?,?,?)",
                      (time.strftime("%Y-%m-%d %H:%M:%S"), res["type"], t[:1000], res["score"], res["level"],
                       json.dumps(res["factors"]), json.dumps([u["domain"] for u in res["urls"]]), st))
            out.append({"text": t[:300], "score": res["score"], "level": res["level"], "scam_type": st,
                        "reasons": [f["label"] for f in res["factors"][:3]], "next": NEXT[res["level"]],
                        "domains": [u["domain"] for u in res["urls"]]})
    out.sort(key=lambda x: -x["score"])
    lv = Counter(x["level"] for x in out)
    types = Counter(x["scam_type"] for x in out if x["scam_type"] and x["level"] != "Safe")
    doms = Counter(d for x in out if x["level"] != "Safe" for d in set(x["domains"]))
    camp = [(d, n) for d, n in doms.most_common(5) if n >= 2]
    hi, med = lv["Critical"] + lv["High"], lv["Medium"]
    recs = []
    if hi: recs.append(f"{hi} message(s) are High/Critical risk. Do not click links or reply; delete them and block the senders.")
    if hi: recs.append("If you already clicked a link or shared an OTP/PIN/password: change your passwords, call your bank to block cards/UPI, and report at 1930 or cybercrime.gov.in right away.")
    if med: recs.append(f"{med} message(s) are Medium risk. Verify through the official app, website or the number printed on your card before acting.")
    if camp: recs.append("Repeated domains found (" + ", ".join(f"{d} x{n}" for d, n in camp) + "). This looks like one campaign: report each domain once with all the examples as evidence.")
    if types:
        top = types.most_common(1)[0][0]; recs.append(f"Most common scam type: {top}. {TIPS.get(top, '')}")
    if hi or med: recs.append("Report suspicious SMS, calls and WhatsApp numbers on the Sanchar Saathi portal (Chakshu) so they can be blocked.")
    if out and not (hi or med): recs.append("No serious threats found. Stay alert for unexpected requests for money, OTPs or links.")
    return {"summary": {"total": len(out), "levels": lv, "campaigns": camp}, "recommendations": recs, "results": out}

class Ingest(BaseModel):
    type: str = "agent"
    text: str = ""
    score: int = 0
    level: str = "Low"
    factors: list = []
    domains: list = []
    scam_type: str = ""

@app.post("/api/ingest")  # lets the local agent push flagged detections to this (deployed) dashboard
def api_ingest(i: Ingest, x_key: str = Header(default="")):
    key = os.getenv("INGEST_KEY", "")
    if key and x_key != key: raise HTTPException(401, "bad key")
    with db() as c:
        c.execute("INSERT INTO cases(ts,type,text,score,level,factors,urls,stype) VALUES(?,?,?,?,?,?,?,?)",
                  (time.strftime("%Y-%m-%d %H:%M:%S"), i.type[:30], i.text[:300], max(0, min(100, i.score)), i.level[:10],
                   json.dumps(i.factors[:6]), json.dumps(i.domains[:10]), i.scam_type[:60]))
    return {"ok": True}

@app.get("/")
def index(): return FileResponse(BASE / "static" / "index.html")