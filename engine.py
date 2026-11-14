"""FraudBeacon AI core analysis engine.

Offline-first heuristics + an explicitly limited prototype text classifier.
No URL is fetched, opened, or contacted by this module.
"""
from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from difflib import SequenceMatcher
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse, unquote

import joblib

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "synthetic_text_classifier.joblib"
UCI_MODEL_PATH = ROOT / "models" / "uci_english_spam_model.joblib"
METRICS_PATH = ROOT / "results" / "synthetic_model_evaluation.json"
UCI_METRICS_PATH = ROOT / "results" / "uci_english_spam_evaluation.json"

MODEL = None
UCI_MODEL = None
MODEL_NOTE = "The bundled classifier was trained on a small AI-assisted synthetic dataset. Its score is an uncalibrated pattern signal, not a real-world probability."
if MODEL_PATH.exists():
    try:
        MODEL = joblib.load(MODEL_PATH).get("pipeline")
    except Exception:
        MODEL = None
if UCI_MODEL_PATH.exists():
    try:
        UCI_MODEL = joblib.load(UCI_MODEL_PATH).get("pipeline")
    except Exception:
        UCI_MODEL = None

try:
    METRICS = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
except Exception:
    METRICS = {}
try:
    UCI_METRICS = json.loads(UCI_METRICS_PATH.read_text(encoding="utf-8"))
except Exception:
    UCI_METRICS = None

ARABIC_TRANSLATION = str.maketrans({
    "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي", "ؤ": "و", "ئ": "ي", "ـ": ""
})


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", str(text or "")).translate(ARABIC_TRANSLATION)
    text = re.sub(r"[\u064b-\u065f\u0670]", "", text)
    return text.lower()


def detect_language(text: str) -> str:
    t = normalize(text)
    arabic = len(re.findall(r"[\u0600-\u06ff]", t))
    latin = len(re.findall(r"[a-z]", t))
    if arabic and latin:
        return "mixed"
    if arabic:
        return "arabic"
    if re.search(r"\b(votre|compte|veuillez|urgent|paiement|banque|cliquez|mot de passe|livraison)\b", t):
        return "french"
    if latin:
        return "english_or_other_latin"
    return "unknown"


PATTERNS = {
    "credential": re.compile(
        r"\b(otp|one.?time.?passcode|verification code|security code|passcode|password|passwd|pin|cvv2?|cvc|account credentials|banking details|card details|login details|recovery code|backup code|code(?:\s+sms)?)\b"
        r"|(?:رمز|كود)\s*(?:التحقق|التاكيد|التأكيد|sms|السري|الدخول)?|كلمة\s*المرور|كلمه\s*السر|الرقم\s*السري|بيانات\s*(?:البطاقة|الحساب)|رمز\s*التطبيق"
        r"|\b(code de verification|code de vérification|mot de passe|code secret|coordonnees bancaires|coordonnées bancaires|informations bancaires)\b",
        re.I,
    ),
    "request": re.compile(
        r"\b(send|share|reply with|text me|provide|enter|type|submit|confirm|verify|validate|update|supply|tell me|forward)\b"
        r"|ارسل|أرسل|ابعث|صيفط|شارك|اعطني|أعطني|ادخل|أدخل|اكتب|أكد|تأكيد|تحقق|حدّث|حدث|عمّر|عمر|ابعثلي"
        r"|\b(envoyez|envoyer|communiquez|saisissez|confirmez|validez|transmettez|répondez|repondez)\b",
        re.I,
    ),
    "urgency": re.compile(
        r"\b(urgent|immediately|right now|within\s+\d+|final warning|last chance|expires? in|act now|limited time|today only|asap)\b"
        r"|عاجل|فورا|فوراً|بسرعة|الان|الآن|خلال\s*\d+|اليوم|قبل\s*\d+|آخر\s*تحذير|اخر\s*تحذير"
        r"|\b(urgent|urgente|immédiatement|immediatement|maintenant|dans\s+\d+|dernière chance|derniere chance)\b",
        re.I,
    ),
    "impersonation": re.compile(
        r"\b(paypal|microsoft|google|apple|amazon|netflix|facebook|instagram|whatsapp|meta|dhl|fedex|ups|courier|customs|tax office|irs|hmrc|bank support|security team|help desk|it support|customer support|account department)\b"
        r"|بريد\s*الجزائر|الجزائر\s*بوست|بريدي\s*موبي|البطاقة\s*الذهبية|البنك|الدعم\s*التقني|خدمة\s*الزبائن|مصلحة\s*الضرائب"
        r"|\b(alg[eé]rie poste|baridi\s*mob|baridimob|la banque|service client|support technique|équipe de sécurité|equipe de securite)\b",
        re.I,
    ),
    "money": re.compile(
        r"\b(payment|pay|fee|refund|transfer|wire|invoice|salary|payroll|crypto|wallet|gift card|prize|reward|claim|tax refund|customs fee|delivery fee|funds|cash)\b"
        r"|ادفع|دفع|رسوم|تحويل|حول|حوّل|مبلغ|جائزة|مكافأة|مكافاه|استرداد|طرد|شحنة|ضريبة|راتب|محفظة|عملات"
        r"|\b(paiement|payer|frais|remboursement|virement|prix|récompense|recompense|cadeau|colis|douane|livraison)\b",
        re.I,
    ),
    "threat": re.compile(
        r"\b(suspended|suspend|blocked|locked|deactivated|closed|terminated|legal action|account closure|lose access|will be deleted|compromised|unauthorized activity)\b"
        r"|سيتم\s*(?:غلق|ايقاف|إيقاف|تعليق)|راح\s*يتغلق|حظر|تجميد|موقوف|معلق|تعليق\s*الحساب|فقدان\s*الوصول|اختراق"
        r"|\b(bloqué|bloque|suspendu|suspendue|fermé|ferme|résilié|resilie|action légale|action legale)\b",
        re.I,
    ),
    "remote_access": re.compile(
        r"\b(anydesk|teamviewer|remote access|screen sharing|share your screen|install this app|remote support|rustdesk|quick assist)\b"
        r"|مشاركة\s*الشاشة|تحكم\s*عن\s*بعد|ثبت\s*التطبيق|تثبيت\s*التطبيق|افتح\s*مشاركة"
        r"|\b(partage d'écran|partage d ecran|accès à distance|acces a distance)\b",
        re.I,
    ),
}

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>\[\]\"']+|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})(?:/[^\s<>\[\]\"']*)?""")
URL_TRIM = ".,;:!?)]}»\u060c\u061b"
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rb.gy", "cutt.ly", "buff.ly", "rebrand.ly", "shorturl.at", "lnkd.in"}
RISKY_TLDS = {"zip", "mov", "top", "click", "work", "live", "gq", "tk", "ml", "cf", "ga", "country"}
BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.co.uk", "paypal.de", "paypal.fr", "paypal.ca", "paypal.com.au", "paypal.com.br"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "azure.com"},
    "google": {"google.com", "google.co.uk", "google.de", "google.fr", "google.ca", "gmail.com", "googleusercontent.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca", "amazon.in", "amazon.co.jp"}, "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"}, "instagram": {"instagram.com"}, "whatsapp": {"whatsapp.com"},
    "dhl": {"dhl.com"}, "fedex": {"fedex.com"}, "ups": {"ups.com"},
}


def extract_urls(text: str) -> list[str]:
    found = []
    for match in URL_RE.findall(text or ""):
        value = match.rstrip(URL_TRIM)
        if value and value not in found:
            found.append(value)
    return found[:10]


def _registered_domain(host: str) -> str:
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in {"co.uk", "com.au", "co.jp", "com.br", "co.in", "com.sg", "co.za", "com.mx", "com.tr", "com.cn", "co.nz"}:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def inspect_url(raw_url: str, ui_language: str = "en") -> dict:
    raw = (raw_url or "").strip().strip("<>").rstrip(URL_TRIM)
    if not raw:
        raise ValueError("Enter a URL." if ui_language == "en" else "أدخل رابطًا للتحليل.")
    if len(raw) > 2048:
        raise ValueError("URL is too long to inspect safely." if ui_language == "en" else "الرابط طويل جدًا للفحص.")
    explicit_scheme = re.match(r"^([a-z][a-z0-9+.-]*):", raw, re.I)
    if explicit_scheme and explicit_scheme.group(1).lower() not in {"http", "https"}:
        scheme = explicit_scheme.group(1).lower()
        return {"url": raw, "host": "—", "scheme": scheme, "score": 60, "verdict": "high",
                "signals": [("Non-web URL scheme", "This is not a normal HTTP/HTTPS web link. Do not execute or open it unless you fully understand the source.") ]}
    normalized = raw if re.match(r"(?i)^https?://", raw) else "https://" + raw
    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
        parsed = urlparse("https://invalid.invalid")
    if not host:
        raise ValueError("This does not look like a valid URL." if ui_language == "en" else "الرابط غير صالح أو لا يحتوي على نطاق واضح.")
    signals = []
    score = 0
    try:
        ipaddress.ip_address(host)
        signals.append(("IP address used as host", "A raw IP is unusual for a normal consumer login page; verify independently."))
        score += 20
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
        if "xn--" in ascii_host:
            signals.append(("Internationalized / punycode domain", "Look-alike characters may be used. Inspect the domain carefully."))
            score += 18
    except Exception:
        pass
    if "@" in parsed.netloc:
        signals.append(("User-info marker in URL", "Text before @ can disguise the actual destination host."))
        score += 22
    if host in SHORTENERS:
        signals.append(("URL shortener", "The final destination is hidden until the link is expanded safely."))
        score += 12
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        signals.append(("Uncommon / higher-abuse top-level domain", "This TLD is not proof of fraud; treat it as one signal among several."))
        score += 10
    if host.count(".") >= 4:
        signals.append(("Unusually deep subdomain chain", "Long chains can hide the actual registered domain."))
        score += 8
    if parsed.scheme.lower() != "https":
        signals.append(("No HTTPS scheme", "The connection may not be encrypted. HTTPS alone would not prove legitimacy either."))
        score += 8
    try:
        port = parsed.port
    except ValueError:
        port = -1
        signals.append(("Malformed port value", "The URL contains an invalid port value; do not trust or open it."))
        score += 18
    if port:
        signals.append(("Non-default port", "A login link with an unusual port deserves extra scrutiny."))
        score += 8
    decoded = unquote(parsed.path + "?" + parsed.query).lower()
    if re.search(r"\.(exe|apk|scr|js|vbs|bat|cmd|iso|dmg)(?:$|[?&])", decoded):
        signals.append(("Executable or script-like file path", "Do not download or run files from an unsolicited link."))
        score += 24
    for brand, domains in BRAND_DOMAINS.items():
        if brand in host and _registered_domain(host) not in domains:
            signals.append((f"Possible {brand.title()} brand impersonation", "The brand name appears in a domain that is not on this limited reference list."))
            score += 22
    score = min(score, 100)
    verdict = "high" if score >= 55 else "medium" if score >= 20 else "low"
    return {"url": raw, "host": host, "scheme": parsed.scheme, "score": score, "verdict": verdict, "signals": signals}


def analyze_indicators(message: str) -> dict:
    text = normalize(message)
    urls = extract_urls(message)
    signal_items = []
    score = 0
    safe_context = bool(re.search(r"\b(never share|do not share|don't share|do not send|never send|ne partagez jamais|ne communiquez jamais)\b|لا\s*(?:تشارك|ترسل|تعطي|تبعث)", text, re.I))
    has_credential = bool(PATTERNS["credential"].search(text))
    asks_credential = has_credential and bool(PATTERNS["request"].search(text)) and not safe_context
    checks = [
        (asks_credential, 42, "Credential or verification-code request", "A message asking for an OTP, password, PIN or card security code is a critical warning sign.", "طلب رمز تحقق أو بيانات دخول", "طلب OTP أو كلمة مرور أو PIN أو رمز أمان البطاقة علامة تحذير قوية."),
        (bool(PATTERNS["remote_access"].search(text)), 28, "Remote-access / screen-sharing request", "Unsolicited remote-access requests can give another person control of a device.", "طلب تحكم عن بُعد أو مشاركة الشاشة", "طلبات التحكم عن بُعد غير المتوقعة قد تمنح طرفًا آخر السيطرة على الجهاز."),
        (bool(urls), 18, "Link included in the message", "A link is not automatically malicious. Do not open an unexpected link before verifying the sender.", "وجود رابط في الرسالة", "وجود رابط لا يعني أنه خبيث تلقائيًا؛ تحقق من المرسل قبل فتح رابط غير متوقع."),
        (bool(PATTERNS["impersonation"].search(text)), 12, "Trusted brand or institution mentioned", "A brand name in a message does not prove that the sender represents that organization.", "ذكر علامة تجارية أو مؤسسة موثوقة", "ذكر اسم شركة أو مؤسسة لا يثبت أن المرسل تابع لها."),
        (bool(PATTERNS["urgency"].search(text)), 10, "Urgency or countdown pressure", "Artificial deadlines can push people to act before checking the request.", "استعجال أو ضغط بمهلة زمنية", "المهل المصطنعة قد تدفع المستخدم للتصرف قبل التحقق."),
        (bool(PATTERNS["money"].search(text)), 9, "Payment, refund or reward language", "Unexpected fees, refunds, prizes or transfers should be confirmed through a separate channel.", "ذكر دفع أو استرداد أو جائزة مالية", "تحقق من الرسوم أو المبالغ أو الجوائز عبر قناة مستقلة."),
        (bool(PATTERNS["threat"].search(text)), 10, "Threat of suspension or account loss", "Threats about losing access are often used to create pressure.", "تهديد بإيقاف الحساب أو فقدان الوصول", "التهديد بفقدان الحساب قد يُستخدم للضغط على الضحية."),
    ]
    for condition, points, title_en, detail_en, title_ar, detail_ar in checks:
        if condition:
            score += points
            signal_items.append({"points": points, "title_en": title_en, "detail_en": detail_en, "title_ar": title_ar, "detail_ar": detail_ar})
    url_details = [inspect_url(url) for url in urls]
    if any(u["verdict"] == "high" for u in url_details):
        score += 12
        signal_items.append({"points": 12, "title_en": "High-risk URL structure detected", "detail_en": "At least one extracted URL has multiple structural warning signals. Review it separately.", "title_ar": "تم رصد بنية رابط عالية الخطورة", "detail_ar": "يحمل رابط واحد على الأقل عدة إشارات بنيوية؛ راجعه بشكل مستقل."})
    score = min(score, 100)
    level = "high" if score >= 65 else "elevated" if score >= 35 else "low"
    return {"score": score, "level": level, "items": signal_items, "urls": url_details, "asks_for_secret": asks_credential, "safe_context": safe_context}


def analyze_message(message: str) -> dict:
    message = (message or "").strip()
    if len(message) < 4:
        raise ValueError("Please enter at least 4 characters." if detect_language(message) != "arabic" else "أدخل أربعة أحرف على الأقل.")
    indicators = analyze_indicators(message)
    lang = detect_language(message)
    model_score = None
    model_prediction = None
    selected_model = UCI_MODEL if lang == "english_or_other_latin" and UCI_MODEL is not None else MODEL
    model_source = "public_uci_english_spam" if selected_model is UCI_MODEL and UCI_MODEL is not None else "synthetic_multilingual_prototype"
    if selected_model is not None:
        try:
            model_score = float(selected_model.predict_proba([message])[0][1])
            model_prediction = int(model_score >= 0.5)
        except Exception:
            pass
    # The rule-based score is the primary decision aid; the model signal remains separate.
    if indicators["level"] == "high":
        verdict = "high"
    elif indicators["level"] == "elevated" or (model_score is not None and model_score >= 0.72 and indicators["score"] >= 20):
        verdict = "elevated"
    else:
        verdict = "low"
    return {"verdict": verdict, "language": lang, "ml_score": model_score, "ml_prediction": model_prediction, "ml_source": model_source, "indicators": indicators, "message_length": len(message), "url_count": len(indicators["urls"])}


def analyze_email_headers(raw_headers: str) -> dict:
    text = raw_headers or ""
    lines = {}
    for line in text.splitlines():
        if ":" in line and not line[:1].isspace():
            key, value = line.split(":", 1)
            lines[key.strip().lower()] = value.strip()
    findings = []
    score = 0
    auth = lines.get("authentication-results", "").lower()
    for mechanism in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mechanism}=fail\b|\b{mechanism}=softfail\b", auth):
            findings.append((f"{mechanism.upper()} authentication failed/soft-failed", "This is a warning. Forwarding and configuration can affect results; review with your mail administrator."))
            score += 18
        elif re.search(rf"\b{mechanism}=pass\b", auth):
            findings.append((f"{mechanism.upper()} authentication passed", "A pass is helpful but does not prove the message content is safe."))
    from_display, from_parsed = parseaddr(lines.get("from", ""))
    from_addr = from_parsed.lower()
    reply_addr = parseaddr(lines.get("reply-to", ""))[1].lower()
    return_addr = parseaddr(lines.get("return-path", ""))[1].lower()
    def domain(addr: str) -> str:
        return addr.rsplit("@", 1)[-1] if "@" in addr else ""
    display = from_display.lower()
    for brand, domains in BRAND_DOMAINS.items():
        if brand in display and from_addr and _registered_domain(domain(from_addr)) not in domains:
            findings.append((f"Display name resembles {brand.title()} but sender domain differs", "The visible display name can be forged. Verify the full sender address and use the organization's official site."))
            score += 22
            break
    if from_addr and reply_addr and domain(from_addr) != domain(reply_addr):
        findings.append(("From and Reply-To domains differ", "Replies may go to a different domain. This can be legitimate in mailing systems, so check context."))
        score += 18
    if from_addr and return_addr and domain(from_addr) != domain(return_addr):
        findings.append(("From and Return-Path domains differ", "Bulk mail platforms can legitimately use separate return-path domains; this is a review cue, not proof."))
        score += 8
    if not auth:
        findings.append(("No Authentication-Results field found", "The pasted header may be incomplete or the mail system may use another format."))
    if not from_addr:
        findings.append(("From address not parsed", "Paste the full raw email headers, not only the visible sender name."))
    return {"score": min(score, 100), "findings": findings, "parsed": {"from": from_addr, "reply_to": reply_addr, "return_path": return_addr, "auth_results": auth}}


def inspect_attachment_name(filename: str) -> dict:
    name = (filename or "").strip()
    if not name:
        raise ValueError("Enter a filename." if filename == "" else "أدخل اسم الملف.")
    lower = name.lower()
    suffixes = re.findall(r"\.([a-z0-9]{1,8})(?=\.|$)", lower)
    risky = {"exe", "scr", "bat", "cmd", "com", "msi", "ps1", "vbs", "js", "jse", "wsf", "hta", "jar", "apk", "iso", "img", "dmg", "sh", "app", "lnk"}
    macro = {"docm", "xlsm", "pptm", "xltm", "dotm"}
    warning = []
    score = 0
    if suffixes and suffixes[-1] in risky:
        warning.append(("Executable or script file type", "Do not run an unexpected executable or script attachment."))
        score += 45
    if suffixes and suffixes[-1] in macro:
        warning.append(("Macro-enabled Office document", "Macros can execute code. Keep macros disabled unless independently verified."))
        score += 30
    if len(suffixes) >= 2 and suffixes[-1] in risky and suffixes[-2] in {"pdf", "jpg", "jpeg", "png", "doc", "docx", "txt"}:
        warning.append(("Double-extension disguise", "The filename may be trying to look like a document while ending in an executable extension."))
        score += 35
    if lower.startswith(".") or name.startswith(" "):
        warning.append(("Unusual filename formatting", "Check the full filename and actual file type in a safe environment."))
        score += 5
    if not warning:
        warning.append(("No obvious risky extension detected", "This checks only the filename. It does not scan file contents or prove the attachment is safe."))
    return {"filename": name, "score": min(score, 100), "findings": warning, "extensions": suffixes}
