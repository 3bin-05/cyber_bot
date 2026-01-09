# ==========================================================
# Cyber Scam & Phishing Detection Bot
# Image-based Risk Visualization | Cloud-ready
# Author: Ebin
# ==========================================================

# ---------- Render Free-tier HTTP workaround ----------
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

PORT = int(os.getenv("PORT", 10000))

class DummyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Bot is running")

def keep_alive():
    server = HTTPServer(("0.0.0.0", PORT), DummyHandler)
    server.serve_forever()

threading.Thread(target=keep_alive, daemon=True).start()

# ---------- Telegram & Security Imports ----------
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    MessageHandler,
    CommandHandler,
    ContextTypes,
    filters
)

import re
import base64
import requests
import tldextract
import Levenshtein

# =========================
# ENVIRONMENT VARIABLES
# =========================
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls/"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# =========================
# USER DATA
# =========================
user_language = {}
vt_cache = {}
sb_cache = {}
abuse_cache = {}

# =========================
# OFFICIAL DOMAINS & RULES
# =========================
OFFICIAL_DOMAINS = [
    "paytm.com", "amazon.in", "flipkart.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "gov.in", "nic.in"
]

HIGH_RISK_TLDS = [".xyz", ".top", ".click", ".tk", ".info"]

SCAM_KEYWORDS = [
    "urgent", "verify", "account blocked", "kyc",
    "suspended", "click immediately", "free", "winner"
]

# =========================
# IMAGE MAPPING (YOUR REPO)
# =========================
RISK_IMAGES = [
    (10,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_0_10.png.png"),
    (20,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_11_20.png.png"),
    (30,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_21_30.png.png"),
    (40,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_31_40.png.png"),
    (50,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_41_50.png.png"),
    (60,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_51_60.png.png"),
    (70,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_61_70.png.png"),
    (80,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_71_80.png.png"),
    (90,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_81_90.png.png"),
    (100, "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_91_100.png.png"),
]

def get_risk_image(confidence):
    for limit, url in RISK_IMAGES:
        if confidence <= limit:
            return url
    return RISK_IMAGES[-1][1]

# =========================
# USER MESSAGES
# =========================

CONFIDENCE_MEANING_EN = (
    "📊 *Confidence Interpretation*\n"
    "🟢 *0–30%* → Likely Safe (No major scam indicators)\n"
    "🟡 *31–60%* → Low to Moderate Risk (Be cautious)\n"
    "🟠 *61–80%* → High Risk (Possible scam/phishing)\n"
    "🔴 *81–100%* → Very High Risk (Likely scam)\n"
)

CONFIDENCE_MEANING_ML = (
    "📊 *വിശ്വാസനിലയുടെ അർത്ഥം*\n"
    "🟢 *0–30%* → സാധാരണ സുരക്ഷിതം (വലിയ തട്ടിപ്പ് സൂചനകളില്ല)\n"
    "🟡 *31–60%* → കുറഞ്ഞ മുതൽ മിതമായ അപകടസാധ്യത (ശ്രദ്ധിക്കുക)\n"
    "🟠 *61–80%* → ഉയർന്ന അപകടസാധ്യത (തട്ടിപ്പ് / ഫിഷിംഗ് സാധ്യത)\n"
    "🔴 *81–100%* → വളരെ ഉയർന്ന അപകടസാധ്യത (തട്ടിപ്പാകാൻ സാധ്യത)\n"
)

START_MSG = (
    "👋 *Welcome to Cyber Scam Detection Bot*\n\n"
    "🛡️ This bot analyzes messages and links to identify scams & phishing attempts.\n\n"
    "📈 You will receive a confidence score indicating the risk level.\n"
    "⚠️ Always verify messages through official channels.\n\n"
    "🌐 Choose language:\n"
    "1️⃣ English\n"
    "2️⃣ മലയാളം\n\n"
    "ℹ️ You can change language anytime using /lang"
)

EN_CLASS = {
    "DANGEROUS": "🚫 *DANGEROUS* — Do NOT click or respond.",
    "SUSPICIOUS": "⚠️ *SUSPICIOUS* — Verify before acting.",
    "SAFE": "✅ *LOW RISK* — No strong scam indicators."
}

ML_CLASS = {
    "DANGEROUS": "🚫 *അപകടകരം* — ക്ലിക്ക് ചെയ്യരുത്.",
    "SUSPICIOUS": "⚠️ *സംശയാസ്പദം* — സ്ഥിരീകരിക്കുക.",
    "SAFE": "✅ *കുറഞ്ഞ അപകടസാധ്യത*."
}

DISCLAIMER_EN = (
    "\n\n⚠️ *Important Disclaimer*\n"
    "• This analysis is advisory, not a legal or security guarantee.\n"
    "• Attackers frequently change techniques to bypass detection.\n"
    "• A low risk score does not mean the message is 100% safe.\n"
    "• Never share OTPs, passwords, or personal details.\n"
    "• Always verify messages via official apps or websites.\n"
)

DISCLAIMER_ML = (
    "\n\n⚠️ *പ്രധാന അറിയിപ്പ്*\n"
    "• ഈ വിശകലനം ഒരു ഉപദേശമാണ്, നിയമപരമായ അല്ലെങ്കിൽ സുരക്ഷാ ഉറപ്പല്ല.\n"
    "• ആക്രമകർ കണ്ടെത്തൽ ഒഴിവാക്കാൻ തന്ത്രങ്ങൾ മാറ്റിക്കൊണ്ടിരിക്കുന്നു.\n"
    "• കുറഞ്ഞ അപകടസാധ്യതയെന്ന് അർത്ഥമാക്കുന്നത് 100% സുരക്ഷിതമാണെന്നല്ല.\n"
    "• OTP, പാസ്‌വേഡ്, വ്യക്തിഗത വിവരങ്ങൾ ഒരിക്കലും പങ്കിടരുത്.\n"
    "• ഔദ്യോഗിക ആപ്പുകൾ അല്ലെങ്കിൽ വെബ്സൈറ്റുകൾ വഴി മാത്രം സ്ഥിരീകരിക്കുക.\n"
)

# =========================
# HELPER FUNCTIONS
# =========================
def safe_browsing_check(url):
    if url in sb_cache:
        return sb_cache[url][0], f"{sb_cache[url][1]} (cached check)"

    if not GOOGLE_SAFE_BROWSING_KEY:
        return False, "Google Safe Browsing not configured"

    payload = {
        "client": {
            "clientId": "cyber-scam-bot",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(
            SAFE_BROWSING_URL,
            params={"key": GOOGLE_SAFE_BROWSING_KEY},
            json=payload,
            timeout=10
        )

        if r.status_code == 200 and r.json().get("matches"):
            result = (True, "Google Safe Browsing: phishing/malware detected")
            sb_cache[url] = result
            return True, f"{result[1]} (fresh check)"

        result = (False, "Google Safe Browsing: no threats detected")
        sb_cache[url] = result
        return False, f"{result[1]} (fresh check)"

    except:
        return False, "Google Safe Browsing check failed"


def abuseipdb_check(domain):
    if domain in abuse_cache:
        cached = abuse_cache[domain]
        return cached["risk"], f"{cached['reason']} (cached lookup)"

    if not ABUSEIPDB_API_KEY:
        return 0, "AbuseIPDB not configured"

    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "domain": domain,
            "maxAgeInDays": 90
        }

        r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)

        if r.status_code != 200:
            result = {"risk": 0, "reason": "AbuseIPDB unavailable"}
            abuse_cache[domain] = result
            return 0, f"{result['reason']} (fresh lookup)"

        data = r.json()["data"]
        score = data.get("abuseConfidenceScore", 0)
        risk = score // 25

        result = {
            "risk": risk,
            "reason": f"AbuseIPDB abuse score: {score}%"
        }

        abuse_cache[domain] = result
        return risk, f"{result['reason']} (fresh lookup)"

    except:
        return 0, "AbuseIPDB check failed"


def risk_banner(label):
    if label == "DANGEROUS":
        return "🚨🚨 *CRITICAL WARNING!* 🚨🚨\n"
    elif label == "SUSPICIOUS":
        return "⚠️ *CAUTION ADVISED* ⚠️\n"
    else:
        return "🛡️ *GENERAL SAFETY NOTICE* 🛡️\n"

def extract_links(text):
    return re.findall(r'https?://\S+', text)

def keyword_score(text):
    return sum(1 for k in SCAM_KEYWORDS if k in text.lower())

def root_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def similarity_score(domain):
    scores = [(Levenshtein.ratio(domain, real), real) for real in OFFICIAL_DOMAINS]
    return max(scores)

def tld_risk(domain):
    return 2 if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS) else 0

def virustotal_check(url):
    if url in vt_cache:
        vt_cache[url]["cached"] = True
        cached_data = vt_cache[url]
        return (
            cached_data["risk"],
            f"{cached_data['reason']} (cached result)"
        )

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(VT_URL + url_id, headers=headers, timeout=10)

        if r.status_code != 200:
            result = {
                "risk": 0,
                "reason": "VirusTotal unavailable",
                "cached": False
            }
            vt_cache[url] = result
            return result["risk"], f"{result['reason']} (fresh scan)"

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)

        risk = mal * 3 + sus * 2
        reason = f"VirusTotal: {mal} malicious, {sus} suspicious"

        vt_cache[url] = {
            "risk": risk,
            "reason": reason,
            "cached": False
        }

        return risk, f"{reason} (fresh scan)"

    except:
        result = {
            "risk": 0,
            "reason": "VirusTotal check failed",
            "cached": False
        }
        vt_cache[url] = result
        return result["risk"], f"{result['reason']} (fresh scan)"


# =========================
# CORE ANALYSIS (FIXED)
# =========================
def analyze_message(text):
    risk = 0
    reasons = []

    k = keyword_score(text)
    if k:
        risk += k
        reasons.append("Scam-related keywords detected")

    for link in extract_links(text):
        domain = root_domain(link)

        # 🥇 Google Safe Browsing (ALWAYS SHOWN)
        sb_hit, sb_reason = safe_browsing_check(link)
        reasons.append(sb_reason)
        if sb_hit:
            return "DANGEROUS", 95, reasons

        sim, real = similarity_score(domain)
        if sim > 0.80:
            risk += 4
            reasons.append(f"Impersonation of {real}")

        tr = tld_risk(domain)
        if tr:
            risk += tr
            reasons.append("High-risk domain extension")

        # 🥈 AbuseIPDB (ALWAYS SHOWN)
        abuse_risk, abuse_reason = abuseipdb_check(domain)
        reasons.append(abuse_reason)
        risk += abuse_risk

        # 🥉 VirusTotal (ALWAYS SHOWN)
        vt_risk, vt_reason = virustotal_check(link)
        reasons.append(vt_reason)
        risk += vt_risk

    confidence = min(10 + risk * 12, 95)

    if confidence >= 90:
        label = "DANGEROUS"
    elif confidence >= 70:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    return label, confidence, reasons


# =========================
# TELEGRAM HANDLERS
# =========================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in user_language:
        await update.message.reply_text(
            "👋 Welcome back!\n\n"
            "Send a message or link to analyze.\n"
            "Use /lang to change language."
        )
    else:
        await update.message.reply_text(START_MSG, parse_mode="Markdown")

async def change_language(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_language.pop(update.effective_user.id, None)
    await update.message.reply_text(
        "🌐 *Change Language*\n\n"
        "1️⃣ English\n"
        "2️⃣ മലയാളം\n\n"
        "ℹ️ This will change the language of analysis results.",
        parse_mode="Markdown"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if user_id not in user_language:
        if text == "1":
            user_language[user_id] = "EN"
            await update.message.reply_text("✅ Language set to English.\nSend a message to analyze.")
        elif text == "2":
            user_language[user_id] = "ML"
            await update.message.reply_text("✅ ഭാഷ മലയാളമായി സജ്ജീകരിച്ചു.\nസന്ദേശം അയയ്ക്കുക.")
        else:
            await update.message.reply_text(
                "🌐 Please select a language:\n"
                "1️⃣ English\n"
                "2️⃣ മലയാളം\n\n"
                "Use /lang anytime to change it."
            )
        return

    label, confidence, reasons = analyze_message(text)
    image_url = get_risk_image(confidence)
    reason_text = "\n".join(f"• {r}" for r in reasons)
    banner = risk_banner(label)

    if user_language[user_id] == "EN":
        reply = (
            f"{banner}"
            f"*🔍 Analysis Summary*\n\n"
            f"*🧪 Classification:* {EN_CLASS[label]}\n"
            f"*📈 Confidence Score:* {confidence}%\n\n"
            f"{CONFIDENCE_MEANING_EN}\n"
            f"*🧠 Detection Reasons:*\n"
            f"{reason_text if reason_text else '• No strong indicators detected'}"
            f"{DISCLAIMER_EN}"
        )
    else:
        reply = (
            f"{banner}"
            f"*🔍 വിശകലന സംഗ്രഹം*\n\n"
            f"*🧪 വർഗ്ഗീകരണം:* {ML_CLASS[label]}\n"
            f"*📈 വിശ്വാസനില:* {confidence}%\n\n"
            f"{CONFIDENCE_MEANING_ML}\n"
            f"*🧠 കണ്ടെത്തിയ കാരണങ്ങൾ:*\n"
            f"{reason_text if reason_text else '• ശക്തമായ തട്ടിപ്പ് സൂചനകളില്ല'}"
            f"{DISCLAIMER_ML}"
        )

    await update.message.reply_photo(
        photo=image_url,
        caption=reply,
        parse_mode="Markdown"
    )

# =========================
# MAIN
# =========================
def main():
    print("🤖 Cyber Scam Bot running...")
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("lang", change_language))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.run_polling()

if __name__ == "__main__":
    main()
# ==========================================================
