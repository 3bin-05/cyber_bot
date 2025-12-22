# ==========================================================
# High-Confidence Scam & Phishing Detection Telegram Bot
# Java-free | Cloud-ready | Explainable Security Logic
# Author: Ebin
# ==========================================================

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    MessageHandler,
    CommandHandler,
    ContextTypes,
    filters
)

import os
import re
import base64
import requests
import tldextract
import Levenshtein

# =========================
# ENVIRONMENT VARIABLES
# =========================
BOT_TOKEN = os.getenv("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls/"

# =========================
# USER DATA
# =========================
user_language = {}

# =========================
# SECURITY CONFIG
# =========================
OFFICIAL_DOMAINS = [
    "paytm.com", "amazon.in", "flipkart.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "gov.in", "nic.in"
]

HIGH_RISK_TLDS = [".xyz", ".top", ".click", ".tk", ".info"]

SCAM_KEYWORDS = [
    "urgent", "verify", "account blocked",
    "kyc", "suspended", "click immediately",
    "limited time", "free", "winner"
]

# =========================
# USER MESSAGES
# =========================
START_MSG = (
    "👋 *Welcome to Cyber Scam Detection Bot*\n\n"
    "🛡️ *What I do:*\n"
    "• Detect scam & phishing messages\n"
    "• Identify fake or impersonated domains\n"
    "• Check links for malware & reputation\n\n"
    "⚠️ This tool provides *safety guidance*, not absolute decisions.\n\n"
    "🌐 Choose language:\n"
    "1️⃣ English\n"
    "2️⃣ മലയാളം"
)

CONFIDENCE_SCALE = (
    "📊 *Confidence Scale:*\n"
    "• 90–95% → Very High Risk\n"
    "• 70–89% → Suspicious\n"
    "• Below 70% → Low Risk\n\n"
    "⚠️ Always verify using official apps or websites."
)

EN_CLASS = {
    "DANGEROUS": "🚫 *DANGEROUS* — Do NOT click or respond.",
    "SUSPICIOUS": "⚠️ *SUSPICIOUS* — Verify before acting.",
    "SAFE": "✅ *LOW RISK* — No strong scam indicators found."
}

ML_CLASS = {
    "DANGEROUS": "🚫 *അപകടകരം* — ക്ലിക്ക് ചെയ്യരുത്.",
    "SUSPICIOUS": "⚠️ *സംശയാസ്പദം* — സ്ഥിരീകരിക്കുക.",
    "SAFE": "✅ *കുറഞ്ഞ അപകടസാധ്യത* — ശക്തമായ തട്ടിപ്പ് സൂചനകൾ ഇല്ല."
}

DISCLAIMER = (
    "\n\nℹ️ *Disclaimer:*\n"
    "This analysis is advisory. Attackers constantly change techniques.\n"
    "Always confirm directly through official channels."
)

# =========================
# HELPER FUNCTIONS
# =========================

def extract_links(text):
    return re.findall(r'https?://\S+', text)


def language_behavior_score(text):
    score = 0
    if text.isupper():
        score += 1
    if text.count("!") > 2:
        score += 1
    if len(text.split()) < 4:
        score += 1
    return score


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
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(VT_URL + url_id, headers=headers, timeout=10)

        if r.status_code != 200:
            return 0, "VirusTotal scan unavailable"

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)

        return mal * 3 + sus * 2, f"VirusTotal: {mal} malicious, {sus} suspicious"
    except:
        return 0, "VirusTotal check failed"

# =========================
# CORE ANALYSIS
# =========================

def analyze_links(text):
    risk = 0
    reasons = []

    for link in extract_links(text):
        domain = root_domain(link)

        if domain in OFFICIAL_DOMAINS:
            reasons.append("Domain matches official source")
            continue

        sim, real = similarity_score(domain)
        if sim > 0.80:
            risk += 4
            reasons.append(f"Impersonation detected ({int(sim*100)}% similar to {real})")

        tld_score = tld_risk(domain)
        if tld_score:
            risk += tld_score
            reasons.append("High-risk domain extension used")

        vt_risk, vt_reason = virustotal_check(link)
        risk += vt_risk
        reasons.append(vt_reason)

    return risk, reasons


def analyze_message(text):
    risk = 0
    reasons = []

    risk += language_behavior_score(text)
    if language_behavior_score(text):
        reasons.append("Suspicious message structure")

    k = keyword_score(text)
    if k:
        risk += k
        reasons.append("Scam-related keywords detected")

    lr, lr_reasons = analyze_links(text)
    risk += lr
    reasons.extend(lr_reasons)

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
    user_language.pop(update.effective_user.id, None)
    await update.message.reply_text(START_MSG, parse_mode="Markdown")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if user_id not in user_language:
        if text == "1":
            user_language[user_id] = "EN"
            await update.message.reply_text("Language set to English.\nSend a message to analyze.")
        elif text == "2":
            user_language[user_id] = "ML"
            await update.message.reply_text("ഭാഷ മലയാളമായി സജ്ജീകരിച്ചു.\nസന്ദേശം അയയ്ക്കുക.")
        else:
            await update.message.reply_text("Please select:\n1️⃣ English\n2️⃣ മലയാളം")
        return

    label, confidence, reasons = analyze_message(text)
    reason_text = "\n".join(f"• {r}" for r in reasons)

    if user_language[user_id] == "EN":
        reply = (
            f"🔍 *Analysis Result*\n\n"
            f"*Classification:* {EN_CLASS[label]}\n"
            f"*Confidence:* {confidence}%\n\n"
            f"*Reasons:*\n{reason_text}\n\n"
            f"{CONFIDENCE_SCALE}"
            f"{DISCLAIMER}"
        )
    else:
        reply = (
            f"🔍 *വിശകലന ഫലം*\n\n"
            f"*വർഗ്ഗീകരണം:* {ML_CLASS[label]}\n"
            f"*വിശ്വാസനില:* {confidence}%\n\n"
            f"*കാരണങ്ങൾ:*\n{reason_text}\n\n"
            f"{DISCLAIMER}"
        )

    await update.message.reply_text(reply, parse_mode="Markdown")

# =========================
# MAIN
# =========================

def main():
    print("🤖 Cyber Scam Bot running...")
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.run_polling()

if __name__ == "__main__":
    main()
