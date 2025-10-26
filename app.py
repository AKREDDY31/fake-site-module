import streamlit as st
from typing import Tuple, Dict, List
import requests, io, re, math, time
from bs4 import BeautifulSoup
import pdfplumber
import tldextract
import validators
import phonenumbers
import json

# WHOIS optional (may not be available in some environments). We'll try to use it if present.
try:
    import whois
except Exception:
    whois = None

# --- Styling & page config ---
st.set_page_config(page_title="Job Scam Detector", layout="wide", page_icon="🛡️")
st.markdown("""
<style>
.app-header { 
  padding: 18px 26px; 
  border-radius: 12px; 
  background: #fff;
  color: #232b3b; 
  box-shadow: 0 2px 10px rgba(30,30,30,0.08); 
}
.title { font-size:28px; font-weight:700; letter-spacing:0.4px; margin-bottom:6px; }
.subtitle { color: #6b7689; margin-top:0; margin-bottom:6px; }

/* Buttons & inputs */
.stButton>button { background: #06b6d4; color: white; padding:10px 18px; border-radius: 10px; border: none; font-weight:600; }
.stButton>button:hover { background: #0d7fab; }
.stFileUploader > div { background: #fff; border-radius: 10px; padding: 8px; }
.big-mono { font-family: monospace; display:block; padding:10px; background:#f4f5f9; color:#334; border-radius:8px; }

/* Cards */
.card { background: #fff; 
  padding:16px; 
  border-radius:12px; 
  color:#232b3b; 
  box-shadow: 0 2px 10px rgba(30,30,30,0.09); 
}
.bad { color:#ff6565; font-weight:600; }
.good { color:#32ab76; font-weight:600; }
.small { font-size:13px; color:#5e6d87; }
.kv { font-weight:700; color:#31386a; }

/* results */
.pos { color:#228c37; font-weight:600; }
.neg { color:#e02323; font-weight:600; }
.explain { background:#f7f7fc; padding:12px; border-radius:8px; color:#232b3b; }

/* Tabs */
div[role="tablist"] > div { background: #fff !important; }

/* Sidebar Quick Tips */
.quickbox {
  background: linear-gradient(90deg,#f8fafc 60%, #e9ecf7 100%);
  border-left: 4px solid #3aadcc;
  box-shadow: 0 2px 10px #d8dbeb44;
  border-radius: 10px;
  padding: 18px 14px 16px 18px;
  margin-top: 20px;
  margin-bottom: 24px;
}
.quickbox-title {
  font-size: 17px;
  font-weight: 700;
  color: #27aebc;
  margin-bottom: 9px;
  letter-spacing: 0.02em;
}
.quickbox-list {
  margin: 0;
  padding-left: 18px;
  font-size: 15.2px;
  color: #335076;
}
.quickbox-list li {
  margin-bottom: 8px;
  line-height: 1.53em;
}
</style>
<div class="app-header">
  <div class="title">🛡️ Job Scam Detector</div>
  <div class="subtitle">Upload a job listing PDF / paste job text / provide a URL — get a trust score, flagged risks, and clear reasons.</div>
</div>
""", unsafe_allow_html=True)

# --- Utility functions ---

SUSPICIOUS_PHRASES = [
    "send money", "pay us", "transfer", "pay a fee", "wire money", "application fee",
    "western union", "moneygram", "click here to pay", "give bank details", "ssn", "social security",
    "urgent hiring", "immediate joining", "work from home and earn", "no experience required and pay",
    "receive money", "crypto", "bitcoin", "pay for training", "certificate fee"
]
VAGUE_PHRASES = [
    "competitive salary", "attractive salary", "details will be discussed", "excellent package", "fast-growing",
    "amazing opportunity", "market leading"
]
CONTACT_KEYWORDS = ["contact", "email", "phone", "whatsapp", "telegram", "apply to", "send resume", "cv to"]

EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
PHONE_REGEX = re.compile(r'(\+?\d[\d\s\-\(\)]{6,}\d)')

def extract_text_from_pdf_bytes(b: bytes) -> str:
    try:
        text = []
        with pdfplumber.open(io.BytesIO(b)) as pdf:
            for page in pdf.pages:
                txt = page.extract_text()
                if txt:
                    text.append(txt)
        return "\n".join(text)
    except Exception:
        return ""

def extract_text_from_url(url: str, headers=None) -> Tuple[str, BeautifulSoup]:
    headers = headers or {"User-Agent": "Mozilla/5.0 (Job-Scam-Detector)"}
    try:
        r = requests.get(url, headers=headers, timeout=12)
        r.raise_for_status()
        content = r.text
        soup = BeautifulSoup(content, "html.parser")
        for s in soup(["script", "style", "noscript", "svg"]):
            s.decompose()
        visible_text = soup.get_text(separator="\n")
        visible_text = re.sub(r'\n\s*\n+', "\n\n", visible_text)
        return visible_text, soup
    except Exception as e:
        return f"", None

def extract_emails(text: str) -> List[str]:
    return list({m.group(0).lower() for m in EMAIL_REGEX.finditer(text)})

def extract_phones(text: str) -> List[str]:
    phones = set()
    for m in PHONE_REGEX.finditer(text):
        phones.add(re.sub(r'\s+', '', m.group(0)))
    try:
        for match in phonenumbers.PhoneNumberMatcher(text, None):
            phones.add(phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164))
    except Exception:
        pass
    return list(phones)

def extract_links_from_soup(soup: BeautifulSoup) -> List[str]:
    if not soup:
        return []
    links = []
    for a in soup.find_all("a", href=True):
        links.append(a["href"])
    return links

def domain_info(domain: str) -> Dict:
    info = {"domain": domain, "https": None, "length": len(domain), "has_hyphen": "-" in domain, "tld": "", "whois_age_days": None}
    try:
        parsed = tldextract.extract(domain)
        info["tld"] = parsed.suffix or ""
    except Exception:
        info["tld"] = ""
    try:
        if whois:
            w = whois.whois(domain)
            cd = w.creation_date
            if isinstance(cd, list) and cd:
                cd = cd[0]
            if hasattr(cd, "timestamp"):
                age_days = (time.time() - cd.timestamp()) / (3600 * 24)
                info["whois_age_days"] = int(age_days)
    except Exception:
        info["whois_age_days"] = None
    return info

def score_text_and_url(text: str, url: str=None, soup: BeautifulSoup=None) -> Dict:
    reasons = []
    positives = []
    negatives = []
    flagged_words = []
    score = 100.0

    text_lower = text.lower()

    s_count = 0
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text_lower:
            s_count += 1
            flagged_words.append(phrase)
    if s_count:
        deduct = min(40, s_count * 8)
        score -= deduct
        negatives.append(f"Found suspicious phrases ({s_count}) like: {', '.join(flagged_words[:6])}")
        reasons.append(f"-{deduct} for suspicious phrases")

    v_count = 0
    for phrase in VAGUE_PHRASES:
        if phrase in text_lower:
            v_count += 1
    if v_count:
        deduct = min(15, v_count * 3)
        score -= deduct
        negatives.append(f"Vague/marketing phrases ({v_count}) found.")
        reasons.append(f"-{deduct} for vague language")

    pay_count = 0
    for phrase in ["pay", "fee", "training fee", "certificate fee", "transfer money", "send money"]:
        if phrase in text_lower:
            pay_count += 1
    if pay_count:
        deduct = min(40, pay_count * 12)
        score -= deduct
        negatives.append("Text includes payment or fee requests for the applicant.")
        reasons.append(f"-{deduct} for payment-related language")

    for s in ["bank account", "account number", "ssn", "social security number", "passport number", "aadhar"]:
        if s in text_lower:
            score -= 25
            negatives.append(f"Requests sensitive personal information like '{s}'.")
            reasons.append("-25 for requesting sensitive data")

    emails = extract_emails(text)
    phones = extract_phones(text)
    if emails:
        suspicious_email_count = 0
        for e in emails:
            domain = e.split("@")[-1]
            if domain.endswith(("gmail.com","yahoo.com","hotmail.com","outlook.com","rediffmail.com","yandex.com")):
                suspicious_email_count += 1
        if suspicious_email_count > 0:
            deduct = min(20, suspicious_email_count * 6)
            score -= deduct
            negatives.append(f"{suspicious_email_count} contact email(s) use free/public email provider(s).")
            reasons.append(f"-{deduct} for free email contact")
        else:
            positives.append("Contact emails appear to be corporate domains.")
    else:
        negatives.append("No contact email found in posting (or maybe image-based text).")
        reasons.append("-5 for missing contact email")

    if phones:
        positives.append(f"Phone numbers found: {len(phones)}")
    else:
        negatives.append("No phone number found in text.")

    if url:
        if validators.url(url):
            parsed = tldextract.extract(url)
            domain = parsed.registered_domain or parsed.domain + "." + parsed.suffix
            info = domain_info(domain)
            try:
                resp = requests.head(url, timeout=8, allow_redirects=True)
                scheme = resp.url.split(":")[0]
                if scheme != "https":
                    score -= 8
                    negatives.append("Website is not using HTTPS.")
                    reasons.append("-8 for missing HTTPS")
                else:
                    positives.append("Website uses HTTPS.")
            except Exception:
                score -= 10
                negatives.append("Could not reach the website to verify HTTPS (network/unavailable).")
                reasons.append("-10 for unreachable site")
            if info.get("whois_age_days") is not None:
                age_years = info["whois_age_days"] / 365.0
                if age_years < 0.5:
                    score -= 12
                    negatives.append(f"Domain is very new ({age_years:.2f} years). New domains are suspicious.")
                    reasons.append("-12 for new domain")
                elif age_years < 2:
                    score -= 5
                    negatives.append(f"Domain age {age_years:.2f} years — exercise caution.")
                    reasons.append("-5 for young domain")
                else:
                    positives.append(f"Domain registered for {age_years:.1f} years.")
            else:
                reasons.append("-0 whois unknown")
            if info.get("has_hyphen"):
                score -= 6
                negatives.append("Domain contains hyphens (common in spoof domains).")
                reasons.append("-6 for hyphens in domain")
            if info.get("length", 0) > 30:
                score -= 6
                negatives.append("Long/complex domain name (might be a phishing URL).")
                reasons.append("-6 for long domain")
            if info.get("tld","") in ("info","ru","pw","xyz","top","biz"):
                score -= 6
                negatives.append(f"Uncommon/suspicious TLD detected ({info.get('tld')}).")
                reasons.append("-6 for suspicious TLD")
            if soup:
                forms = soup.find_all("form")
                if not forms:
                    reasons.append("-2 no forms detected for application (could mean only email apply).")
                else:
                    positives.append(f"Site has {len(forms)} form(s) (application/interaction possible).")
            if soup:
                links = extract_links_from_soup(soup)
                external_links = [l for l in links if validators.url(l) and tldextract.extract(l).registered_domain != domain]
                if len(external_links) > 10:
                    score -= 4
                    negatives.append("Page links heavily to external domains (could be low-quality aggregator).")
                    reasons.append("-4 for many external links")
        else:
            score -= 20
            negatives.append("Provided URL is not valid.")
            reasons.append("-20 for invalid URL")

    required_keywords = ["responsibilit", "requirement", "qualification", "skills", "experience", "role", "position"]
    req_found = sum(1 for k in required_keywords if k in text_lower)
    if req_found < 2:
        score -= 18
        negatives.append("Job description lacks clear responsibilities / required skills.")
        reasons.append("-18 for missing job structure")
    else:
        positives.append("Clear job responsibilities / skills described.")

    salary_matches = re.findall(r'₹[\d,]+|rs\.\s*\d+|\$\s?\d+|\band salary\b|\bCTC\b', text, flags=re.IGNORECASE)
    if salary_matches:
        positives.append("Salary / CTC mentioned.")
    else:
        reasons.append("-3 salary not explicitly mentioned")

    urgent_count = sum(1 for p in ["urgent hiring", "apply now", "immediate join", "interview today", "walkin interview"] if p in text_lower)
    if urgent_count:
        score -= min(12, urgent_count*6)
        negatives.append("Pressure/urgency language used (common in scam posts).")
        reasons.append(f"-{min(12, urgent_count*6)} urgency wording")

    score = max(0, min(100, score))
    label = "Likely Legit" if score >= 70 else ("Suspicious" if score >= 40 else "Likely Scam")

    return {
        "score": int(round(score)),
        "label": label,
        "reasons": reasons,
        "positives": positives,
        "negatives": negatives,
        "flagged_words": flagged_words,
        "emails": emails,
        "phones": phones
    }

# --- Streamlit UI ---

st.sidebar.markdown("## 🔎 Input method")
input_mode = st.sidebar.radio("Choose input type", ("Upload PDF", "Paste Text", "URL"))

st.sidebar.markdown("""
<div class='quickbox'>
  <div class='quickbox-title'>ℹ️ Quick Tips</div>
  <ul class='quickbox-list'>
    <li>Upload job listing PDF or paste the job text.</li>
    <li>For URLs, provide the full URL (<span style='color:#2985ca;font-weight:500'>https://...</span>).</li>
    <li>The detector uses an <b>explainable rule-based system</b> (not an opaque ML model), so you see <b>exactly why a result is flagged</b>.</li>
  </ul>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3, tab4 = st.tabs(["Analyze", "Raw Output", "Highlights", "About"])

with tab1:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.markdown("### Provide job listing")
    st.write("")  # spacing

    extracted_text = ""
    page_soup = None
    provided_url = None

    if input_mode == "Upload PDF":
        uploaded = st.file_uploader("Upload job listing PDF", type=["pdf"], accept_multiple_files=False)
        if uploaded:
            raw_bytes = uploaded.read()
            extracted_text = extract_text_from_pdf_bytes(raw_bytes)
            if not extracted_text:
                st.error("Couldn't extract selectable text from PDF. If the PDF is scanned as image, try copy-paste or use OCR pipeline.")
            else:
                st.success("Text extracted from PDF.")
    elif input_mode == "Paste Text":
        extracted_text = st.text_area("Paste job description text here", height=280)
    else:
        provided_url = st.text_input("Job listing URL (include https:// or http://)")
        if provided_url:
            st.info("Fetching URL... this may take a moment.")
            txt, soup = extract_text_from_url(provided_url)
            extracted_text = txt or ""
            page_soup = soup
            if not extracted_text:
                st.error("Couldn't fetch readable text from URL (site blocked or dynamic content). You may paste text manually.")
            else:
                st.success("Text extracted from URL.")

    st.markdown("#### Final text to analyze (you can edit before analyzing):")
    final_text = st.text_area("Final text", value=extracted_text, height=240)
    analyze_button = st.button("Analyze Listing", key="analyze")

    if analyze_button:
        if not final_text.strip() and not provided_url:
            st.warning("Please provide text (or a URL / PDF) to analyze.")
        else:
            with st.spinner("Analyzing..."):
                result = score_text_and_url(final_text, provided_url, page_soup)
            col1, col2 = st.columns([1.2, 1])
            with col1:
                st.markdown(f"<div class='card'><div style='display:flex; justify-content:space-between; align-items:center;'>"
                            f"<div><h3 style='margin:0'>{result['label']}</h3><div class='small'>Trust score: <span style='font-weight:700'>{result['score']}/100</span></div></div>"
                            f"<div style='text-align:right'><div class='small'>Input: <b>{input_mode}</b></div></div></div>"
                            f"<hr style='margin:10px 0 10px 0;'/>"
                            f"<div style='display:flex; gap:12px;'><div class='small'><b>Positives</b><ul>"
                            + "".join([f"<li class='pos'>{p}</li>" for p in result['positives']]) +
                            "</ul></div><div class='small'><b>Negatives</b><ul>"
                            + "".join([f"<li class='neg'>{n}</li>" for n in result['negatives']]) +
                            "</ul></div></div>"
                            f"<hr style='margin:8px 0 8px 0;'/>"
                            f"<div class='small'><b>Top reasons / deductions:</b><br/>" +
                            "<br/>".join(result['reasons'][:8]) +
                            "</div></div>", unsafe_allow_html=True)

            with col2:
                st.markdown("<div class='card'><b>Contact Info Found</b><hr/>", unsafe_allow_html=True)
                st.markdown(f"<div class='small'><b>Emails:</b> {', '.join(result['emails']) if result['emails'] else 'None found'}</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='small'><b>Phones:</b> {', '.join(result['phones']) if result['phones'] else 'None found'}</div>", unsafe_allow_html=True)
                if provided_url:
                    st.markdown(f"<div class='small'><b>URL analyzed:</b> {provided_url}</div>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            with st.expander("See detailed explanation and flagged fragments"):
                st.markdown("<div class='explain'>", unsafe_allow_html=True)
                st.markdown("**Verdict summary**")
                st.write(result)
                st.markdown("**Flagged words/phrases (sample):**")
                st.write(result['flagged_words'][:40])
                st.markdown("**Suggestions to user:**")
                st.markdown("""
                - Don't share bank details, SSN, or passport numbers before confirming an employer's legitimacy.  
                - If contact emails are from free providers (gmail/yahoo) prefer verifying via LinkedIn/company website.  
                - Ask for official HR contact and corporate domain email.  
                - Use job portal application forms (not email) when possible.  
                - If job requests payment: do not pay and treat as scam.
                """)
                st.markdown("</div>", unsafe_allow_html=True)

with tab2:
    st.markdown("### Raw text / debug output")
    st.write("")
    st.markdown("You can paste the raw job text below for debug / manual review.")
    raw_text = st.text_area("Raw text", height=400)
    if st.button("Run quick extract on raw text"):
        st.write("Emails:", extract_emails(raw_text))
        st.write("Phones:", extract_phones(raw_text))
        st.write("Suspicious phrases (detected):", [p for p in SUSPICIOUS_PHRASES if p in raw_text.lower()])

with tab3:
    st.markdown("### Highlights from last analyzed text")
    st.info("This shows the last run's flagged phrases and contact details for quick scanning.")
    if "last_result" not in st.session_state:
        st.session_state["last_result"] = None
    if st.button("Show last result (if any)"):
        st.write(st.session_state.get("last_result"))
    else:
        st.write("Press the button to display last result stored in this session (if you analysed a listing).")

with tab4:
    st.markdown("## About this detector")
    st.markdown("""
    - **Engine:** Explainable rule-based system (weighted heuristics).  
    - **Inputs supported:** PDF (selectable text), copied text, URL.  
    - **What it checks:** suspicious phrases, payment requests, contact email types, phone presence, domain features (HTTPS, whois age if available), vagueness, missing job structure, and urgency language.  
    - **Limitations:** Not a replacement for human judgement. Scammers evolve; always cross-verify via company website, LinkedIn, and direct HR email on corporate domain.
    """)
    st.markdown("---")
    st.markdown("### Development / Integration notes")
    st.markdown("""
    - This module is built to be integrated into a larger MERN stack platform as described in your SRS.
    - For production, you can add: automated OCR for image PDFs (Tesseract), ML classifiers trained on labeled scam vs legit postings, rate-limited WHOIS + domain reputation API, and integration with external threat intelligence APIs.
    """, unsafe_allow_html=True)

try:
    if 'result' in locals():
        st.session_state["last_result"] = result
except Exception:
    pass
