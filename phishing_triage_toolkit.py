"""
==================================================================
   CYBER GUARD :: Phishing Triage Toolkit
   DecodeLabs Cyber Security Internship - Project 3
   "Building the Human Firewall"
==================================================================
   A stylish, hacker-themed DESKTOP APP (not a website) built with
   Python + CustomTkinter, that analyzes a suspicious email/message
   and produces a triage verdict using the Pause -> Verify -> Report
   decision tree taught in the Project 3 training deck.

   Run with:  python phishing_triage_toolkit.py

   Requires:  pip install customtkinter
==================================================================
"""

import re
import difflib
import customtkinter as ctk

# ------------------------------------------------------------------
# THEME / COLOR PALETTE  -  "Hacker Terminal" aesthetic
# ------------------------------------------------------------------
BG_MAIN     = "#0a0e0f"
BG_PANEL    = "#0f1720"
BG_CARD     = "#111c1f"
NEON_GREEN  = "#39ff14"
NEON_CYAN   = "#00e5ff"
NEON_RED    = "#ff2b4e"
NEON_AMBER  = "#ffb800"
TEXT_MUTED  = "#5f7a75"
TEXT_MAIN   = "#d8fff0"
FONT_MONO   = "Consolas"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# ------------------------------------------------------------------
# KNOWLEDGE BASE (built from the Project 3 training deck)
# ------------------------------------------------------------------
URGENCY_WORDS = [
    "urgent", "immediately", "asap", "act now", "act fast", "expire",
    "expires", "expiring", "24 hours", "locked", "suspend", "suspended",
    "final notice", "action required", "verify now", "limited time",
    "right away", "as soon as possible", "before the close of business",
]

AUTHORITY_WORDS = [
    "ceo", "director", "law enforcement", "irs", "government",
    "strictly confidential", "do not discuss", "bypass standard",
    "bypass procedure", "compliance", "legal action", "executive",
]

FEAR_GREED_WORDS = [
    "account suspended", "unauthorized access", "unusual activity",
    "your account will be", "prize", "winner", "reward", "free gift",
    "refund", "payment failed", "payment overdue", "wire transfer",
    "invoice overdue", "gift card",
]

SENSITIVE_INFO_WORDS = [
    "password", "otp", "one-time code", "verification code", "ssn",
    "social security", "credit card", "cvv", "pin number", "mfa code",
    "authenticator", "banking details", "routing number", "account number",
]

SECRECY_WORDS = [
    "do not tell", "keep this confidential", "do not discuss with anyone",
    "don't discuss", "between us", "strictly confidential",
]

DANGEROUS_ATTACHMENT_EXT = [
    ".exe", ".scr", ".js", ".iso", ".vbs", ".bat", ".jar", ".hta", ".lnk",
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly",
]

TRUSTED_BRANDS = [
    "amazon", "paypal", "microsoft", "google", "apple", "facebook",
    "netflix", "linkedin", "chase", "wellsfargo", "bankofamerica",
    "dhl", "fedex", "ups", "chatgpt", "outlook", "office365",
]

IP_URL_REGEX = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
URL_REGEX = re.compile(r"https?://[^\s\)\]\>\"']+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"[\w\.\-+]+@[\w\-]+\.[\w\.\-]+")


# ------------------------------------------------------------------
# CORE ANALYSIS LOGIC
# ------------------------------------------------------------------
NEGATION_PREFIXES = ("non-", "non", "not-", "no ", "not ")


def _contains_any(text, words):
    """Word-boundary match that ignores negated occurrences such as
    'Non-Urgent' or 'no immediate action required'."""
    text_l = text.lower()
    hits = []
    for w in words:
        pattern = r"(?<![a-z\-])" + re.escape(w) + r"(?![a-z])"
        for m in re.finditer(pattern, text_l):
            start = m.start()
            preceding = text_l[max(0, start - 8):start]
            if any(preceding.endswith(neg) for neg in NEGATION_PREFIXES):
                continue
            hits.append(w)
            break  # one confirmed hit per word is enough
    return hits


def _extract_domain(email_addr):
    m = re.search(r"@([\w\-]+\.[\w\.\-]+)", email_addr or "")
    return m.group(1).lower() if m else ""


def _lookalike_brand(domain):
    """Return the closest trusted brand name if this domain looks like a
    typosquat / lookalike of it, but isn't the real thing."""
    if not domain:
        return None
    root = domain.split(".")[0].lower()
    for brand in TRUSTED_BRANDS:
        if root == brand:
            return None  # it IS the real brand root, not a lookalike
        ratio = difflib.SequenceMatcher(None, root, brand).ratio()
        if ratio >= 0.75 and root != brand:
            return brand
        # combosquatting: brand name + extra security-ish words
        if brand in root and root != brand:
            return brand
    return None


def analyze_email(display_name, sender_email, reply_to, subject, body):
    """Runs the full Project-3 triage checklist against a message and
    returns a structured result dict."""
    full_text = f"{subject}\n{body}"
    flags = []          # list of (label, severity, explanation)
    score = 0

    sender_domain = _extract_domain(sender_email)
    reply_domain = _extract_domain(reply_to) if reply_to else ""

    # --- 1. Display-name vs domain mismatch -----------------------
    if display_name and sender_email:
        for brand in TRUSTED_BRANDS:
            if brand in display_name.lower() and brand not in sender_domain:
                flags.append((
                    "Display-name spoofing",
                    "high",
                    f'Display name claims "{display_name}" but the real address '
                    f'domain is "{sender_domain}" — a classic Red Flag 1 (sender-domain mismatch).'
                ))
                score += 20
                break

    # --- 2. Reply-To domain mismatch -------------------------------
    if reply_domain and sender_domain and reply_domain != sender_domain:
        flags.append((
            "Reply-To domain mismatch",
            "high",
            f'Replies are silently routed to "{reply_domain}", which differs from '
            f'the sending domain "{sender_domain}".'
        ))
        score += 15

    # --- 3. Lookalike / typosquatted sender domain ------------------
    lookalike = _lookalike_brand(sender_domain)
    if lookalike:
        flags.append((
            "Lookalike / typosquatted domain",
            "high",
            f'"{sender_domain}" closely resembles the trusted brand "{lookalike}.com" '
            f'(typosquatting or combosquatting pattern).'
        ))
        score += 20

    # --- 4. Free/generic email used for a claimed authority ---------
    if display_name and sender_domain in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com"):
        if any(w in display_name.lower() for w in ["ceo", "director", "hr", "support", "it security", "admin"]):
            flags.append((
                "Authority impersonation via free email",
                "high",
                f'A message claiming to be from "{display_name}" is sent from a free '
                f'consumer webmail domain ("{sender_domain}"), not a corporate address.'
            ))
            score += 20

    # --- 5. Urgency triggers -----------------------------------------
    hits = _contains_any(full_text, URGENCY_WORDS)
    if hits:
        flags.append((
            "Urgency / time-pressure language",
            "medium",
            f'Uses urgency cues ({", ".join(hits[:3])}...) designed to trigger a '
            f'fight-or-flight response and bypass rational verification.'
        ))
        score += 10

    # --- 6. Authority pressure -----------------------------------------
    hits = _contains_any(full_text, AUTHORITY_WORDS)
    if hits:
        flags.append((
            "Authority / bypass-procedure pressure",
            "high",
            f'Invokes authority or demands bypassing normal procedure ({", ".join(hits[:3])}).'
        ))
        score += 15

    # --- 7. Fear / greed triggers ---------------------------------------
    hits = _contains_any(full_text, FEAR_GREED_WORDS)
    if hits:
        flags.append((
            "Fear / greed manipulation",
            "medium",
            f'Threatens a negative consequence or dangles a reward ({", ".join(hits[:3])}).'
        ))
        score += 10

    # --- 8. Request for sensitive info -----------------------------------
    hits = _contains_any(full_text, SENSITIVE_INFO_WORDS)
    if hits:
        flags.append((
            "Requests sensitive information",
            "critical",
            f'Asks for sensitive data over email/message ({", ".join(hits[:3])}) — '
            f'legitimate services never request this via a link or reply.'
        ))
        score += 25

    # --- 9. Secrecy demand -------------------------------------------------
    hits = _contains_any(full_text, SECRECY_WORDS)
    if hits:
        flags.append((
            "Demands secrecy",
            "critical",
            "Instructs the recipient to keep the request confidential or not "
            "discuss it with colleagues — isolates the target from verification."
        ))
        score += 20

    # --- 10. URLs: IP address, shorteners, lookalikes -----------------------
    urls = URL_REGEX.findall(full_text)
    for url in urls:
        if IP_URL_REGEX.match(url):
            flags.append((
                "Raw IP-address link",
                "critical",
                f'Link points to a raw IP address ({url}) instead of a named domain — '
                f'a strong malicious indicator.'
            ))
            score += 25
        domain_match = re.search(r"https?://([^/]+)", url)
        if domain_match:
            link_domain = domain_match.group(1).lower()
            if any(s in link_domain for s in SHORTENER_DOMAINS):
                flags.append((
                    "Shortened URL",
                    "medium",
                    f'Uses a link shortener ({link_domain}) that hides the true '
                    f'destination domain.'
                ))
                score += 10
            link_lookalike = _lookalike_brand(link_domain.split(":")[0])
            if link_lookalike:
                flags.append((
                    "Lookalike link domain",
                    "critical",
                    f'Link domain "{link_domain}" mimics "{link_lookalike}.com" — '
                    f'read URLs right-to-left to find the true root domain.'
                ))
                score += 25

    # --- 11. Dangerous attachment extensions mentioned -----------------------
    for ext in DANGEROUS_ATTACHMENT_EXT:
        if ext in full_text.lower():
            flags.append((
                "Dangerous attachment extension",
                "critical",
                f'References a high-risk attachment type ("{ext}") commonly used '
                f'to deliver malware.'
            ))
            score += 25
            break

    # --- 12. Generic greeting (weak signal, only added if other flags exist)
    if re.search(r"\bdear (customer|user|member|sir/madam)\b", body.lower()):
        flags.append((
            "Generic greeting",
            "low",
            'Uses a generic greeting ("Dear Customer/User") instead of your name — '
            'common in mass-phishing templates.'
        ))
        score += 5

    # ---------------------------------------------------------------
    # VERDICT / DECISION TREE  (Pause -> Verify -> Report)
    # ---------------------------------------------------------------
    critical_count = sum(1 for _, sev, _ in flags if sev == "critical")
    high_count = sum(1 for _, sev, _ in flags if sev == "high")

    if not full_text.strip() and not sender_email:
        verdict, action, color = "N/A", "Awaiting input", TEXT_MUTED
    elif critical_count >= 1 or score >= 55:
        verdict, action, color = "MALICIOUS", "Block Domain & Escalate", NEON_RED
    elif high_count >= 1 or score >= 25:
        verdict, action, color = "SUSPICIOUS", "Warn User / Verify Out-of-Band", NEON_AMBER
    elif flags:
        verdict, action, color = "LOW RISK", "Monitor", NEON_AMBER
    else:
        verdict, action, color = "SAFE", "Close", NEON_GREEN

    return {
        "flags": flags,
        "score": min(score, 100),
        "verdict": verdict,
        "action": action,
        "color": color,
        "sender_domain": sender_domain,
    }


# ------------------------------------------------------------------
# SAMPLE MESSAGES  (drawn from the training deck's own examples)
# ------------------------------------------------------------------
SAMPLES = {
    "✅ Safe example": dict(
        display_name="Sarah Lee",
        sender_email="sarah.lee@company.com",
        reply_to="",
        subject="Q3 Project Status Update - Non-Urgent",
        body=(
            "Hi Team,\n\nPlease review the attached project status for Q3 at your "
            "earliest convenience.\n\nNo immediate action is required.\n\nThanks,\nSarah."
        ),
    ),
    "⚠️ Suspicious example (BEC / lost wallet)": dict(
        display_name="CEO",
        sender_email="ceo@gmail.com",
        reply_to="",
        subject="Urgent",
        body=(
            "I lost my wallet at the airport. Need you to wire transfer funds "
            "for my flight immediately before the close of business. Please keep "
            "this confidential and do not discuss with anyone.\n- CEO"
        ),
    ),
    "☠️ Malicious example (credential harvest)": dict(
        display_name="Microsoft Support",
        sender_email="support@logins-updates.com",
        reply_to="collect@attacker-mail.ru",
        subject="FW: Urgent Your Account Security Alert - Action Required",
        body=(
            "Your account will be suspended in 24 hours due to unusual activity.\n\n"
            "Please verify your account immediately by confirming your password and "
            "one-time code at http://192.168.44.12/login\n\n"
            "Attachment: Security_Update_2024.iso\n\n"
            "This is urgent, act now to avoid permanent account lockout."
        ),
    ),
}


# ------------------------------------------------------------------
# GUI APPLICATION
# ------------------------------------------------------------------
class PhishingTriageApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CYBER GUARD // Phishing Triage Toolkit")
        self.geometry("760x860")
        self.minsize(680, 760)
        self.configure(fg_color=BG_MAIN)

        self._build_ui()
        self._animate_scanline()

    # ---------------------------------------------------------
    def _build_ui(self):
        header = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=90)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="🎣  CYBER GUARD",
                     font=(FONT_MONO, 26, "bold"), text_color=NEON_GREEN).pack(pady=(14, 0))
        ctk.CTkLabel(header, text="[ PHISHING TRIAGE TOOLKIT — PROJECT 3 ]",
                     font=(FONT_MONO, 11), text_color=NEON_CYAN).pack()

        self.scanline = ctk.CTkFrame(header, fg_color=NEON_GREEN, width=90, height=2)
        self.scanline.place(x=0, y=88)

        body = ctk.CTkScrollableFrame(self, fg_color=BG_MAIN, scrollbar_button_color=BG_PANEL)
        body.pack(fill="both", expand=True, padx=18, pady=16)

        # ---- Sample loader row ----
        sample_card = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=12,
                                    border_width=1, border_color="#1c2b2b")
        sample_card.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(sample_card, text="> LOAD A TEST MESSAGE:",
                     font=(FONT_MONO, 12, "bold"), text_color=TEXT_MAIN
                     ).pack(anchor="w", padx=16, pady=(14, 6))

        self.sample_var = ctk.StringVar(value="Select a sample...")
        sample_menu = ctk.CTkOptionMenu(
            sample_card, values=list(SAMPLES.keys()), variable=self.sample_var,
            command=self._load_sample, fg_color="#132323", button_color="#1b3232",
            button_hover_color=NEON_GREEN, text_color=NEON_CYAN,
            font=(FONT_MONO, 12), dropdown_font=(FONT_MONO, 11)
        )
        sample_menu.pack(fill="x", padx=16, pady=(0, 14))

        # ---- Input card ----
        input_card = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=12,
                                   border_width=1, border_color="#1c2b2b")
        input_card.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(input_card, text="> INBOX INSPECTOR",
                     font=(FONT_MONO, 13, "bold"), text_color=TEXT_MAIN
                     ).pack(anchor="w", padx=16, pady=(14, 8))

        self.display_name_var = ctk.StringVar()
        self.sender_email_var = ctk.StringVar()
        self.reply_to_var = ctk.StringVar()
        self.subject_var = ctk.StringVar()

        self._field(input_card, "From (display name):", self.display_name_var)
        self._field(input_card, "From (email address):", self.sender_email_var)
        self._field(input_card, "Reply-To (if different):", self.reply_to_var)
        self._field(input_card, "Subject:", self.subject_var)

        ctk.CTkLabel(input_card, text="Body / message text:",
                     font=(FONT_MONO, 11), text_color=TEXT_MUTED
                     ).pack(anchor="w", padx=16, pady=(4, 2))
        self.body_text = ctk.CTkTextbox(
            input_card, height=140, font=(FONT_MONO, 12),
            fg_color="#0b1313", border_color=NEON_GREEN, border_width=1,
            text_color=NEON_GREEN, corner_radius=8
        )
        self.body_text.pack(fill="x", padx=16, pady=(0, 14))

        analyze_btn = ctk.CTkButton(
            input_card, text="🔍 RUN TRIAGE ANALYSIS", height=40, corner_radius=8,
            fg_color="#132323", hover_color="#1b3232", text_color=NEON_GREEN,
            font=(FONT_MONO, 13, "bold"), border_width=1, border_color=NEON_GREEN,
            command=self._run_analysis
        )
        analyze_btn.pack(fill="x", padx=16, pady=(0, 16))

        # ---- Verdict card ----
        verdict_card = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=12,
                                     border_width=1, border_color="#1c2b2b")
        verdict_card.pack(fill="x", pady=(0, 16))

        self.verdict_lbl = ctk.CTkLabel(
            verdict_card, text="AWAITING INPUT...", font=(FONT_MONO, 22, "bold"),
            text_color=TEXT_MUTED
        )
        self.verdict_lbl.pack(pady=(16, 2))

        self.action_lbl = ctk.CTkLabel(
            verdict_card, text="Triage action: —", font=(FONT_MONO, 13, "bold"),
            text_color=NEON_CYAN
        )
        self.action_lbl.pack(pady=(0, 8))

        self.score_bar = ctk.CTkProgressBar(
            verdict_card, height=14, corner_radius=7,
            progress_color=NEON_GREEN, fg_color="#0b1313"
        )
        self.score_bar.set(0)
        self.score_bar.pack(fill="x", padx=20, pady=(4, 8))

        self.score_lbl = ctk.CTkLabel(
            verdict_card, text="Threat score: 0 / 100", font=(FONT_MONO, 12),
            text_color=TEXT_MUTED
        )
        self.score_lbl.pack(pady=(0, 16))

        # ---- Red flag checklist card ----
        self.flags_card = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=12,
                                        border_width=1, border_color="#1c2b2b")
        self.flags_card.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(self.flags_card, text="> RED FLAGS DETECTED",
                     font=(FONT_MONO, 13, "bold"), text_color=TEXT_MAIN
                     ).pack(anchor="w", padx=16, pady=(14, 8))
        self.flags_frame = ctk.CTkFrame(self.flags_card, fg_color="transparent")
        self.flags_frame.pack(fill="x", padx=16, pady=(0, 16))
        self.flag_widgets = []
        self._render_flags([])

        # ---- Golden rule reminder ----
        rule_card = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=12,
                                  border_width=1, border_color=NEON_CYAN)
        rule_card.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(rule_card, text="🛡  THE GOLDEN RULE: PAUSE → VERIFY → REPORT",
                     font=(FONT_MONO, 12, "bold"), text_color=NEON_CYAN
                     ).pack(pady=(12, 4))
        ctk.CTkLabel(
            rule_card,
            text="Never act on a single message alone. Confirm requests through a\n"
                 "second, out-of-band channel, and report suspicious mail instead\n"
                 "of just deleting it.",
            font=(FONT_MONO, 11), text_color=TEXT_MUTED, justify="center"
        ).pack(pady=(0, 12))

        ctk.CTkLabel(
            body, text="DecodeLabs Cyber Security Internship — Project 3 (Phishing Triage Toolkit)",
            font=(FONT_MONO, 10), text_color=TEXT_MUTED
        ).pack(pady=(4, 10))

    def _field(self, parent, label, var):
        ctk.CTkLabel(parent, text=label, font=(FONT_MONO, 11), text_color=TEXT_MUTED
                     ).pack(anchor="w", padx=16, pady=(4, 2))
        entry = ctk.CTkEntry(
            parent, textvariable=var, font=(FONT_MONO, 13), height=36,
            corner_radius=8, fg_color="#0b1313", border_color=NEON_GREEN,
            border_width=1, text_color=NEON_GREEN
        )
        entry.pack(fill="x", padx=16, pady=(0, 6))
        return entry

    # ---------------------------------------------------------
    def _load_sample(self, name):
        sample = SAMPLES.get(name)
        if not sample:
            return
        self.display_name_var.set(sample["display_name"])
        self.sender_email_var.set(sample["sender_email"])
        self.reply_to_var.set(sample["reply_to"])
        self.subject_var.set(sample["subject"])
        self.body_text.delete("1.0", "end")
        self.body_text.insert("1.0", sample["body"])
        self._run_analysis()

    def _render_flags(self, flags):
        for w in self.flag_widgets:
            w.destroy()
        self.flag_widgets = []

        if not flags:
            placeholder = ctk.CTkLabel(
                self.flags_frame, text="No message analyzed yet, or no red flags found.",
                font=(FONT_MONO, 12), text_color=TEXT_MUTED
            )
            placeholder.pack(anchor="w", pady=2)
            self.flag_widgets.append(placeholder)
            return

        severity_color = {
            "critical": NEON_RED, "high": NEON_RED,
            "medium": NEON_AMBER, "low": TEXT_MUTED,
        }
        severity_icon = {
            "critical": "☠", "high": "⚠", "medium": "△", "low": "•",
        }

        for label, severity, explanation in flags:
            row = ctk.CTkFrame(self.flags_frame, fg_color="#0b1313", corner_radius=8)
            row.pack(fill="x", pady=4)
            top = ctk.CTkFrame(row, fg_color="transparent")
            top.pack(fill="x", padx=10, pady=(8, 2))
            ctk.CTkLabel(
                top, text=f"{severity_icon.get(severity, '•')} {label}",
                font=(FONT_MONO, 12, "bold"),
                text_color=severity_color.get(severity, TEXT_MUTED)
            ).pack(side="left")
            ctk.CTkLabel(
                top, text=severity.upper(), font=(FONT_MONO, 10, "bold"),
                text_color=severity_color.get(severity, TEXT_MUTED)
            ).pack(side="right")
            ctk.CTkLabel(
                row, text=explanation, font=(FONT_MONO, 11), text_color=TEXT_MAIN,
                wraplength=620, justify="left"
            ).pack(anchor="w", padx=10, pady=(0, 8))
            self.flag_widgets.append(row)

    # ---------------------------------------------------------
    def _run_analysis(self):
        result = analyze_email(
            self.display_name_var.get(),
            self.sender_email_var.get(),
            self.reply_to_var.get(),
            self.subject_var.get(),
            self.body_text.get("1.0", "end"),
        )
        self.verdict_lbl.configure(text=result["verdict"], text_color=result["color"])
        self.action_lbl.configure(text=f"Triage action: {result['action']}")
        self.score_bar.configure(progress_color=result["color"])
        self.score_bar.set(result["score"] / 100)
        self.score_lbl.configure(text=f"Threat score: {result['score']} / 100")
        self._render_flags(result["flags"])

    # ---------------------------------------------------------
    def _animate_scanline(self):
        try:
            x = self.scanline.winfo_x()
            new_x = (x + 6) % max(self.winfo_width(), 100)
            self.scanline.place(x=new_x, y=88)
        except Exception:
            pass
        self.after(60, self._animate_scanline)


if __name__ == "__main__":
    app = PhishingTriageApp()
    app.mainloop()
