"""
Offline SMS risk engine for an Indian-context SMS scam detection prototype.

Design principles:
- Based on behaviours highlighted in RBI, NPCI and DoT public safety guidance.
- These are implementation heuristics, NOT official RBI/NPCI rules or scores.
- Mentions of OTP, PIN, KYC, bank, URLs or urgency alone do not establish fraud.
- The engine looks for combinations of requested actions and context.
- Returns explainable indicators and keeps the optional ML spam probability separate.

Python standard library only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit


# ---------- Text helpers ----------

URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>()]+"
)

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "cutt.ly", "rb.gy", "tiny.cc",
}

SENSITIVE = (
    r"(?:otp|one[\s-]?time password|upi[\s-]?pin|mpin|"
    r"atm[\s-]?pin|pin|password|passcode|cvv|"
    r"card details|login credentials)"
)

PERSONAL_DATA = (
    r"(?:aadhaar|aadhar|pan(?:\s+card)?|date of birth|"
    r"account number|card number|identity document|"
    r"personal details|kyc documents)"
)

URGENCY = (
    r"\b(?:immediately|urgent(?:ly)?|today|within\s+\d+\s+hours?|"
    r"within\s+\d+\s+minutes?|last chance|final warning|"
    r"will be blocked|will be suspended|will be deactivated|"
    r"account.{0,20}(?:blocked|frozen|suspended|closed))\b"
)

BANKING_CONTEXT = (
    r"\b(?:bank|banking|account|upi|payment|transaction|"
    r"debit card|credit card|kyc|wallet)\b"
)

REWARD_CONTEXT = (
    r"\b(?:receive|received|get|claim|win|won|reward|refund|"
    r"cashback|prize|lottery|commission|gift)\b"
)

PAYMENT_CONTEXT = (
    r"\b(?:pay|payment|transfer|send money|deposit|processing fee|"
    r"registration fee|release fee|claim fee|advance fee)\b"
)


def _clean_text(message: str) -> str:
    return re.sub(r"\s+", " ", str(message or "")).strip().lower()


def _sentences(text: str) -> List[str]:
    # Keep this intentionally simple and deterministic for an offline prototype.
    parts = re.split(r"(?<=[.!?;])\s+|\n+", text)
    return [p.strip(" \t\r\n.,;:") for p in parts if p.strip(" \t\r\n.,;:")]


def _has(pattern: str, text: str) -> bool:
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def _urls(text: str) -> List[str]:
    return URL_RE.findall(text)


def extract_urls(text: str) -> List[str]:
    """Return unique, punctuation-trimmed URLs found in an SMS."""
    found = []
    for raw_url in _urls(text):
        url = raw_url.rstrip(".,;:!?)\"]}")
        normalized = url if "://" in url else f"http://{url}"
        try:
            hostname = urlsplit(normalized).hostname
        except ValueError:
            continue
        if hostname and url not in found:
            found.append(url)
    return found


def _url_indicators(text: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    for raw_url in _urls(text):
        url = raw_url.rstrip(".,;:!?)\"]}")
        host_match = re.search(
            r"(?i)^(?:https?://)?(?:www\.)?([^/:?#]+)", url
        )
        host = host_match.group(1).lower() if host_match else ""

        if host in SHORTENER_HOSTS:
            found.append({
                "rule": "URL_SHORTENER",
                "weight": 8,
                "reason": "The message contains a URL-shortening domain that hides the final destination.",
                "severity": "medium",
                "category": "suspicious_link",
            })
        elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            found.append({
                "rule": "IP_ADDRESS_URL",
                "weight": 12,
                "reason": "The message contains a link whose host is an IP address rather than a recognizable domain.",
                "severity": "medium",
                "category": "suspicious_link",
            })

        if "xn--" in host:
            found.append({
                "rule": "PUNYCODE_DOMAIN",
                "weight": 10,
                "reason": "The link contains a punycode domain; inspect it carefully because look-alike domains can be used in impersonation.",
                "severity": "medium",
                "category": "suspicious_link",
            })

    return found


# ---------- Behaviour-based detections ----------

def _credential_request(text: str) -> bool:
    """
    Detect an apparent request to disclose an authentication secret.
    A clear warning against disclosure in the same sentence suppresses
    that sentence's match.
    """
    request_patterns = [
        rf"\b(?:share|send|provide|reveal|disclose|tell|submit|"
        rf"forward|reply with|enter|type)\b.{{0,55}}\b{SENSITIVE}\b",
        rf"\b{SENSITIVE}\b.{{0,55}}\b(?:share|send|provide|reveal|"
        rf"disclose|tell|submit|forward|reply with|enter|type)\b",
        rf"\b(?:we need|we require|need|needs|require|requires|please give|kindly provide|"
        rf"verify by sending)\b.{{0,55}}\b{SENSITIVE}\b",
    ]

    warning_patterns = [
        r"\b(?:do not|don't|never|must not|should not)\s+"
        r"(?:share|send|reveal|disclose|tell|forward|give)\b",
        r"\b(?:do not|don't|never|must not|should not)\s+"
        r"(?:share|send|reveal|disclose|tell|forward|give)\b.{0,45}\b"
        + SENSITIVE + r"\b",
        r"\b(?:we|our bank|the bank)\s+will never ask\b",
        r"\bnever share\b",
    ]

    for sentence in _sentences(text):
        if any(_has(p, sentence) for p in warning_patterns):
            continue
        if any(_has(p, sentence) for p in request_patterns):
            # Avoid treating generic advice such as "scammers ask you to share
            # OTP" as a direct request from the sender.
            if _has(r"\b(?:scammers?|fraudsters?|criminals?)\b", sentence):
                continue
            return True
    return False


def _upi_receive_pin(text: str) -> bool:
    receive_or_reward = _has(
        r"\b(?:to receive|receive|claim|get|collect|"
        r"cashback|refund|reward|prize|money credited)\b",
        text,
    )
    pin_action = _has(
        r"\b(?:enter|input|type|share|provide|submit|approve)\b"
        r".{0,45}\b(?:upi[\s-]?pin|mpin|pin)\b",
        text,
    ) or _has(
        r"\b(?:upi[\s-]?pin|mpin)\b.{0,45}\b"
        r"(?:enter|input|type|share|provide|submit|approve)\b",
        text,
    )
    # A PIN used to authorise a payment the sender is asking the user to make
    # is also risky, but this rule specifically captures the receive-money scam.
    return receive_or_reward and pin_action


def _remote_access_app(text: str) -> bool:
    install_or_access = _has(
        r"\b(?:install|download|open|use)\b.{0,65}\b"
        r"(?:app|application|apk|remote access|screen sharing|"
        r"remote support|anydesk|teamviewer|quick support)\b",
        text,
    ) or _has(
        r"\b(?:grant|enable|allow)\b.{0,45}\b"
        r"(?:remote access|screen sharing|accessibility permission)\b",
        text,
    )
    banking_context = _has(BANKING_CONTEXT, text)
    help_or_verification = _has(
        r"\b(?:bank|kyc|account|refund|payment|verification|"
        r"customer support|support team)\b",
        text,
    )
    return install_or_access and (banking_context or help_or_verification)


def _kyc_urgency_link(text: str) -> bool:
    kyc_or_account = _has(
        r"\b(?:kyc|re.?kyc|account|bank account|wallet)\b", text
    )
    threat_or_urgency = _has(
        r"\b(?:blocked|blocking|freeze|frozen|suspend|suspended|"
        r"deactivate|deactivated|close|closed|expire|expired|"
        r"immediately|urgent|today|within\s+\d+\s+(?:hours?|minutes?))\b",
        text,
    )
    # Some SMS omit the literal URL but use a link-like instruction such as
    # "click here". Require an update/verification action too.
    link_or_data = (
        bool(_urls(text))
        or _has(PERSONAL_DATA, text)
        or (
            _has(
                r"\b(?:click|tap|open|visit|follow)\s+(?:here|this link|the link)\b"
                r"|\b(?:link below|link provided)\b",
                text,
            )
            and _has(
                r"\b(?:update|verify|complete|submit|confirm|reactivate)\b",
                text,
            )
        )
    )
    return kyc_or_account and threat_or_urgency and link_or_data
def _sensitive_data_link(text: str) -> bool:
    return bool(_urls(text)) and _has(PERSONAL_DATA, text) and _has(
        r"\b(?:update|verify|upload|submit|confirm|provide|enter|"
        r"complete|share)\b",
        text,
    )


def _advance_fee_reward(text: str) -> bool:
    reward = _has(
        r"\b(?:lottery|prize|won|winner|reward|commission|"
        r"cashback|gift|claim your prize)\b",
        text,
    )
    explicit_fee = _has(
        r"\b(?:fee|deposit|processing charge|registration charge|"
        r"release charge|advance payment|pay first|payment required)\b",
        text,
    )
    # Recognize a stated amount tied to a payment action, e.g. "Pay INR 500".
    # A currency amount alone is not sufficient.
    currency_amount = _has(
        r"(?:₹|\b(?:inr|rs\.?|rupees?)\b)\s*\d[\d,]*(?:\.\d{1,2})?",
        text,
    )
    payment_action = _has(
        r"\b(?:pay|transfer|deposit|send|submit)\b", text
    )
    return reward and payment_action and (explicit_fee or currency_amount)


def _unrealistic_income_promise(text: str) -> bool:
    income_offer = _has(
        r"\b(?:earn|earning|income|salary|profit|make)\b", text
    )
    if not income_offer:
        return False
    if _has(r"\bget rich quick\b", text):
        return True
    if not (
        _has(r"\b(?:daily|per day|every day)\b", text)
        and _has(r"\b(?:from home|work from home)\b", text)
    ):
        return False

    amounts = re.findall(
        r"(?:₹|\b(?:inr|rs\.?|rupees?)\b)\s*(\d[\d,]*)", text
    )
    return any(int(amount.replace(",", "")) >= 100_000 for amount in amounts)


def _suspicious_payment_pressure(text: str) -> bool:
    payment = _has(PAYMENT_CONTEXT, text)
    pressure = _has(
        r"\b(?:immediately|urgent|today|last chance|final warning|"
        r"account will be blocked|legal action|penalty|avoid arrest)\b",
        text,
    )
    impersonation_or_threat = _has(
        r"\b(?:police|court|government|tax department|bank officer|"
        r"customs|electricity department|your account will)\b",
        text,
    )
    return payment and pressure and impersonation_or_threat


def _promotional_cues(text: str) -> int:
    patterns = [
        r"\bdiscount\b", r"\boffer\b", r"\bsale\b",
        r"\bshop now\b", r"\bpromo(?:tion|code)?\b",
        r"\bsubscribe\b", r"\bfree delivery\b",
        r"\b(?:for )?free\b", r"\bchat (?:here|now)\b",
        r"\bcompatibility(?: forecast)?\b",
        r"\b(?:find out|check (?:your|the)|discover)\b",
        r"\bwhatsapp\b",
    ]
    return sum(1 for p in patterns if _has(p, text))


def _transactional_cues(text: str) -> int:
    patterns = [
        r"\bdebited\b", r"\bcredited\b", r"\btransaction\b",
        r"\bavailable balance\b", r"\border dispatched\b",
        r"\bdelivery\b", r"\brecharge successful\b",
        r"\bpayment received\b", r"\bhas been paid\b",
    ]
    return sum(1 for p in patterns if _has(p, text))


def assess_sms(
    message: str,
    spam_probability: Optional[float] = None,
    scam_probability: Optional[float] = None,
    scam_threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Assess an SMS and return a JSON-serializable dictionary.

    Args:
        message: SMS text.
        spam_probability: Deprecated alias for backwards compatibility.
                          Prefer scam_probability.
        scam_probability: Optional classifier probability in [0, 1].
                          It adds only a small supporting contribution;
                          it does not independently establish a scam.
        scam_threshold: Optional classifier decision threshold. A prediction
                        at or above this threshold but below the existing
                        high-score bands adds one supporting point.

    Returns:
        {
          "risk_score": int,
          "risk_level": str,
          "category": str,
          "indicators": list of detected indicators,
          "heuristic_score": int,
          "model_support": int,
          "promotional_cues": int,
          "transactional_cues": int
        }

    Risk scores are calibrated heuristic evidence scores, NOT probabilities.
    """
    text = _clean_text(message)
    indicators: List[Dict[str, Any]] = []

    def add(
        rule: str,
        weight: int,
        reason: str,
        severity: str,
        category: str,
    ) -> None:
        indicators.append({
            "rule": rule,
            "weight": weight,
            "reason": reason,
            "severity": severity,
            "category": category,
        })

    # High-confidence behavioural indicators.
    if _credential_request(text) and not _upi_receive_pin(text):
        add(
            "CREDENTIAL_REQUEST", 45,
            "The message appears to ask the recipient to disclose an authentication secret such as an OTP, PIN, password or CVV.",
            "critical", "credential_theft",
        )

    if _upi_receive_pin(text):
        add(
            "UPI_RECEIVE_PIN", 40,
            "The message links receiving or claiming money to entering or approving a UPI PIN. A UPI PIN should not be entered to receive money.",
            "critical", "upi_payment_deception",
        )

    if _remote_access_app(text):
        add(
            "REMOTE_ACCESS_APP", 35,
            "The message asks the recipient to install or use an app, or grant remote/screen access, in a banking, account or support context.",
            "high", "remote_access",
        )

    if _kyc_urgency_link(text):
        add(
            "KYC_URGENCY_LINK", 30,
            "The message combines a KYC/account threat or urgency with a link or request for personal information.",
            "high", "kyc_impersonation",
        )

    if _sensitive_data_link(text):
        add(
            "SENSITIVE_DATA_LINK", 25,
            "The message contains a link and asks the recipient to update, verify or submit sensitive identity information.",
            "high", "data_harvesting",
        )

    if _advance_fee_reward(text):
        add(
            "ADVANCE_FEE_REWARD", 30,
            "The message combines a prize, reward or commission claim with a request for an advance payment or fee.",
            "high", "advance_fee_fraud",
        )

    if _unrealistic_income_promise(text):
        add(
            "UNREALISTIC_INCOME_PROMISE", 26,
            "The message promises unusually large, quick income from daily work at home. Verify the offer and employer independently before responding.",
            "high", "unrealistic_income_offer",
        )

    if _suspicious_payment_pressure(text):
        add(
            "SUSPICIOUS_PAYMENT_PRESSURE", 18,
            "The message combines a payment demand with urgency, a threat or an authority/bank impersonation context.",
            "high", "payment_pressure",
        )

    # URL structure is weak supporting evidence, never proof by itself.
    indicators.extend(_url_indicators(text))

    promo_count = _promotional_cues(text)
    transaction_count = _transactional_cues(text)

    # Optional ML support is deliberately capped and modest.
    ml_support = 0
    probability = None
    classifier_probability = (
        scam_probability if scam_probability is not None else spam_probability
    )
    if classifier_probability is not None:
        try:
            probability = float(classifier_probability)
            if 0.0 <= probability <= 1.0:
                if probability >= 0.95:
                    ml_support = 6
                elif probability >= 0.85:
                    ml_support = 4
                elif probability >= 0.70:
                    ml_support = 2
                elif (
                    scam_threshold is not None
                    and 0.0 <= float(scam_threshold) <= 1.0
                    and probability >= float(scam_threshold)
                ):
                    ml_support = 1
        except (TypeError, ValueError):
            ml_support = 0

    heuristic_score = sum(int(item["weight"]) for item in indicators)
    evidence_score = min(100, heuristic_score + ml_support)

    strong_rules = {
        "CREDENTIAL_REQUEST", "UPI_RECEIVE_PIN",
        "REMOTE_ACCESS_APP", "KYC_URGENCY_LINK",
        "SENSITIVE_DATA_LINK", "ADVANCE_FEE_REWARD",
    }
    strong_evidence = any(item["rule"] in strong_rules for item in indicators)
    # Keep strong behavioral evidence in the upper score band; component totals stay raw.
    risk_score = max(evidence_score, 78) if strong_evidence else evidence_score

    if strong_evidence and evidence_score >= 45:
        risk_level = "CRITICAL"
    elif evidence_score >= 30:
        risk_level = "HIGH"
    elif evidence_score >= 12:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if strong_evidence or evidence_score >= 30:
        category = "POTENTIAL_SCAM"
    elif promo_count > 0 and evidence_score < 12:
        category = "PROMOTIONAL"
    elif transaction_count > 0 and evidence_score < 12:
        category = "LIKELY_TRANSACTIONAL"
    elif evidence_score >= 12:
        category = "SUSPICIOUS_OR_UNCERTAIN"
    else:
        category = "NO_STRONG_INDICATORS"

    return {
        "risk_score": int(risk_score),
        "risk_level": risk_level,
        "category": category,
        "indicators": indicators,
        "heuristic_score": int(heuristic_score),
        "model_support": int(ml_support),
        "promotional_cues": int(promo_count),
        "transactional_cues": int(transaction_count),
    }


# ---------- Built-in regression tests ----------

if __name__ == "__main__":
    import json

    test_messages = [
        (
            "Your OTP for login is 482913. Do not share this OTP with anyone.",
            "Expected: no credential request",
        ),
        (
            "Your account will be blocked today. Share your OTP immediately.",
            "Expected: credential request",
        ),
        (
            "Never reveal your bank password to anyone.",
            "Expected: no credential request",
        ),
        (
            "Our support team needs your OTP. Send it now.",
            "Expected: credential request",
        ),
        (
            "You have received money. Enter your UPI PIN to claim it.",
            "Expected: UPI receive-PIN warning",
        ),
        (
            "Your account has been debited by INR 1500. Available balance is INR 4500.",
            "Expected: likely transactional, no strong scam indicator",
        ),
        (
            "Update your KYC immediately at http://example.invalid or your account will be blocked.",
            "Expected: KYC urgency plus link",
        ),
        (
            "Congratulations, you won a lottery. Pay the processing fee to release your prize.",
            "Expected: advance-fee reward warning",
        ),
        (
            "Congratulations! You won INR 10 lakh. Pay INR 500 to claim your prize.",
            "Expected: advance-fee reward warning for a stated payment amount",
        ),
        (
            "Your KYC has expired. Click here to update your details immediately.",
            "Expected: KYC urgency plus link-like call to action",
        ),
        (
            "Get 50% discount on your next purchase. Shop today!",
            "Expected: promotional, not automatically scam",
        ),
        (
            "Install this remote support app so we can fix your bank account.",
            "Expected: remote-access warning",
        ),
    ]

    for sms, expectation in test_messages:
        print("=" * 78)
        print(sms)
        print(expectation)
        print(json.dumps(assess_sms(sms), indent=2, ensure_ascii=False))
