"""Connects the advisor to the existing sms_pipeline.py (classifier + risk engine)."""
import json, re

CANDIDATE_FUNCS = ("analyse_sms", "analyze_sms", "analyze_message", "analyze", "run_pipeline", "predict", "classify_sms", "classify")

def load_analyzer(demo: bool = False):
    if demo:
        return demo_analyzer
    import sms_pipeline                                   # your module in the project root
    for name in CANDIDATE_FUNCS:
        fn = getattr(sms_pipeline, name, None)
        if callable(fn):
            def call(msg, _fn=fn):
                r = _fn(msg)
                return json.loads(r) if isinstance(r, str) else r
            return call
    raise RuntimeError(
        "No analysis function found in sms_pipeline.py. Add the real function name to "
        "CANDIDATE_FUNCS in pipeline_adapter.py (it must take one SMS string and return the JSON/dict).")

def demo_analyzer(msg: str) -> dict:
    """DEMO ONLY (no model needed): crude regex stand-in that mimics the pipeline's JSON shape."""
    m = msg.lower()
    inds = []
    if re.search(r"\b(otp|password|pin|cvv)\b", m) and re.search(r"share|send|enter|reply|verify", m):
        inds.append({"id": "credential_request", "title": "Credential request"})
    if "kyc" in m and re.search(r"http|www|\.com|\.in|bit\.ly", m):
        inds.append({"id": "kyc_threat_link", "title": "KYC/account threat with link"})
    if re.search(r"anydesk|teamviewer|quicksupport", m):
        inds.append({"id": "remote_access", "title": "Remote access request"})
    if re.search(r"(won|winner|prize|lottery).*(fee|pay|send)", m):
        inds.append({"id": "advance_fee_reward", "title": "Advance-fee reward"})
    spam = bool(inds) or bool(re.search(r"\b(offer|discount|sale|free|%\s?off)\b", m))
    return {
        "classifier": {
            "label": "spam" if spam else "ham",
            "spam_probability": 0.95 if spam else 0.05,
        },
        "risk": {
            "level": "high" if len(inds) >= 2 else "medium" if inds else "none",
            "score": 10 * len(inds),
            "heuristic_score": 10 * len(inds),
            "model_support": 0,
            "indicators": inds,
        },
        "url_analysis": {"status": "unavailable", "findings": []},
    }


SELFTEST_SCAM = ("Dear customer your KYC is expired. Update immediately at http://bit.ly/kyc-update "
                 "and share the OTP you receive to avoid account block")

def selftest(analyzer):
    """Run a synthetic scam through the real analyzer; return a warning string if the adapter
    cannot read the pipeline output or the scam is judged normal (a silent-failure guard)."""
    from advisory_core import normalize_pipeline_output, decide
    try:
        a = normalize_pipeline_output(SELFTEST_SCAM, analyzer(SELFTEST_SCAM))
    except Exception as e:
        return f"self-test crashed: {type(e).__name__}: {e}"
    if a.clf_label == "unknown":
        return "adapter could not read the classifier label (check ml_analysis keys)"
    if a.risk_level == "unknown" and not a.indicators:
        return "adapter could not read the risk engine output (check risk_analysis keys in advisory_core.normalize_pipeline_output)"
    if decide(a) == "likely_ok":
        return "a synthetic KYC/OTP scam was judged normal - verify the adapter and risk engine"
    return None
