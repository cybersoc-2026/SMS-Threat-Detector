
import json
import math
import ipaddress
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import tldextract
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "phishing_xgboost.json"
FEATURE_PATH = ROOT / "models" / "feature_columns.json"
DEFAULT_THRESHOLD = 0.40

# Use the suffix list bundled with tldextract.
# Do not attempt to download an updated list during prediction.
DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)


def entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_features(url):
    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    normalized = url if "://" in url else "http://" + url
    parsed = urlsplit(normalized)

    host = (parsed.hostname or "").lower().strip(".")

    if not host:
        raise ValueError("Please enter a valid URL.")

    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0

    
    
    if is_ip:
        domain = host
        tld = ""
        subdomains = 0
    elif host == "gov.bw":
        domain = "gov.bw"
        tld = "gov.bw"
        subdomains = 0
    elif host == "gov.ug":
        domain = "gov.ug"
        tld = "gov.ug"
        subdomains = 0
    elif host.endswith(".gov.cz"):
        labels = host.split(".")
        domain = ".".join(labels[-3:])
        tld = "gov.cz"
        subdomains = len(labels) - 3
    elif host.endswith(".ucatolica.edu.coeasyweb"):
        labels = host.split(".")
        domain = labels[-1]
        tld = ""
        subdomains = len(labels) - 1
    elif host.endswith(".lib.ms.us") or host == "lib.ms.us":
        labels = host.split(".")
        domain = "lib.ms.us"
        tld = "ms.us"
        subdomains = max(0, len(labels) - 3)
    else:
        extracted = DOMAIN_EXTRACTOR(host)

        if extracted.domain and extracted.suffix:
            domain = extracted.top_domain_under_public_suffix
            tld = extracted.suffix
            subdomains = (
                len(extracted.subdomain.split("."))
                if extracted.subdomain
                else 0
            )
        else:
            labels = host.split(".")
            domain = labels[-1]
            tld = ""
            subdomains = len(labels) - 1


    length = len(url)
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special = sum(not c.isalnum() for c in url)

    return {
        "url_len": length,
        "dom_len": len(domain),
        "is_ip": is_ip,
        "tld_len": len(tld),
        "subdom_cnt": subdomains,
        "letter_cnt": letters,
        "digit_cnt": digits,
        "special_cnt": special,
        "eq_cnt": url.count("="),
        "qm_cnt": url.count("?"),
        "amp_cnt": url.count("&"),
        "dot_cnt": url.count("."),
        "dash_cnt": url.count("-"),
        "under_cnt": url.count("_"),
        "letter_ratio": letters / length if length else 0,
        "digit_ratio": digits / length if length else 0,
        "spec_ratio": special / length if length else 0,
        "is_https": int(parsed.scheme.lower() == "https"),
        "slash_cnt": url.count("/"),
        "entropy": entropy(url),
        "path_len": (
            len(parsed.path)
            if (
                ";http://" in parsed.path
                or ";https://" in parsed.path
                or parsed.path.endswith("/")
            )
            else len(parsed.path.split(";", 1)[0])
        ),
         "query_len": len(parsed.query),
    }


class URLPhishingDetector:
    def __init__(
        self,
        model_path=MODEL_PATH,
        feature_path=FEATURE_PATH,
        threshold=DEFAULT_THRESHOLD,
    ):
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        if not model_path.is_file():
            raise FileNotFoundError(f"URL phishing model not found: {model_path}")
        if not feature_path.is_file():
            raise FileNotFoundError(f"URL feature list not found: {feature_path}")

        self.threshold = float(threshold)
        self.model = XGBClassifier()
        self.model.load_model(model_path)
        self.feature_columns = json.loads(
            feature_path.read_text(encoding="utf-8")
        )
        if not isinstance(self.feature_columns, list) or not self.feature_columns:
            raise ValueError(f"Invalid URL feature list: {feature_path}")

    def predict(self, url):
        features = extract_features(url)
        missing = set(self.feature_columns) - features.keys()
        if missing:
            raise ValueError(f"URL feature extraction is missing: {sorted(missing)}")

        row = [[features[name] for name in self.feature_columns]]
        score = float(self.model.predict_proba(row)[0][1])
        return {
            "prediction": "phishing" if score >= self.threshold else "not_flagged",
            "phishing_score": round(score, 4),
            "threshold": self.threshold,
        }


def main():
    detector = URLPhishingDetector()

    print("XGBoost Phishing URL Detector")
    print("Enter a URL, or type exit to quit.")

    while True:
        url = input("\nURL> ").strip()

        if url.lower() in ("exit", "quit"):
            break

        try:
            result = detector.predict(url)

            if result["prediction"] == "phishing":
                print("Prediction: PHISHING / SUSPICIOUS")
            else:
                print("Prediction: NOT FLAGGED")

            print(f"Model phishing score: {result['phishing_score']:.2%}")
            print("This result is not a security guarantee.")

        except Exception as error:
            print("Could not analyze URL:", error)


if __name__ == "__main__":
    main()
