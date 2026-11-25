import joblib
import json
import uuid

from sms_risk_engine import assess_sms, extract_urls
from url_phishing.predict_url import URLPhishingDetector

# Load trained classifier
saved = joblib.load("artifacts_bsis_augmented/bsis_scam_tfidf.joblib")
model = saved["model"]
decision_threshold = float(saved["decision_threshold"])
url_detector = URLPhishingDetector()

def analyse_sms(message):

    # Run ML classifier
    probabilities = model.predict_proba([message])[0]
    classes = list(model.classes_)

    scam_prob = float(probabilities[classes.index(1)])
    safe_prob = float(probabilities[classes.index(0)])

    prediction = "scam" if scam_prob >= decision_threshold else "safe"

    # Run the rule-based risk engine
    risk = assess_sms(
        message,
        scam_probability=scam_prob,
        scam_threshold=decision_threshold,
    )
    urls = extract_urls(message)
    url_findings = [
        {"url_index": index, **url_detector.predict(url)}
        for index, url in enumerate(urls)
    ]

    # Build output
    output = {
        "schema_version": "1.1",
        "message_id": str(uuid.uuid4()),

        "sms": {
            "text": message,
            "language": "unknown"
        },

        "ml_analysis": {
            "model_name": "bsis_tfidf_word_char_logistic_regression",
            "predicted_class": prediction,
            "decision_threshold": decision_threshold,
            "scam_probability": round(scam_prob, 4),
            "safe_probability": round(safe_prob, 4)
        },

        "risk_analysis": risk,

        "url_analysis": {
            "status": "scanned" if urls else "not_applicable",
            "model_name": "xgboost_url_structure_classifier",
            "findings": url_findings
        },

        "assessment_metadata": {
            "detection_method": [
                "machine_learning",
                "rule_based",
                "url_phishing_model"
            ],
            "is_offline": True,
            "score_is_probability": False,
            "classifier_score_is_calibrated_probability": False,
            "classifier_benchmark_is_synthetic": True
        }
    }

    return output


if __name__ == "__main__":
    sms = input("Enter SMS: ")
    result = analyse_sms(sms)

    print(json.dumps(
        result,
        indent=4,
        ensure_ascii=False
    ))