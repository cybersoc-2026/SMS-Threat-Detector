import unittest
import re

from advisory_core import Advisor
from sms_risk_engine import assess_sms


class AdvisoryScoringTests(unittest.TestCase):
    def test_clean_message_has_a_reason_for_empty_evidence(self):
        advisor = Advisor(
            lambda message: {
                "ml_analysis": {
                    "predicted_class": "safe",
                    "scam_probability": 0.05,
                },
                "risk_analysis": {
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "indicators": [],
                },
            }
        )

        result = advisor.analyze("Hi, how are you?")

        self.assertTrue(result["reasons"])

    def test_classifier_decision_gets_small_support_below_heuristic_cutoff(self):
        message = "The weather is clear this afternoon."
        advisor = Advisor(
            lambda _: {
                "ml_analysis": {
                    "predicted_class": "scam",
                    "scam_probability": 0.3,
                },
                "risk_analysis": assess_sms(
                    message,
                    scam_probability=0.3,
                    scam_threshold=0.2,
                ),
            }
        )

        result = advisor.analyze(message)
        self.assertEqual(result["level"], "suspicious")
        self.assertEqual(result["details"]["heuristic_score"], 0)
        self.assertEqual(result["details"]["model_support"], 1)
        self.assertEqual(result["details"]["risk_score"], 1)
        self.assertIn("classifier flagged", result["reasons"][0])

    def test_heuristic_and_model_contributions_are_reported_separately(self):
        message = "Your account will be blocked today. Share your OTP immediately."
        result = assess_sms(
            message,
            scam_probability=0.7005,
            scam_threshold=0.2019,
        )

        self.assertEqual(result["heuristic_score"], 45)
        self.assertEqual(result["model_support"], 2)
        advisor = Advisor(lambda _: {
            "ml_analysis": {"predicted_class": "scam", "scam_probability": 0.7005},
            "risk_analysis": result,
        })
        assessment = advisor.analyze(message)
        self.assertGreaterEqual(assessment["details"]["risk_score"], 75)
        self.assertLess(assessment["details"]["risk_score"], 90)

    def test_recommended_action_uses_message_specific_guidance(self):
        def analyzer(message):
            indicators = []
            if "otp" in message.lower():
                indicators.append({
                    "rule": "CREDENTIAL_REQUEST",
                    "reason": "The message asks for an OTP.",
                })
            if "http" in message.lower():
                indicators.append({
                    "rule": "SENSITIVE_DATA_LINK",
                    "reason": "The message contains a link.",
                })
            return {
                "ml_analysis": {"predicted_class": "scam", "scam_probability": 0.9},
                "risk_analysis": {
                    "risk_level": "HIGH",
                    "risk_score": 80,
                    "indicators": indicators,
                },
            }

        advisor = Advisor(analyzer)
        otp_action = advisor.analyze("Share your OTP now.")["action"]
        link_action = advisor.analyze("Verify your account at https://example.invalid")["action"]

        self.assertIn("OTP", otp_action)
        self.assertIn("link", link_action.lower())

    def test_flagged_phishing_url_cannot_remain_low_risk(self):
        advisor = Advisor(
            lambda _: {
                "ml_analysis": {"predicted_class": "safe", "scam_probability": 0.1},
                "risk_analysis": {
                    "risk_level": "LOW",
                    "risk_score": 18,
                    "indicators": [],
                },
                "url_analysis": {
                    "status": "scanned",
                    "findings": [{
                        "url_index": 0,
                        "prediction": "phishing",
                        "phishing_score": 0.97,
                        "threshold": 0.5,
                    }],
                },
            }
        )

        result = advisor.analyze("Verify your account at https://example.invalid")

        self.assertEqual(result["level"], "suspicious")
        self.assertEqual(result["details"]["risk_level"], "medium")
        self.assertGreaterEqual(result["details"]["risk_score"], 40)

    def test_extreme_get_rich_daily_income_offer_is_high_risk(self):
        message = "Get rich quick! Earn ₹8525843944 daily from home. Call Shahjahanpur"
        result = assess_sms(
            message,
            scam_probability=0.8949,
            scam_threshold=0.5,
        )

        self.assertEqual(result["risk_level"], "HIGH")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertIn(
            "UNREALISTIC_INCOME_PROMISE",
            [indicator["rule"] for indicator in result["indicators"]],
        )
        advisor = Advisor(
            lambda _: {
                "ml_analysis": {
                    "predicted_class": "scam",
                    "scam_probability": 0.8949,
                },
                "risk_analysis": result,
            }
        )
        assessment = advisor.analyze(message)
        self.assertEqual(assessment["level"], "scam_likely")
        self.assertEqual(assessment["details"]["risk_level"], "high")
        self.assertIn("verify the employer", assessment["action"])

        ordinary_job = assess_sms("Earn ₹500 per day working from home.")
        self.assertNotIn(
            "UNREALISTIC_INCOME_PROMISE",
            [indicator["rule"] for indicator in ordinary_job["indicators"]],
        )

    def test_recommended_action_is_one_sentence_in_each_supported_language(self):
        advisor = Advisor(
            lambda _: {
                "ml_analysis": {"predicted_class": "scam", "scam_probability": 0.9},
                "risk_analysis": {
                    "risk_level": "HIGH",
                    "risk_score": 45,
                    "indicators": [
                        {"rule": "CREDENTIAL_REQUEST", "reason": "Requests an OTP."},
                        {"rule": "SENSITIVE_DATA_LINK", "reason": "Includes a link."},
                    ],
                },
            }
        )
        message = "Share your OTP at https://example.invalid"

        for language in ("en", "hi"):
            with self.subTest(language=language):
                result = advisor.analyze(message, language)
                self.assertIsInstance(result["action"], str)
                self.assertNotIn("actions", result)
                self.assertEqual(len(re.findall(r"[.!?।]", result["action"])), 1)


if __name__ == "__main__":
    unittest.main()
