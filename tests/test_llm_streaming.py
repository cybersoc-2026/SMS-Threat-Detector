import io
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.request import Request, urlopen

from advisory_core import (
    Advisor,
    Analysis,
    build_llm_prompt,
    normalize_pipeline_output,
    validate_llm_text,
)
from app_server import make_handler
from llm_executorch import ExecuTorchLlama
from sms_risk_engine import assess_sms


class FakeLlama:
    def __init__(self, chunks):
        self.chunks = chunks
        self.calls = 0

    def available(self):
        return True

    def generate_stream(self, prompt):
        self.calls += 1
        yield from self.chunks

    def generate(self, prompt):
        self.calls += 1
        return "".join(self.chunks)


class FakeProcess:
    def __init__(self, output):
        self.stdout = io.StringIO(output)
        self.waited = False
        self.returncode = 0

    def wait(self, timeout=None):
        self.waited = True
        return self.returncode

    def poll(self):
        return self.returncode if self.waited else None

    def kill(self):
        self.returncode = -9
        self.waited = True


class LLMStreamingTests(unittest.TestCase):
    def test_system_prompt_prevents_unsupported_numbers_and_too_short_drafts(self):
        message = "Hey, how are you? Let's catch up later."
        analysis = normalize_pipeline_output(
            message,
            {
                "ml_analysis": {"predicted_class": "safe", "scam_probability": 0.05},
                "risk_analysis": assess_sms(message),
            },
        )
        prompt = build_llm_prompt(
            analysis,
            "likely_ok",
            "en",
        )

        self.assertIn("Do not include digits", prompt)
        self.assertIn("at least 40 characters", prompt)
        self.assertIn("no more than 400 characters", prompt)
        self.assertIn(message, prompt)
        self.assertIn("untrusted", prompt.lower())
        self.assertIn("Promotional cues: 0", prompt)
        self.assertIn("Transactional cues: 0", prompt)
        self.assertIn("Detected URLs: 0", prompt)

    def test_unverified_number_drops_its_sentence_but_keeps_valid_explanation(self):
        analysis = Analysis(
            message="Your account is locked. Verify requests through the official bank app."
        )
        draft = (
            "Call 9876543210 to resolve the issue. "
            "Verify the request only through your bank's official app."
        )

        valid, text, reason = validate_llm_text(draft, analysis, "suspicious", "en")

        self.assertTrue(valid, reason)
        self.assertNotIn("9876543210", text)
        self.assertIn("Verify the request", text)

    def test_llm_output_is_yielded_before_subprocess_finishes(self):
        prompt = "prompt text"
        response = (
            "The message asks you to share an OTP, which is a sensitive secret."
        )
        process = FakeProcess(prompt + response)
        llm = ExecuTorchLlama("runner", "model", "tokenizer")

        with patch("llm_executorch.subprocess.Popen", return_value=process):
            stream = llm.generate_stream(prompt)
            first_chunk = next(stream)
            self.assertTrue(first_chunk)
            self.assertFalse(process.waited)
            self.assertEqual(first_chunk, response[:len(first_chunk)])
            self.assertEqual(first_chunk + "".join(stream), response)

    def test_advisor_streams_draft_then_returns_validated_explanation(self):
        message = "Please share your OTP to verify the account."
        text = (
            "The message asks you to share an OTP, which is a sensitive secret."
        )
        llm = FakeLlama([text[:24], text[24:]])
        advisor = Advisor(
            lambda _: {
                "ml_analysis": {"predicted_class": "safe", "scam_probability": 0.1},
                "risk_analysis": {
                    "risk_level": "HIGH",
                    "risk_score": 45,
                    "category": "POTENTIAL_SCAM",
                    "indicators": [{
                        "rule": "CREDENTIAL_REQUEST",
                        "reason": "It requests an OTP.",
                        "weight": 45,
                    }],
                },
            },
            llm,
        )

        events = list(advisor.explain_stream(message))

        self.assertEqual(llm.calls, 1)
        self.assertEqual(
            [event["text"] for event in events if event["type"] == "token"],
            [text],
        )
        self.assertEqual(
            events[-1],
            {"type": "complete", "text": text, "source": "llm", "reason": "ok"},
        )

    def test_rejected_streamed_draft_is_replaced_with_template(self):
        advisor = Advisor(
            lambda _: {
                "ml_analysis": {"predicted_class": "scam", "scam_probability": 0.9},
                "risk_analysis": {
                    "risk_level": "HIGH",
                    "risk_score": 45,
                    "indicators": [],
                },
            },
            FakeLlama(["This message is safe and legitimate."]),
        )

        events = list(advisor.explain_stream("Unexpected payment request"))

        self.assertFalse(any(event["type"] == "token" for event in events))
        self.assertEqual(events[-1]["type"], "complete")
        self.assertEqual(events[-1]["source"], "template")
        self.assertTrue(events[-1]["reason"].startswith("rejected:"))

    def test_unsupported_claims_are_not_streamed_for_benign_conversation(self):
        message = "Hey, how are you? Let's catch up later."
        draft = (
            "The system checks found no specific warning signs, but there are some red flags. "
            "The message appears to be a standard promotional offer, but the tone is slightly off. "
            "The language is too casual and informal, which is unusual for a legitimate company. "
            "Additionally, the message asks you to click on a link, a common tactic used by scammers."
        )
        llm = FakeLlama([draft[:100], draft[100:]])
        advisor = Advisor(
            lambda text: {
                "ml_analysis": {"predicted_class": "safe", "scam_probability": 0.05},
                "risk_analysis": assess_sms(text),
            },
            llm,
        )

        explanation = advisor.explain(message)
        self.assertEqual(explanation["source"], "template")
        self.assertEqual(llm.calls, 0)

        events = list(advisor.explain_stream(message))

        self.assertEqual(llm.calls, 0)
        self.assertEqual(
            [event["text"] for event in events if event["type"] == "token"],
            [],
        )
        self.assertEqual(events[-1]["source"], "template")
        self.assertNotIn("red flags", events[-1]["text"].lower())

    def test_stream_endpoint_flushes_token_events(self):
        class StubAdvisor:
            def explain_stream(self, message, lang):
                yield {"type": "token", "text": "Draft "}
                yield {
                    "type": "complete",
                    "text": "Draft explanation.",
                    "source": "llm",
                }

        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(StubAdvisor()))
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            request = Request(
                f"http://127.0.0.1:{server.server_port}/api/explain/stream",
                data=json.dumps({"message": "Test message"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request) as response:
                body = response.read().decode()
                self.assertIn("text/event-stream", response.headers["Content-Type"])
            events = [
                json.loads(line.removeprefix("data: "))
                for line in body.splitlines()
                if line.startswith("data: ")
            ]
            self.assertEqual([event["type"] for event in events], ["token", "complete"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
