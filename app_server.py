#!/usr/bin/env python3
"""Local web app for the SMS advisor 

  uv run python app_server.py                 # real pipeline + ExecuTorch Llama on the Pi
  uv run python app_server.py --demo          # stub analyzer, no models needed (UI testing)
  uv run python app_server.py --host 0.0.0.0  # reachable from your phone on the same Wi-Fi 
"""
import argparse, json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import perf_counter

from advisory_core import Advisor, SUPPORTED_LANGS
from llm_executorch import ExecuTorchLlama
from pipeline_adapter import load_analyzer, selftest

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "application/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}
MAX_BODY, MAX_MSG = 16_384, 2_000
SEC_HEADERS = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
               "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
               "Cache-Control": "no-store"}

def make_handler(advisor: Advisor):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body: bytes, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SEC_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def _stream_explanation(self, message, lang):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("X-Accel-Buffering", "no")
            for key, value in SEC_HEADERS.items():
                self.send_header(key, value)
            self.end_headers()

            try:
                for event in advisor.explain_stream(message, lang):
                    payload = json.dumps(event, ensure_ascii=False)
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception:
                payload = json.dumps({"type": "error", "error": "stream_failed"})
                try:
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
            finally:
                self.close_connection = True

        def do_GET(self):
            if self.path in STATIC:
                name, ctype = STATIC[self.path]
                with open(os.path.join(HERE, "static", name), "rb") as f:
                    return self._send(200, f.read(), ctype)
            if self.path == "/api/health":
                return self._json(200, {"ok": True, "llm_available": bool(advisor.llm and advisor.llm.available())})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path not in ("/api/analyze", "/api/explain", "/api/explain/stream"):
                return self._json(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n <= 0 or n > MAX_BODY:
                    return self._json(413, {"error": "bad_size"})
                data = json.loads(self.rfile.read(n).decode("utf-8"))
                msg = str(data.get("message", "")).strip()
                lang = data.get("lang", "en")
                if lang not in SUPPORTED_LANGS:
                    lang = "en"
                if not msg:
                    return self._json(400, {"error": "empty"})
                if len(msg) > MAX_MSG:
                    return self._json(400, {"error": "too_long"})
                if self.path == "/api/explain/stream":
                    return self._stream_explanation(msg, lang)
                fn = advisor.analyze if self.path == "/api/analyze" else advisor.explain
                started = perf_counter()
                result = fn(msg, lang)
                if self.path == "/api/analyze":
                    result["analysis_time_ms"] = round((perf_counter() - started) * 1000, 2)
                return self._json(200, result)
            except (ValueError, UnicodeDecodeError):
                return self._json(400, {"error": "bad_request"})
            except Exception:
                return self._json(500, {"error": "internal"})      # never echo message content

        def log_message(self, *a):          # privacy: do not log requests
            pass
    return H

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--demo", action="store_true", help="use stub analyzer instead of sms_pipeline.py")
    ap.add_argument("--llama-main", default="executorch/cmake-out/examples/models/llama/llama_main")
    ap.add_argument("--model", default="spam_llama.pte")
    ap.add_argument("--tokenizer", default="tokenizer.model")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--num-bos", type=int, default=None, help="leave unset: the prompt already starts with <|begin_of_text|> (adding both = double BOS)")
    args = ap.parse_args()

    llm = ExecuTorchLlama(args.llama_main, args.model, args.tokenizer, threads=args.threads, num_bos=args.num_bos)
    if not llm.available():
        print("[warn] Llama files not found - explanations will use the built-in template.")
        for p in llm.missing():
            print(f"         missing: {p}")
        print(f"         (paths are relative to the current directory: {os.getcwd()})")
        print("         pass absolute paths with --llama-main, --model and --tokenizer")
    analyzer = load_analyzer(demo=args.demo)
    problem = selftest(analyzer)
    if problem:
        print(f"[WARNING] pipeline self-test failed: {problem}")
    advisor = Advisor(analyzer, llm)
    if args.host != "127.0.0.1":
        print("[warn] Listening on the network with no authentication. Use only on a trusted home network.")
    srv = ThreadingHTTPServer((args.host, args.port), make_handler(advisor))
    print(f"SMS Advisor running at http://{args.host}:{args.port}")
    srv.serve_forever()

if __name__ == "__main__":
    main()
