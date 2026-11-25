#!/usr/bin/env python3
"""Command-line advisor.  uv run python cli_advisor.py [--lang hi] [--demo] [--no-llm] "message" """
import argparse, sys
from advisory_core import Advisor
from llm_executorch import ExecuTorchLlama
from pipeline_adapter import load_analyzer, selftest

ap = argparse.ArgumentParser()
ap.add_argument("messages", nargs="*")
ap.add_argument("--lang", default="en", choices=["en", "hi"])
ap.add_argument("--demo", action="store_true")
ap.add_argument("--no-llm", action="store_true")
a = ap.parse_args()

llm = None if a.no_llm else ExecuTorchLlama("executorch/cmake-out/examples/models/llama/llama_main",
                                             "spam_llama.pte", "tokenizer.model")
analyzer = load_analyzer(demo=a.demo)
if (problem := selftest(analyzer)):
    print(f"[WARNING] pipeline self-test failed: {problem}", file=sys.stderr)
adv = Advisor(analyzer, llm)
for msg in (a.messages or [l.strip() for l in sys.stdin if l.strip()]):
    r = adv.analyze(msg, a.lang)
    e = adv.explain(msg, a.lang) if r["llm_available"] else r["explanation"]
    print(f"\n=== {r['title']} ===\n{e['text']}   [{e['source']}]\nWhat to do: {r['action']}")
