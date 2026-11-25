# SMS Threat Detector

**SMS Threat Detector** is an offline-first prototype for analyzing suspicious SMS messages and links in an Indian context. Its current interface is branded **Threat Lens**. It combines an SMS scam classifier, explainable message-risk rules, and a phishing-URL model, then presents a deterministic assessment and safe next steps. An optional local LLM can explain the findings; it does not decide the verdict.

> **Status:** Prototype, not a certified fraud detector. The SMS classifier benchmark and URL model evaluations use dataset holdouts, not independent real-world traffic. Do not rely on a “safe” or “not flagged” result as proof that a message or link is safe.

## What is implemented

- **SMS classification:** word and character TF-IDF features with Logistic Regression, trained using the lineage-grouped BSIS scam/safe dataset. The decision threshold is selected on validation data using a scam-precision floor and F2 objective.
- **SMS risk analysis:** offline, explainable rules for credential requests, UPI PIN deception, remote-access requests, KYC/account threats, sensitive-data links, advance-fee rewards, unrealistic income promises, payment pressure, and suspicious URL structure.
- **URL analysis:** an XGBoost phishing classifier using URL structure features. It runs locally and uses a bundled suffix-list snapshot rather than fetching an updated list during prediction.
- **Advisory:** deterministic verdicts and fixed safe-action guidance. Optional ExecuTorch/Llama explanations are constrained to detected evidence and fall back to templates when unavailable or rejected.
- **Interfaces:** a local web dashboard with streaming explanations and an interactive CLI. English and Hindi advisory text are supported.
- **Training-only supplement:** an audited, synthetic Indian SMS dataset can augment training, but it is excluded from BSIS validation and test splits.

The SMS classifier, behavior-based rules, and URL model provide separate signals. Classifier scores and risk scores are not calibrated probabilities, and rule scores are not official RBI/NPCI scores.

## Quick start

The project uses [`uv`](https://docs.astral.sh/uv/) for Python dependency management. Install `uv`, then from the repository root:

```bash
uv sync
```

Train the SMS model used by the current pipeline. The default pipeline expects the generated model at `artifacts_bsis_augmented/bsis_scam_tfidf.joblib`:

```bash
uv run python train_bsis.py \
  --data-dir datasets/raw/bsis/classifier \
  --supplement-csv datasets/raw/bhavya_indian_scam_sms/data/synthetic_audited.csv \
  --output-dir artifacts_bsis_augmented \
  --minimum-scam-precision 0.75
```

Training writes the model, metrics, held-out predictions, and inference benchmark under `artifacts_bsis_augmented/`. To train on BSIS alone, omit `--supplement-csv`. The URL model and its feature list are already in `url_phishing/models/`.

Start the web dashboard:

```bash
uv run python app_server.py
```

Open <http://127.0.0.1:8080>. If the ExecuTorch runner or Llama files are missing, the app uses its built-in template explanation. For UI work without the trained SMS model, start the demo analyzer instead:

```bash
uv run python app_server.py --demo
```

The demo analyzer is a simple stand-in, not the real detection pipeline. To make the dashboard reachable from another device on the same trusted network, use `--host 0.0.0.0`; the server has no authentication, so do not expose it to an untrusted network.

Run the CLI:

```bash
uv run python cli_advisor.py --no-llm "Your account will be blocked. Share your OTP now."
uv run python cli_advisor.py --no-llm --lang hi "आपका खाता बंद हो जाएगा।"
```

The full CLI pipeline also requires the trained SMS artifact. Use `--demo` for the stand-in analyzer; omit `--no-llm` only if the optional local ExecuTorch setup is available. To run the Python tests:

```bash
uv run python -m unittest discover -s tests
```

## Optional ExecuTorch explanation backend

The advisory layer works without an LLM. To enable local generated explanations, provide the ExecuTorch `llama_main` executable, a compatible `.pte` model, and its tokenizer. Defaults are:

```text
executorch/cmake-out/examples/models/llama/llama_main
spam_llama.pte
tokenizer.model
```

Override the runner and model paths with `app_server.py` options, for example:

```bash
uv run python app_server.py \
  --llama-main /path/to/llama_main \
  --model /path/to/model.pte \
  --tokenizer /path/to/tokenizer.model
```

These binaries and model files are not included. The LLM only writes an explanation; the advisor determines the verdict and recommended action independently.

## Repository map

```text
.
├── app_server.py              # Local web app and JSON/SSE endpoints
├── static/                    # Threat Lens dashboard
├── cli_advisor.py             # Interactive command-line advisor
├── advisory_core.py           # Verdicts, localized guidance, LLM guardrails
├── pipeline_adapter.py        # Connects the advisor to the SMS pipeline
├── sms_pipeline.py            # SMS model + risk engine + URL model
├── sms_risk_engine.py         # Explainable offline SMS heuristics
├── train_bsis.py              # BSIS model training and evaluation
├── url_phishing/              # URL training, prediction, model and results
├── datasets/
│   ├── raw/                   # Source datasets; preserve originals
│   ├── README.md
│   └── DATASET_MANIFEST.json  # Current source inventory/status
└── tests/
```

`train_sms_tfidf.py` is an earlier ham/spam baseline experiment; the current integrated pipeline uses the scam/safe model produced by `train_bsis.py`.

## Data and evaluation notes

- BSIS is a **synthetic, multilingual** classifier benchmark. Its lineage-grouped split makes the experiment more reproducible, but results do not establish real-world fraud-detection performance.
- The Bhavya Indian SMS supplement is synthetic and partially reviewed. It is training-only and must not be used to claim independent validation.
- The URL evaluation is a random holdout from the same URL dataset, not a time-separated or independent live-web evaluation. See `url_phishing/results/evaluation.json`.
- Review `datasets/DATASET_MANIFEST.json` for which source files are present. Preserve files in `datasets/raw/`; retain source labels and provenance when preparing any new data.
- Keep “spam” and “scam” distinct: promotional or unsolicited messages are not necessarily fraudulent.

## Safety and privacy

- Analyze messages locally where possible. Avoid retaining SMS text unless necessary and appropriately consented.
- Never automatically open links, install APKs, grant remote access, approve UPI collect requests, or initiate payments.
- Verify requests using an official app or independently obtained contact details; sender names and URLs can be spoofed.
- Use synthetic examples for testing. Do not include real OTPs, PINs, passwords, or personal data.
- Treat all results as decision support, not a guarantee or substitute for official reporting channels.

## References

- [BSIS dataset](https://huggingface.co/datasets/harshcasper/bsis)
- [Bhavya Indian scam SMS synthetic-audited dataset](https://huggingface.co/datasets/bhavya2910/indian-scam-sms-synthetic-audited)
- [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection)
- [IIIT-D SMS Dataset information](https://www.iiitd.ac.in/)
- [RBI](https://www.rbi.org.in/)
- [NPCI UPI](https://www.npci.org.in/what-we-do/upi/product-overview)
- [uv documentation](https://docs.astral.sh/uv/)
