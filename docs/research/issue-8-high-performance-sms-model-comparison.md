# Pretrained SMS/Scam Model and Dataset Comparison

Issue: #8  
Scope: research candidates for a Raspberry Pi 5 CPU-only SMS scam detector. This note does not select a final model or report Pi latency because actual Pi measurements are not available yet.

## Recommended comparison set

### 1. MiniLM-L6 SMS spam classifier

- Model: `hari-krishna-ai/sms-spam-minilm-l6`
- Architecture: 22.7M-parameter MiniLM-L6 sequence classifier
- License: Apache-2.0
- Revision: `b0abe55e667e20df902e969b590ee5cf7677d788`
- Assets: Safetensors, ONNX FP32, ONNX INT8, UCI-only and UCI-plus-India variants
- Languages in the model card: English
- Training data: UCI SMS Spam Collection, plus `CloveAI/india-spam-sms` for the mixed/root variant
- UCI held-out: 516 messages after deduplication and a 10% held-out split
- Reported UCI spam F1: 0.9355 for the mixed model; 0.9603 for the UCI-only model
- Reported India-synthetic held-out spam F1: 0.9991 for the mixed model
- Caveat: the author explicitly states the Indian dataset is synthetic and generated from templates; 0.9991 should not be treated as real-world Indian SMS accuracy.
- Export advantage: the repository already provides ONNX and INT8 ONNX assets, making this one of the strongest candidates for an edge benchmark.

Sources:
- https://huggingface.co/hari-krishna-ai/sms-spam-minilm-l6
- https://huggingface.co/datasets/CloveAI/india-spam-sms

### 2. BERT-Tiny SMS spam classifier

- Model: `mrm8488/bert-tiny-finetuned-sms-spam-detection`
- Architecture: approximately 4.39M parameters
- Revision: `012e2681d92fa3f9be2ea08bd31cfa1db14599d2`
- Dataset tag: `sms_spam`
- Reported validation accuracy: 0.98
- Language: English
- Pi relevance: smallest and fastest candidate in this shortlist, but it is important to re-run the full held-out benchmark rather than relying on the model card's single accuracy number.
- Caveat: license and complete reproducibility information are not clearly documented in the model card; verify repository files and base-model license before deployment.

Sources:
- https://huggingface.co/mrm8488/bert-tiny-finetuned-sms-spam-detection
- https://huggingface.co/datasets/ucirvine/sms_spam

### 3. DistilBERT SMS spam classifier

- Model: `omarash/sms-spam-distilbert`
- Architecture: 66.95M-parameter DistilBERT sequence classifier
- License: Apache-2.0 for the model; UCI dataset CC BY 4.0
- Revision: `84189df518a68a53843822142113113e61d19b21`
- Dataset: UCI SMS Spam Collection
- Fixed protocol: 4,459 train / 1,115 held-out; stratified seed 42
- Reported results: 99.10% accuracy, 0.9655 spam F1, 0.9929 spam precision, 0.9396 spam recall
- Baseline comparison: TF-IDF word unigrams/bigrams plus logistic regression, spam F1 0.9488
- Caveat: epoch selection used the held-out evaluation split, so the model card's split is not an untouched final test set.
- English-only and dated dataset; no evidence of Hindi, Hinglish, or Indian scam behavior.

Sources:
- https://huggingface.co/omarash/sms-spam-distilbert
- https://huggingface.co/datasets/ucirvine/sms_spam

### 4. DistilBERT Scam/Phishing detector

- Model: `rehan-ml/scamshield-scam-detector`
- Architecture: 66.95M-parameter DistilBERT
- License: MIT
- Revision: `0aca58d73bc34d17b247496aa5216fd04aaa39aa`
- Task: safe versus scam across SMS, email, job offers, and similar text
- Training data: UCI SMS, employment scam data, and a synthetic contrastive dataset
- Reported held-out results: 98.5% accuracy, 0.944 precision, 0.833 recall, 0.885 F1
- Edge claim: model card describes browser/edge/ONNX usage, but the repository files available from the card do not establish Pi latency or an ONNX export.
- Caveat: English-only and broader than SMS; lower recall than the F1 aggregate suggests possible missed scams.

Sources:
- https://huggingface.co/rehan-ml/scamshield-scam-detector
- https://huggingface.co/datasets/ucirvine/sms_spam

### 5. BERT SMS spam classifier

- Model: `niru-nny/SMS_Spam_Detection`
- Architecture: 109.48M-parameter BERT
- License: MIT
- Revision: `5b735d822ca661d5acc403213bf8e25e9bb38231`
- Dataset: UCI SMS Spam Collection
- Reported results: 99.16% accuracy, 97.30% precision, 96.43% recall, 96.86% F1
- Protocol: model card reports an 80/20 split but not enough detail for a reproducible split
- Pi relevance: likely too large as an initial edge candidate compared with BERT-Tiny or MiniLM-L6.
- English-only and limited card provenance.

Source: https://huggingface.co/niru-nny/SMS_Spam_Detection

### 6. RoBERTa email/SMS classifier

- Model: `coconutsc/roberta_email_sms_spam_classifier`
- Architecture: approximately 124.65M parameters
- Base model license: likely MIT for RoBERTa-base, but verify every release file
- Revision: `9316406e3df941878670276bda9579576d130326`
- Reported evaluation: F1 0.9869, accuracy 0.9890, precision 0.9858, recall 0.9879
- Training/evaluation dataset is not identified in the model card.
- Pi relevance: substantially larger and slower than MiniLM or BERT-Tiny; exclude unless it wins held-out comparison after a rigorous protocol.

Source: https://huggingface.co/coconutsc/roberta_email_sms_spam_classifier

### 7. Multilingual BERT Korean SMS classifier

- Model: `blockenters/sms-spam-classifier`
- Architecture: approximately 177.85M-parameter multilingual BERT
- License: Apache-2.0
- Base model: `google-bert/bert-base-multilingual-cased`
- Revision: `b588a1258a401704a1aa4d07584ba53607a8ed25`
- Training card: custom processed SMS data, 80/20 split, one epoch
- Language evidence: Korean plus claims of multilingual support
- No validated metrics or public training dataset in the card
- Pi relevance: poor parameter-to-evidence ratio; maintain only as a multilingual control candidate, not an India-specific candidate.

Sources:
- https://huggingface.co/blockenters/sms-spam-classifier
- https://huggingface.co/google-bert/bert-base-multilingual-cased

### 8. India-named DistilBERT classifier

- Model: `xixama/indian_sms_spam_classifier`
- Architecture: 66.96M-parameter DistilBERT
- License: Apache-2.0
- Revision: `b19cc7dd4e2c4f8c18005b7263ac18cf228ffab1`
- Reported accuracy: 99.34%
- Model card says “Indian news spam classifier”; the training dataset is `None/unknown`, and intended use and limitations are incomplete.
- Pi relevance: same size as DistilBERT; reject as a leading candidate unless data provenance and reproducible labels can be established.

Source: https://huggingface.co/xixama/indian_sms_spam_classifier

### 9. Generic DistilBERT SMS classifier with incomplete card

- Model: `priya145/email_sms_spam_classifier_finetuned`
- Architecture: 66.96M-parameter DistilBERT
- Revision: `a26b1af82c78f6bd54de926814324a5b28d9ba37`
- Model card is an incomplete autogenerated card: no verified dataset, license, metrics, split, or limitations.
- Pi relevance: exclude unless repository provenance is established.

Source: https://huggingface.co/priya145/email_sms_spam_classifier_finetuned

## Highest-priority datasets

### UCI SMS Spam Collection

- Source: `ucirvine/sms_spam`
- 5,574 English real SMS messages
- 4,827 ham / 747 spam
- Monolingual English
- Benchmark-only role: use fixed stratified splits and report spam-class F1, precision, recall, confusion matrices, and macro/balanced metrics
- Dataset card/license: license field is unknown/undefined on the Hugging Face card; source documentation points to the UCI record and CC BY 4.0 in newer model cards. Verify the exact dataset license before redistribution.

Source: https://huggingface.co/datasets/ucirvine/sms_spam

### Synthetic India SMS dataset

- Source: `CloveAI/india-spam-sms`
- Approximately 20,000 rows
- Contains template-generated Indian bank, Aadhaar, telecom, bill, parcel, UPI, loan, and promotional patterns
- Strong for systematic domain-shift experiments and Indian terminology/hard-negative generation
- Not sufficient alone to prove real-world Indian SMS accuracy

Source: https://huggingface.co/datasets/CloveAI/india-spam-sms

### Hinglish scam text dataset

- Source: `bolewara/hinglish-scam-text-dataset`
- English and Hinglish financial fraud/scam text
- Card reports approximately 3,000 English benign, 700 English scam, 35 Hinglish scam, and 28 Hinglish benign examples
- Useful for code-mixed testing, but the dataset viewer currently reports malformed JSON/split parsing, and the number of handcrafted Hinglish rows is small
- Separate this from its SMS claims and verify source files before download

Source: https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset

### Indian multilingual scam message dataset

- Source: `karanverma19/Indian_Multilingual_Scam_Message_Dataset`
- 120 realistic SMS/text messages in English, Hindi, and Hinglish
- Apache-2.0
- Useful as a small curated validation set, not as a training or population-representative benchmark
- The rows appear templated and include repeated urgency phrases; inspect leakage and balance before use

Source: https://huggingface.co/datasets/karanverma19/Indian_Multilingual_Scam_Message_Dataset

### Indian cyber-scam Hinglish communication dataset

- Source: `ysangam/Indian_Cyber_Scam_PhoneCall_Hinglish_Dataset`
- Approximately 10,000 rows of scam/non-scam communication, including SMS, call, WhatsApp, and other text styles
- English/Hindi/Hinglish
- Useful for broader Indian scam language, but it is not exclusively SMS and license/curation provenance needs verification

Source: https://huggingface.co/datasets/ysangam/Indian_Cyber_Scam_PhoneCall_Hinglish_Dataset

## Recommended model-comparison matrix

For the first benchmark, include these candidates:

1. TF-IDF word 1–2 grams + char 3–5 grams plus logistic regression: transparent baseline.
2. `mrm8488/bert-tiny-finetuned-sms-spam-detection`: absolute minimum-size control.
3. `hari-krishna-ai/sms-spam-minilm-l6`: primary compact candidate and existing ONNX/INT8 assets.
4. `omarash/sms-spam-distilbert`: strongest reproducible English UCI fine-tune found in this pass.
5. `rehan-ml/scamshield-scam-detector`: broader scam candidate that includes synthetic contrastive examples.
6. One robust multilingual base or candidate: `blockenters/sms-spam-classifier` only as a control because the public card provides weak provenance.

Do not include `xixama/indian_sms_spam_classifier` or `priya145/email_sms_spam_classifier_finetuned` as serious finalists until training data, label mapping, license, and reproducible evaluation are established.

## Required benchmark protocol

Use one fixed protocol for every candidate:

- Recreate fixed deduplicated, leakage-checked UCI train/validation/test splits.
- Keep threshold tuning off the final test split.
- Evaluate UCI, the synthetic India corpus, and curated Indian-English/Hindi/Hinglish hard negatives separately.
- Report confusion matrices, class-wise precision/recall/F1, macro F1, balanced accuracy, and PR-AUC.
- Use identical token limits and no candidate-specific prompt engineering.
- Test FP32 Transformers, then ONNX FP32/INT8 where available.
- Measure 5 cold starts and at least 20 warm runs on Raspberry Pi 5 with networking disabled.
- Report median/p95 latency, peak RSS, model/package size, CPU utilization, OS/runtime/Python versions, and thermal conditions.
- Treat any mixed/India dataset as a domain-shift diagnostic, not as evidence of real-world Indian performance.

## Initial selection hypothesis

The likely first-choice edge candidate is `hari-krishna-ai/sms-spam-minilm-l6` because it is compact, has reproducible UCI and India self-reported comparisons, and already exposes ONNX/INT8 assets. However, the TF-IDF baseline may remain more accurate on UCI and is far cheaper. The final choice must be made only after a single fixed benchmark and actual Pi inference measurements.
