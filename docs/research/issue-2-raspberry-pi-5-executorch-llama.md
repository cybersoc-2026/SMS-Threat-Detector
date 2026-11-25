# Issue #2 research: small Llama advisory inference on Raspberry Pi 5 with ExecuTorch

**Research date:** 2026-11-09  
**Scope:** Determine whether a small Llama-family model can provide local advisory inference on a Raspberry Pi 5 using ExecuTorch. This note is evidence and a test plan, not a performance claim or legal opinion.

## Executive conclusion

The strongest candidate is **Llama 3.2 1B Instruct**, exported to ExecuTorch and run through its XNNPACK CPU backend with the official 4-bit Arm-oriented quantization recipe. Meta explicitly describes the 1B/3B text-only models as suitable for constrained/on-device use, and ExecuTorch documents Llama 3.2 1B/3B export and XNNPACK execution. A Raspberry Pi 5 has a 2.4 GHz quad-core 64-bit Arm Cortex-A76, so the instruction set and CPU-backend direction are technically aligned.

There is **no authoritative first-party benchmark found for this exact model/runtime/device combination**. ExecuTorch's published measurements are on phones, not Raspberry Pi 5. Treat Pi feasibility, throughput, latency, thermal behavior, and advisory quality as hypotheses to measure.

## Candidate models and legal/technical fit

| Candidate | Technical assessment | License/use caveat |
|---|---|---|
| **Llama 3.2 1B Instruct** | Recommended first experiment. Text-only, 1.23B parameters, 128k context in the original model card; ExecuTorch provides a 1B recipe and 4-bit variants. Use a bounded context on Pi rather than the maximum context. | Governed by Meta's custom Llama 3.2 Community License and Acceptable Use Policy; not an unrestricted open-source/OSI license. Review and retain the license, attribution, and any required “Built with Llama” notice before distribution. |
| **Llama 3.2 3B Instruct** | Officially supported by ExecuTorch, but materially larger. The published SpinQuant `.pte`/RSS figures already exceed the practical memory budget of many Pi configurations; use only on a high-RAM Pi after measuring. | Same custom license/policy. |
| **Llama 3.1 8B / Llama 3 8B** | ExecuTorch supports them, but the example says 8B may require at least 32 GB RAM and reports phone tests. Not a sensible Pi 5 baseline. | Same family of Meta license/policy obligations; verify the exact model's terms. |
| **Llama 2 7B** | ExecuTorch example support exists, but size/age make it a poor fit for Pi 5 advisory inference. | Separate Llama 2 license and Acceptable Use Policy; do not assume Llama 3.2 terms apply. |

Meta's Llama 3.2 model card identifies the 1B and 3B models as text-in/text-out, lists Hindi among eight officially supported languages, and names mobile assistants, retrieval, summarization, and constrained on-device use cases. It also says use must comply with applicable law, the Community License, and the Acceptable Use Policy. Sources: [Llama 3.2 model card — model information and intended use](https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/MODEL_CARD.md#model-information), [Community License](https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/LICENSE), [Acceptable Use Policy](https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/USE_POLICY.md).

“Advisory” must remain decision support, not an unreviewed claim of professional, legal, medical, or cybersecurity authority. The model card and policy do not prove that a particular advisory application is permitted; obtain a product/legal review for the actual deployment and jurisdiction.

## ExecuTorch conversion and runtime evidence

The official ExecuTorch LLM Export API describes the complete path: instantiate model, apply source transforms/quantization, export through EXIR/Edge, delegate to a backend, and serialize a `.pte` file. Its supported-model list includes Llama 2, Llama 3, Llama 3.1, and Llama 3.2 (1B/3B). Source: [ExecuTorch LLM Export API](https://github.com/pytorch/executorch/blob/main/extension/llm/export/README.md).

The official Llama example:

* supports Llama 3.2 1B/3B (including quantized variants);
* uses XNNPACK for CPU acceleration;
* documents BF16 and 4-bit Arm-oriented exports;
* builds a C++ runner with model, tokenizer, prompt, maximum output tokens, CPU-thread, and warm-up controls.

Source: [ExecuTorch Llama example](https://github.com/pytorch/executorch/blob/main/examples/models/llama/README.md). The runtime library documents `.pte` loading and the export manager's `to_backend()`/`to_executorch()`/`save_to_pte()` flow: [ExecuTorch LLM extension](https://github.com/pytorch/executorch/blob/main/extension/llm/README.md).

For Raspberry Pi's CPU-only path, use XNNPACK rather than assuming a Pi-specific accelerator. XNNPACK is the relevant ExecuTorch CPU backend, but a Pi-specific validation result was not found in the official sources. The Pi build must therefore be treated as an ARM64/Linux port and validated on-device.

## Quantization and memory constraints

Meta states that the Llama 3.2 quantization scheme was designed with ExecuTorch and an Arm CPU backend in mind:

* transformer-block linear weights: 4-bit groupwise, group size 32;
* transformer-block activations: 8-bit per-token dynamic;
* classification weights: 8-bit per-channel, with 8-bit dynamic activations;
* embedding: 8-bit per-channel.

Source: [Meta model card — quantization scheme](https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/MODEL_CARD.md#quantization-scheme).

ExecuTorch warns that ordinary PTQ can reduce Llama 3.2 1B/3B accuracy and documents SpinQuant and QAT+LoRA alternatives. Its OnePlus 12 table reports for 1B:

* BF16: 2,358 MiB `.pte`, 3,185 MiB RSS;
* SpinQuant: 1,083 MiB `.pte`, 1,921 MiB RSS;
* QAT+LoRA: 1,127 MiB `.pte`, 2,255 MiB RSS.

These are **reference measurements on a OnePlus 12, not Pi limits**. They exclude the Pi OS baseline, allocator behavior, prompt/KV-cache growth, and thermal effects. Source: [ExecuTorch Llama quantization and performance](https://github.com/pytorch/executorch/blob/main/examples/models/llama/README.md#quantization).

Recommendation: start with the official 1B SpinQuant artifact if available; otherwise reproduce the documented export recipe rather than substituting an unrelated 4-bit format. Keep context and `max_new_tokens` bounded, measure peak RSS, and leave headroom for the OS and application.

## Tokenizer and packaging requirements

ExecuTorch's LLM extension currently documents SentencePiece and Tiktoken support. It identifies BPE/SentencePiece handling and Tiktoken support for Llama 3/Llama 3.1; the Llama example instructs users to obtain the matching `tokenizer.model` alongside model files. Sources: [ExecuTorch tokenizer/runtime documentation](https://github.com/pytorch/executorch/blob/main/extension/llm/README.md#tokenizer), [Llama preparation instructions](https://github.com/pytorch/executorch/blob/main/examples/models/llama/README.md#step-2-prepare-model).

The tokenizer must match the exact checkpoint/export (base versus instruct, vocabulary, special tokens, and chat template). Package and checksum the `.pte`, tokenizer artifact, and model metadata together. A successful `.pte` load with a mismatched tokenizer is not a valid inference result.

## Raspberry Pi 5 constraints

Raspberry Pi's official product brief specifies a 2.4 GHz quad-core 64-bit Arm Cortex-A76 CPU, 512 KB L2 cache per core, and a 2 MB shared L3 cache. Source: [Raspberry Pi 5 product brief (official PDF)](https://pip.raspberrypi.com/documents/RP-008348-DS-3-raspberry-pi-5.pdf) (the official site currently redirects this document to a newer product-brief revision).

Implications:

1. Use a 64-bit Raspberry Pi OS/userspace and an ARM64 ExecuTorch build.
2. Expect CPU-only execution unless a separately supported accelerator/backend is demonstrated; do not infer GPU/NPU acceleration from the board's video or display features.
3. Use active cooling and record governor/throttling state. Sustained decode is a thermal workload.
4. Benchmark 1, 2, and 4 worker threads; more threads do not guarantee better latency.
5. Test the actual RAM SKU and reserve memory for the OS, application, tokenizer, and KV cache.

## Reproducible measurement plan

### Fixed environment record

Record Pi model/RAM, Raspberry Pi OS image and kernel, CPU governor, cooling, power supply, ExecuTorch commit, PyTorch/torchao versions, compiler/toolchain, model/tokenizer URLs and SHA-256 checksums, export configuration, and git revision of the harness.

### Export and correctness

1. Download Llama 3.2 1B Instruct and its matching tokenizer only from Meta's official distribution or the authorized model repository; record acceptance of the applicable terms.
2. Export with the official ExecuTorch Llama tooling, XNNPACK enabled, KV cache enabled, and the documented 4-bit SpinQuant (then QAT+LoRA, if available) configuration.
3. Run a deterministic smoke test with a fixed prompt, fixed sampling settings (temperature 0/greedy where supported), and fixed output limit. Verify special-token handling and repeatability.
4. Compare a small golden set against the reference implementation before measuring speed.

### Performance cases

For each of 1/2/4 CPU threads, run prompt lengths **32, 128, 512** and generation lengths **32, 128**. Separate cold start from warm start. Perform one warm-up, then at least five measured repetitions per case.

Capture:

* time to first token;
* prefill tokens/second;
* decode tokens/second;
* end-to-end latency;
* peak RSS and `.pte` size;
* CPU temperature, frequency, throttling flags, and failures;
* output correctness, truncation, and tokenizer errors.

Report median and p95, not only a best run. Repeat a representative case after a sustained workload to expose thermal throttling. Compare SpinQuant and QAT+LoRA only when the artifacts use the same tokenizer, context limit, prompt, and sampling settings.

### Advisory-quality gate

Create a fixed, reviewed corpus of benign advisory prompts and expected safety constraints. Score factuality, unsupported certainty, refusal behavior, language coverage (including Hindi if required), and escalation recommendations separately from speed. Do not treat throughput as evidence that the advice is safe or legally appropriate.

## Evidence limits and unresolved questions

* The sources prove model-family support, export/runtime mechanisms, quantization intent, and Pi 5 CPU specifications.
* They do **not** prove acceptable Pi 5 throughput, real-time behavior, or advisory quality.
* The ExecuTorch published performance table is Android OnePlus 12 data; it must not be copied as Pi performance.
* Exact support for the latest ExecuTorch commit, ARM64 build flags, and SpinQuant artifact availability can change; pin a commit and record it in the experiment.
* Meta's custom license and policy require deployment-specific review. This note is not legal advice.

