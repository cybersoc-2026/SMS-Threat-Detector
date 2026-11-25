---
language:
- hi
- en
- bn
- mr
- ta
- te
- gu
- kn
- ml
- or
- pa
- ur
- as
- brx
- doi
- kok
- ks
- mai
- mni
- ne
- sa
- sat
- sd
license: other
configs:
- config_name: classifier
  data_files:
  - split: train
    path: classifier/train-*.parquet
  - split: validation
    path: classifier/validation-*.parquet
  - split: test
    path: classifier/test-*.parquet
- config_name: chatml
  data_files:
  - split: train
    path: chatml/train-*.parquet
  - split: validation
    path: chatml/validation-*.parquet
  - split: test
    path: chatml/test-*.parquet
---

# BSIS: Indian Scam Message Detection Dataset

Synthetic training data for on-device scam detection on Indian SMS and
WhatsApp traffic. Every row was produced by the BSIS red-team/blue-team
simulation arena: a scammer (or a genuine sender) talks to a simulated victim
in an Indian language, and a privacy-preserving defender scores each message.
Labels come from deterministic Rust logic over ground truth, never from
model opinion. This dataset is synthetic. It contains no real user
messages, and no real personal data.

## Splits

| config | train | validation | test |
|---|---|---|---|
| classifier | 32858 | 2148 | 1883 |
| chatml | 28957 | 1905 | 1607 |

Splits are grouped by lineage. All mutated generations of one scenario stay
in the same split, so no adversarial sibling leaks across train, validation
or test.

## Label balance (classifier)

| label | rows |
|---|---|
| 0 (safe until this round) | 14598 |
| 1 (scam detectable at this round) | 22291 |

Label 1 marks the sender turns from which a careful human could tell the
message is a scam (judge `earliest_detectable_round`). Earlier turns of the
same scam carry label 0 and teach the detector not to false-alarm during
grooming.

## Languages

All 23 Sarvam-supported Indian languages: 22 Scheduled languages plus Indian
English. Odia uses the `od-IN` code.

| language | train | validation | test |
|---|---|---|---|
| as-IN | 1017 | 88 | 89 |
| bn-IN | 2322 | 144 | 153 |
| brx-IN | 893 | 83 | 61 |
| doi-IN | 882 | 72 | 58 |
| en-IN | 1866 | 135 | 118 |
| gu-IN | 1309 | 83 | 73 |
| hi-IN | 4654 | 257 | 224 |
| kn-IN | 1371 | 64 | 68 |
| kok-IN | 905 | 69 | 60 |
| ks-IN | 857 | 62 | 51 |
| mai-IN | 890 | 76 | 56 |
| ml-IN | 1233 | 48 | 72 |
| mni-IN | 796 | 73 | 50 |
| mr-IN | 2208 | 109 | 101 |
| ne-IN | 877 | 70 | 51 |
| od-IN | 1139 | 78 | 25 |
| pa-IN | 1315 | 87 | 67 |
| sa-IN | 859 | 75 | 45 |
| sat-IN | 917 | 77 | 59 |
| sd-IN | 1057 | 83 | 63 |
| ta-IN | 2117 | 127 | 128 |
| te-IN | 2103 | 136 | 142 |
| ur-IN | 1271 | 52 | 69 |

## Vectors

Nine scam playbooks grounded in RBI BE(A)WARE and I4C advisories, plus four
hard negatives (genuine senders). Hard negatives make up roughly a quarter of
lineages, so the detector learns not to flag ordinary bank alerts, doorstep
delivery OTP requests, bill reminders and family messages.

| vector | train | validation | test |
|---|---|---|---|
| digital_arrest | 3077 | 117 | 270 |
| fake_courier_customs | 2836 | 127 | 114 |
| fake_customer_care | 3227 | 233 | 232 |
| kyc_utility_panic | 2568 | 96 | 166 |
| legit_bank_alert | 1646 | 108 | 66 |
| legit_delivery_otp | 1485 | 71 | 63 |
| legit_electricity_reminder | 2025 | 98 | 73 |
| legit_family_transfer | 1700 | 108 | 107 |
| predatory_loan_app | 2472 | 349 | 94 |
| qr_code_refund_trap | 3346 | 237 | 145 |
| social_friend_emergency | 2813 | 237 | 105 |
| upi_collect_trap | 2771 | 136 | 197 |
| whatsapp_stock_task | 2892 | 231 | 251 |

## Schema

### classifier

- `text` (string): the message window, all sender turns up to and including
  the current one, prefixed `SENDER:` / `RECIPIENT:`.
- `label` (int64): 1 if the scam is detectable at this round, else 0.
- `language` (string): BCP-47 code, for example `hi-IN` or `od-IN`.
- `script_mode` (string): `native_script` or `romanized_codemix`.
- `vector` (string): the scam playbook or legitimate scenario name.
- `round` (int64): the sender turn number.
- `lineage_id` (string): UUIDv5 of the scenario lineage. Rows sharing a
  lineage belong to the same conversation family.
- `hard_example` (bool): the defender missed, was late, or false-alarmed.

### chatml

- `messages` (list of {role, content}): a three-message conversation:
  a short detector system prompt, the user window, and a strict-JSON
  assistant reply with `scam_probability`, `tactics` and `warning`.

Positive windows without an agreeing on-device warning are excluded from
chatml and kept in classifier only, so the assistant target never invents
a warning.

## Provenance and safety

- Synthetic only. Generated on the Sarvam Token Factory platform with
  red-team prompts restricted to placeholders: `+91-98XXX-XXXXX`,
  `http://example-<word>.invalid`, `name@fakeupi`, `XXXX XXXX 1234`.
- Every generated message passed a regex PII scrubber before storage, and
  this package re-checks each exported row for raw Indian mobile numbers,
  Aadhaar patterns, PAN patterns and non-`.invalid` URLs. The check passes
  with zero hits.
- A deterministic script check rejected conversations written in the wrong
  script before verification: Romanized rows stay ASCII, native rows match
  the expected Unicode block per language.
- Real, anonymized evaluation messages are kept in a separate held-out set
  and are not part of this package.

## Use

```python
from datasets import load_dataset

dataset = load_dataset("harshcasper/bsis", "classifier")
```

## License

This dataset is released for research and educational use in scam
detection and cyber-safety training. It is synthetic and carries no
warranty. Do not use it to contact anyone or to send any message. If you
need a different license, open an issue in the source repository.
