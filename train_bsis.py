#!/usr/bin/env python3
"""Train and benchmark an on-device scam classifier on the BSIS dataset."""

from __future__ import annotations

import argparse
import json
import time
import unicodedata
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    fbeta_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import FeatureUnion, Pipeline


SEED = 42
REQUIRED_COLUMNS = {
    "text",
    "label",
    "language",
    "script_mode",
    "vector",
    "round",
    "lineage_id",
    "hard_example",
}


def clean_text(value: object) -> str:
    if pd.isna(value):
        return ""
    value = unicodedata.normalize("NFKC", str(value))
    return " ".join(value.split()).strip()


def load_split(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"BSIS split not found: {path}")
    frame = pd.read_parquet(path)
    missing = REQUIRED_COLUMNS - set(frame.columns)
    if missing:
        raise ValueError(f"{path}: missing required columns: {sorted(missing)}")
    frame = frame.copy()
    frame["text"] = frame["text"].map(clean_text)
    frame = frame[
        frame["text"].str.len().gt(0)
        & frame["label"].isin([0, 1])
    ].copy()
    frame["label"] = frame["label"].astype(int)
    frame["normalized_text"] = frame["text"].str.casefold().str.strip()
    return frame.reset_index(drop=True)


def load_supplement(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Supplement CSV not found: {path}")
    frame = pd.read_csv(path)
    required = {"text", "label", "language", "row_id", "audit_action"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"{path}: missing required columns: {sorted(missing)}")
    frame = frame.copy()
    frame["text"] = frame["text"].map(clean_text)
    frame["label"] = frame["label"].map(
        {"safe": 0, "scam": 1}
    )
    frame = frame[
        frame["text"].str.len().gt(0)
        & frame["label"].notna()
    ].copy()
    frame["label"] = frame["label"].astype(int)
    frame["normalized_text"] = frame["text"].str.casefold().str.strip()
    frame["source"] = "bhavya2910_indian-scam-sms-synthetic-audited"
    return frame.reset_index(drop=True)


def build_model() -> Pipeline:
    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=120_000,
                    sublinear_tf=True,
                    strip_accents="unicode",
                    dtype=np.float32,
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=180_000,
                    sublinear_tf=True,
                    dtype=np.float32,
                ),
            ),
        ],
        n_jobs=1,
    )
    return Pipeline(
        [
            ("features", features),
            (
                "classifier",
                LogisticRegression(
                    C=10,
                    max_iter=2500,
                    class_weight="balanced",
                    random_state=SEED,
                    solver="liblinear",
                ),
            ),
        ],
        memory=None,
    )


def select_threshold(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    minimum_precision: float,
) -> tuple[float, dict[str, float]]:
    candidates = np.unique(
        np.concatenate(
            [
                np.array([0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40,
                          0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75,
                          0.80, 0.85, 0.90, 0.95]),
                probabilities,
            ]
        )
    )
    best: dict[str, float] | None = None
    best_threshold = 0.5
    for threshold in candidates:
        predictions = (probabilities >= threshold).astype(int)
        precision = precision_score(y_true, predictions, pos_label=1, zero_division=0)
        recall = recall_score(y_true, predictions, pos_label=1, zero_division=0)
        f2 = fbeta_score(y_true, predictions, beta=2, pos_label=1, zero_division=0)
        eligible = precision >= minimum_precision
        rank = (eligible, f2, recall, -abs(threshold - 0.5))
        if best is None or rank > best["_rank"]:
            best_threshold = float(threshold)
            best = {
                "_rank": rank,
                "precision": float(precision),
                "recall": float(recall),
                "f2": float(f2),
            }
    assert best is not None
    return best_threshold, {
        "precision": best["precision"],
        "recall": best["recall"],
        "f2": best["f2"],
    }


def evaluate(
    model: Pipeline,
    frame: pd.DataFrame,
    tag: str,
    threshold: float,
) -> dict:
    if frame.empty:
        return {"dataset": tag, "rows": 0}

    y_true = frame["label"].to_numpy()
    probabilities = model.predict_proba(frame["text"].tolist())[:, 1]
    predictions = (probabilities >= threshold).astype(int)
    report = classification_report(
        y_true,
        predictions,
        labels=[0, 1],
        target_names=["safe", "scam"],
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(y_true, predictions, labels=[0, 1])
    result = {
        "dataset": tag,
        "rows": int(len(frame)),
        "threshold": round(threshold, 6),
        "accuracy": round(float(accuracy_score(y_true, predictions)), 6),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 6),
        "safe": {
            "precision": round(report["safe"]["precision"], 6),
            "recall": round(report["safe"]["recall"], 6),
            "f1": round(report["safe"]["f1-score"], 6),
            "support": int(report["safe"]["support"]),
        },
        "scam": {
            "precision": round(report["scam"]["precision"], 6),
            "recall": round(report["scam"]["recall"], 6),
            "f1": round(report["scam"]["f1-score"], 6),
            "f2": round(
                float(fbeta_score(y_true, predictions, beta=2, pos_label=1)), 6
            ),
            "support": int(report["scam"]["support"]),
        },
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_order": ["safe", "scam"],
    }
    print(f"\n--- {tag} (threshold={threshold:.6f}) ---")
    print(
        classification_report(
            y_true,
            predictions,
            labels=[0, 1],
            target_names=["safe", "scam"],
            zero_division=0,
        )
    )
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(cm)
    return result


def benchmark(model: Pipeline, texts: list[str], repeats: int) -> dict:
    warmup = texts[: min(100, len(texts))]
    model.predict_proba(warmup)

    timings = []
    for _ in range(repeats):
        start = time.perf_counter()
        model.predict_proba(texts)
        timings.append((time.perf_counter() - start) * 1000)
    return {
        "rows": len(texts),
        "repeats": repeats,
        "mean_batch_ms": round(float(np.mean(timings)), 3),
        "median_batch_ms": round(float(np.median(timings)), 3),
        "mean_ms_per_message": round(
            float(np.mean(timings) / max(len(texts), 1)), 6
        ),
    }


def grouped_duplicates(frame: pd.DataFrame, name: str) -> dict:
    conflicting = frame.groupby("normalized_text")["label"].nunique()
    conflicting_count = int(conflicting.gt(1).sum())
    before = len(frame)
    frame = frame.drop_duplicates(
        subset=["normalized_text", "label"], keep="first"
    ).copy()
    return frame, {
        "name": name,
        "rows_before": before,
        "rows_after": len(frame),
        "exact_conflicting_text_groups": conflicting_count,
    }


def per_group_evaluation(
    model: Pipeline,
    frame: pd.DataFrame,
    threshold: float,
    column: str,
) -> dict:
    output = {}
    for value, subset in frame.groupby(column, sort=True):
        y_true = subset["label"].to_numpy()
        probabilities = model.predict_proba(subset["text"].tolist())[:, 1]
        predictions = (probabilities >= threshold).astype(int)
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true,
            predictions,
            labels=[1],
            average=None,
            zero_division=0,
        )
        cm = confusion_matrix(y_true, predictions, labels=[0, 1])
        output[str(value)] = {
            "rows": int(len(subset)),
            "scam_precision": round(float(precision[0]), 6),
            "scam_recall": round(float(recall[0]), 6),
            "scam_f1": round(float(f1[0]), 6),
            "scam_support": int(support[0]),
            "confusion_matrix": cm.tolist(),
        }
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the BSIS TF-IDF scam classifier."
    )
    parser.add_argument(
        "--data-dir",
        default="datasets/raw/bsis/classifier",
        help="Directory containing train/validation/test parquet files.",
    )
    parser.add_argument("--output-dir", default="artifacts_bsis")
    parser.add_argument(
        "--minimum-scam-precision",
        type=float,
        default=0.75,
        help="Validation precision floor used while selecting the scam threshold.",
    )
    parser.add_argument(
        "--benchmark-repeats",
        type=int,
        default=5,
    )
    parser.add_argument(
        "--supplement-csv",
        default=None,
        help="Optional training-only audited CSV; not used for validation/test.",
    )
    args = parser.parse_args()

    if not 0 < args.minimum_scam_precision <= 1:
        parser.error("--minimum-scam-precision must be in (0, 1]")
    if args.benchmark_repeats < 1:
        parser.error("--benchmark-repeats must be at least 1")

    data_dir = Path(args.data_dir)
    train = load_split(data_dir / "train-00000-of-00001.parquet")
    validation = load_split(data_dir / "validation-00000-of-00001.parquet")
    test = load_split(data_dir / "test-00000-of-00001.parquet")

    duplicate_audit = []
    train, audit = grouped_duplicates(train, "train")
    duplicate_audit.append(audit)
    validation, audit = grouped_duplicates(validation, "validation")
    duplicate_audit.append(audit)
    test, audit = grouped_duplicates(test, "test")
    duplicate_audit.append(audit)

    supplement_rows = 0
    supplement_overlap_removed = 0
    supplement_conflicts = 0
    if args.supplement_csv:
        supplement = load_supplement(Path(args.supplement_csv))
        supplement_before = len(supplement)
        supplement, supplement_audit = grouped_duplicates(
            supplement, "training_supplement"
        )
        supplement_conflicts = supplement_audit["exact_conflicting_text_groups"]

        bsis_groups = set(
            train["normalized_text"].tolist()
            + validation["normalized_text"].tolist()
            + test["normalized_text"].tolist()
        )
        supplement = supplement[
            ~supplement["normalized_text"].isin(bsis_groups)
        ].copy().reset_index(drop=True)

        supplement_overlap_removed = supplement_before - len(supplement)
        supplement_rows = int(len(supplement))
        train = pd.concat(
            [train, supplement],
            ignore_index=True,
        )
        train, supplement_train_audit = grouped_duplicates(
            train, "augmented_train"
        )
        supplement_conflicts += supplement_train_audit[
            "exact_conflicting_text_groups"
        ]
        duplicate_audit.append(supplement_train_audit)

    model = build_model()
    print(
        f"Training BSIS model: train={len(train):,}, "
        f"validation={len(validation):,}"
    )
    model.fit(train["text"].tolist(), train["label"].to_numpy())

    validation_probabilities = model.predict_proba(
        validation["text"].tolist()
    )[:, 1]
    threshold, threshold_selection = select_threshold(
        validation["label"].to_numpy(),
        validation_probabilities,
        args.minimum_scam_precision,
    )

    print(
        f"Selected threshold={threshold:.6f} from validation "
        f"(precision={threshold_selection['precision']:.6f}, "
        f"recall={threshold_selection['recall']:.6f}, "
        f"f2={threshold_selection['f2']:.6f})"
    )

    validation_metrics = evaluate(
        model, validation, "bsis_validation", threshold
    )
    test_metrics = evaluate(model, test, "bsis_test", threshold)

    benchmark_texts = test["text"].tolist()
    inference = benchmark(model, benchmark_texts, args.benchmark_repeats)

    metrics = {
        "dataset": "harshcasper/bsis",
        "dataset_role": "synthetic, lineage-grouped classifier benchmark",
        "task": "binary_scam_vs_safe",
        "label_mapping": {"0": "safe", "1": "scam"},
        "decision_threshold": threshold,
        "threshold_selection": {
            "set": "validation",
            "objective": "maximize validation F2 while meeting minimum scam precision",
            "minimum_scam_precision": args.minimum_scam_precision,
            **threshold_selection,
        },
        "model": {
            "features": "word TF-IDF 1-2 grams + char_wb TF-IDF 3-5 grams",
            "classifier": "LogisticRegression(C=10, class_weight=balanced)",
            "artifact_format": "joblib",
        },
        "rows": {
            "train": int(len(train)),
            "validation": int(len(validation)),
            "test": int(len(test)),
        },
        "training_augmentation": {
            "enabled": bool(args.supplement_csv),
            "dataset": (
                "bhavya2910/indian-scam-sms-synthetic-audited"
                if args.supplement_csv else None
            ),
            "rows_added": supplement_rows,
            "rows_removed_due_to_bsis_overlap": supplement_overlap_removed,
            "conflicting_exact_text_groups": supplement_conflicts,
            "role": (
                "training-only supplement; never used for validation or BSIS test"
            ),
        },
        "validation": validation_metrics,
        "test": test_metrics,
        "test_per_language": per_group_evaluation(
            model, test, threshold, "language"
        ),
        "test_per_vector": per_group_evaluation(
            model, test, threshold, "vector"
        ),
        "test_per_script_mode": per_group_evaluation(
            model, test, threshold, "script_mode"
        ),
        "inference_benchmark": inference,
        "exact_duplicate_audit": duplicate_audit,
        "caveats": [
            "BSIS is synthetic and must not be treated as independent real-world proof.",
            "The published splits are lineage-grouped; avoid claiming conversation-level independence beyond the lineage grouping.",
            "The scam score is a classifier score, not calibrated fraud probability.",
        ],
        "software": {
            "python": __import__("sys").version.split()[0],
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "label_mapping": {0: "safe", 1: "scam"},
            "model_name": "tfidf_word_char_logistic_regression",
            "decision_threshold": threshold,
            "training_dataset": "harshcasper/bsis",
            "training_sources": ["BSIS"],
            "task": "binary_scam_vs_safe",
        },
        output_dir / "bsis_scam_tfidf.joblib",
        compress=3,
    )

    test_predictions = test.copy()
    test_probabilities = model.predict_proba(test["text"].tolist())[:, 1]
    test_predictions["predicted_label"] = (
        test_probabilities >= threshold
    ).astype(int)
    test_predictions["scam_probability"] = test_probabilities
    test_predictions.to_csv(
        output_dir / "bsis_test_predictions.csv", index=False
    )

    with open(output_dir / "metrics.json", "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=2, ensure_ascii=False)

    print(f"\nSaved trained artifacts to {output_dir.resolve()}")
    print("  - bsis_scam_tfidf.joblib")
    print("  - bsis_test_predictions.csv")
    print("  - metrics.json")


if __name__ == "__main__":
    main()
