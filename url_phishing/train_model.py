from pathlib import Path
import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    roc_auc_score, average_precision_score
)
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "Dataset.csv"
MODEL_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"
MODEL_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

def main():
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    required = {"url", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")

    print(f"Rows before cleaning: {len(df):,}")
    print("Original label counts:")
    print(df["label"].value_counts(dropna=False).sort_index().to_string())

    # Keep one row per exact URL to reduce duplicate leakage between train/test.
    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"]).copy()
    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)

    labels = set(df["label"].unique())
    if not labels.issubset({0, 1}) or labels != {0, 1}:
        raise ValueError(f"Expected binary labels 0 and 1; found {sorted(labels)}")

    # Dataset convention used here: 0 = legitimate, 1 = phishing.
    # Use numerical engineered features only. Raw URL/domain/TLD strings are excluded.
    excluded = {"url", "dom", "tld", "label"}
    feature_cols = [
        c for c in df.columns
        if c not in excluded and pd.api.types.is_numeric_dtype(df[c])
    ]
    if not feature_cols:
        raise ValueError("No numeric feature columns found.")

    X = df[feature_cols].replace([float("inf"), float("-inf")], pd.NA)
    X = X.fillna(0)
    y = df["label"]

    print(f"\nRows after exact-URL deduplication: {len(df):,}")
    print(f"Numeric features used: {len(feature_cols)}")
    print("Feature columns:", ", ".join(feature_cols))
    print("\nLabels after cleaning (0=legitimate, 1=phishing):")
    print(y.value_counts().sort_index().to_string())

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"\nTraining rows: {len(X_train):,}")
    print(f"Testing rows:  {len(X_test):,}")
    print("\nTraining XGBoost...")

    model = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.85,
        colsample_bytree=0.90,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        tree_method="hist"
    )
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    report = classification_report(
        y_test, pred, labels=[0, 1],
        target_names=["Legitimate (0)", "Phishing (1)"],
        digits=4, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    metrics = {
        "dataset_rows_after_deduplication": int(len(df)),
        "feature_count": len(feature_cols),
        "features": feature_cols,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "accuracy": float(accuracy_score(y_test, pred)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "average_precision": float(average_precision_score(y_test, probabilities)),
        "confusion_matrix_labels_order": ["Legitimate (0)", "Phishing (1)"],
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "note": "Internal random stratified holdout from this dataset; not a guarantee of real-world performance."
    }

    model_path = MODEL_DIR / "phishing_xgboost.json"
    model.save_model(model_path)
    (MODEL_DIR / "feature_columns.json").write_text(
        json.dumps(feature_cols, indent=2), encoding="utf-8"
    )
    (RESULTS_DIR / "evaluation.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )

    print("\n===== TEST RESULTS =====")
    print(f"Accuracy: {metrics['accuracy']:.4%}")
    print(f"ROC-AUC: {metrics['roc_auc']:.4f}")
    print(f"Average precision (PR-AUC summary): {metrics['average_precision']:.4f}")
    print("\nClassification report:")
    print(classification_report(
        y_test, pred, labels=[0, 1],
        target_names=["Legitimate (0)", "Phishing (1)"],
        digits=4, zero_division=0
    ))
    print("Confusion matrix (rows=actual, columns=predicted; order 0, 1):")
    print(cm)
    print(f"\nSaved model: {model_path}")
    print(f"Saved evaluation: {RESULTS_DIR / 'evaluation.json'}")
    print("\nTraining finished.")

if __name__ == "__main__":
    main()
