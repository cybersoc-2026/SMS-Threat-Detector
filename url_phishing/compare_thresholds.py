
import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    balanced_accuracy_score,
)
from xgboost import XGBClassifier

# Load and prepare the existing dataset
df = pd.read_csv("Dataset.csv")
df = df.dropna(subset=["url", "label"])
df = df.drop_duplicates(subset=["url"]).copy()
df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)

# Load the exact feature order used by the trained model
with open("models/feature_columns.json", encoding="utf-8") as f:
    feature_cols = json.load(f)

X = df[feature_cols]
X = X.replace([float("inf"), float("-inf")], pd.NA).fillna(0)
y = df["label"]

# Recreate the original test split
_, X_test, _, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

# Load the existing trained model; do not retrain
model = XGBClassifier()
model.load_model("models/phishing_xgboost.json")
probabilities = model.predict_proba(X_test)[:, 1]

print("\nBALANCED DETECTOR: THRESHOLD COMPARISON")
print("Threshold | Precision | Recall | F1-score | Balanced accuracy")
print("-" * 66)

for threshold in [0.30, 0.35, 0.40, 0.45, 0.50]:
    predictions = (probabilities >= threshold).astype(int)

    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)
    balanced_accuracy = balanced_accuracy_score(y_test, predictions)

    print(
        f"{threshold:.2f}      | "
        f"{precision:.4f}    | "
        f"{recall:.4f} | "
        f"{f1:.4f}   | "
        f"{balanced_accuracy:.4f}"
    )

print("\nEvaluation complete. Existing model and predictor were not changed.")
