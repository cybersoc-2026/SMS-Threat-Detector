# Phishing URL Detection with XGBoost

## Dataset
`Dataset.csv` is the supplied URL-Phish dataset. It has 116,600 rows and 26 columns.
The `label` convention in this project is:
- `0` = legitimate URL
- `1` = phishing URL

The training script removes exact duplicate URLs and uses numeric engineered features.
It excludes raw `url`, `dom`, and `tld` text columns for the first baseline.

## Windows setup (Command Prompt)
1. Install Python 3.11 or 3.12 from https://www.python.org/downloads/ if needed.
   During installation, select **Add Python to PATH**.
2. Extract this folder to a simple location, e.g. `C:\Phishing_URL_XGBoost`.
3. Open Command Prompt and run:

```bat
cd C:\Phishing_URL_XGBoost
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python train_model.py
```

Wait for training to finish. It prints accuracy, precision, recall, F1-score, ROC-AUC,
and the confusion matrix.

## Outputs
- `models\phishing_xgboost.json` — trained XGBoost model
- `models\feature_columns.json` — feature order used by the model
- `results\evaluation.json` — saved test evaluation

## Important
The evaluation is a random holdout from the same dataset, not an independent live-web test.
URLs can change over time, so later we should evaluate on a time-separated or external dataset.
This initial package trains the classifier; a matching live URL feature-extraction/prediction
script will be added after training is confirmed.
