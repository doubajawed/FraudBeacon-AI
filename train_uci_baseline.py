"""Train an optional English SMS spam model from the public UCI collection.

This is separate from the bundled multilingual synthetic research model.
UCI labels are spam/ham, not pure phishing/fraud labels.
Run: python train_uci_baseline.py
"""
from __future__ import annotations
import io, json, urllib.request, zipfile
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, average_precision_score, confusion_matrix

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
RESULT_DIR = ROOT / "results"
URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
ZIP_PATH = DATA_DIR / "uci_sms_spam_collection.zip"
RAW_PATH = DATA_DIR / "SMSSpamCollection"
MODEL_PATH = MODEL_DIR / "uci_english_spam_model.joblib"
RESULT_PATH = RESULT_DIR / "uci_english_spam_evaluation.json"


def ensure_data():
    DATA_DIR.mkdir(exist_ok=True)
    if not ZIP_PATH.exists() and not RAW_PATH.exists():
        print("Downloading the UCI SMS Spam Collection...")
        request = urllib.request.Request(URL, headers={"User-Agent": "FraudBeaconAI-research/1.0"})
        with urllib.request.urlopen(request, timeout=45) as response:
            ZIP_PATH.write_bytes(response.read())
    if not RAW_PATH.exists():
        with zipfile.ZipFile(ZIP_PATH) as archive:
            member = next((n for n in archive.namelist() if n.lower().endswith("smsspamcollection")), None)
            if not member:
                raise RuntimeError("SMSSpamCollection file not found in UCI archive")
            RAW_PATH.write_bytes(archive.read(member))


def load_data():
    ensure_data()
    rows = []
    for line in RAW_PATH.read_text(encoding="latin-1").splitlines():
        if "\t" not in line:
            continue
        label, message = line.split("\t", 1)
        rows.append({"message": message.strip(), "label": 1 if label.strip().lower() == "spam" else 0})
    df = pd.DataFrame(rows).dropna().drop_duplicates(subset=["message", "label"])
    df = df[df.message.str.len() > 2].reset_index(drop=True)
    return df


def make_pipeline():
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=20000, sublinear_tf=True, token_pattern=r"(?u)\b\w+\b")),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, max_features=30000, sublinear_tf=True)),
    ])
    return Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(C=1.5, class_weight="balanced", max_iter=3000, solver="liblinear", random_state=42)),
    ])


def main():
    MODEL_DIR.mkdir(exist_ok=True)
    RESULT_DIR.mkdir(exist_ok=True)
    df = load_data()
    X = df.message.to_numpy()
    y = df.label.to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    model = make_pipeline().fit(X_train, y_train)
    probability = model.predict_proba(X_test)[:, 1]
    predicted = (probability >= 0.5).astype(int)
    baseline = np.zeros_like(y_test)  # always ham / not spam
    matrix = confusion_matrix(y_test, predicted, labels=[0, 1]).tolist()
    metrics = {
        "dataset": "UCI SMS Spam Collection",
        "rows": int(len(df)), "train_rows": int(len(X_train)), "test_rows": int(len(X_test)),
        "label_counts": {"ham": int((y == 0).sum()), "spam": int((y == 1).sum())},
        "baseline": {"name": "always predict ham", "accuracy": float(accuracy_score(y_test, baseline)),
                     "precision_spam": float(precision_score(y_test, baseline, zero_division=0)),
                     "recall_spam": float(recall_score(y_test, baseline, zero_division=0)),
                     "f1_spam": float(f1_score(y_test, baseline, zero_division=0))},
        "model": {"name": "word + character TF-IDF with Logistic Regression",
                  "accuracy": float(accuracy_score(y_test, predicted)),
                  "precision_spam": float(precision_score(y_test, predicted, zero_division=0)),
                  "recall_spam": float(recall_score(y_test, predicted, zero_division=0)),
                  "f1_spam": float(f1_score(y_test, predicted, zero_division=0)),
                  "average_precision": float(average_precision_score(y_test, probability))},
        "confusion_matrix_labels": ["ham", "spam"], "confusion_matrix": matrix,
        "evaluation_note": "Random stratified holdout of English UCI SMS spam/ham labels. Spam is broader than phishing or financial fraud; this is not an international phishing benchmark.",
        "citation": "Almeida, T. & Hidalgo, J. (2011). SMS Spam Collection. UCI Machine Learning Repository. DOI: 10.24432/C5CC84.",
    }
    RESULT_PATH.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    final_model = make_pipeline().fit(X, y)
    joblib.dump({"pipeline": final_model, "threshold": 0.5, "training_rows": len(df), "dataset": "UCI SMS Spam Collection", "score_is_calibrated": False}, MODEL_PATH)
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    print("\nSaved the optional English model. Restart FraudBeacon AI to activate it.")


if __name__ == "__main__":
    main()
