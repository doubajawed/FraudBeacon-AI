"""Reproduce the bundled synthetic-data experiment.

Run: python train_model.py
This script evaluates a grouped holdout and then saves a model trained on all rows.
Do not call the result a real-world/global benchmark: the bundled dataset is synthetic.
"""
from __future__ import annotations
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, average_precision_score, confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline, FeatureUnion

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "regional_synthetic_messages.csv"
MODEL = ROOT / "models" / "synthetic_text_classifier.joblib"
RESULTS = ROOT / "results" / "synthetic_model_evaluation.json"


def make_pipeline():
    features = FeatureUnion([
        ("word_tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=16000, sublinear_tf=True, token_pattern=r"(?u)\b\w+\b")),
        ("char_tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, max_features=26000, sublinear_tf=True)),
    ])
    return Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(C=1.5, class_weight="balanced", max_iter=3000, solver="liblinear", random_state=42)),
    ])


def main():
    df = pd.read_csv(DATA).dropna(subset=["text", "label", "group_id"]).copy()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)
    X, y, groups = df["text"].to_numpy(), df["label"].to_numpy(), df["group_id"].to_numpy()
    splitter = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=42)
    train_idx, test_idx = next(splitter.split(X, y, groups))
    model = make_pipeline().fit(X[train_idx], y[train_idx])
    probabilities = model.predict_proba(X[test_idx])[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    majority = int(pd.Series(y[train_idx]).mode().iloc[0])
    baseline = np.full_like(y[test_idx], majority)
    cm = confusion_matrix(y[test_idx], predictions, labels=[0, 1]).tolist()
    metrics = {
        "dataset_rows": int(len(df)), "train_rows": int(len(train_idx)), "test_rows": int(len(test_idx)),
        "train_groups": int(len(set(groups[train_idx]))), "test_groups": int(len(set(groups[test_idx]))),
        "source_counts": {"regional_synthetic_context": int(len(df))},
        "label_counts": {"legitimate": int((y == 0).sum()), "scam": int((y == 1).sum())},
        "baseline": {"name": "majority-class baseline", "accuracy": float(accuracy_score(y[test_idx], baseline)),
                     "precision_scam": float(precision_score(y[test_idx], baseline, zero_division=0)),
                     "recall_scam": float(recall_score(y[test_idx], baseline, zero_division=0)),
                     "f1_scam": float(f1_score(y[test_idx], baseline, zero_division=0))},
        "model": {"name": "word + character TF-IDF with Logistic Regression",
                  "accuracy": float(accuracy_score(y[test_idx], predictions)),
                  "precision_scam": float(precision_score(y[test_idx], predictions, zero_division=0)),
                  "recall_scam": float(recall_score(y[test_idx], predictions, zero_division=0)),
                  "f1_scam": float(f1_score(y[test_idx], predictions, zero_division=0)),
                  "average_precision": float(average_precision_score(y[test_idx], probabilities))},
        "confusion_matrix_labels": ["legitimate", "scam"], "confusion_matrix": cm,
        "evaluation_note": "Grouped holdout on 136 AI-assisted synthetic messages only; not a real-world, international or field-performance evaluation.",
    }
    RESULTS.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    final_model = make_pipeline().fit(X, y)
    joblib.dump({"pipeline": final_model, "threshold": 0.5, "training_rows": len(df), "model_name": "FraudBeacon AI synthetic research classifier", "score_is_calibrated": False}, MODEL)
    print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
