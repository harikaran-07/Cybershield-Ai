"""Train CyberShield AI ML models.

IMPORTANT — honest model status:
- Models are NOT bundled. Run this script on labeled data you are licensed to use.
- After training, artifacts are written to the paths configured in backend/.env.
- /api/v1/health reports exactly which models are loaded. Nothing is faked.

Usage:
    python scripts/train_models.py --roberta --train data/sms_train.csv
    python scripts/train_models.py --url --train data/url_train.csv
    python scripts/train_models.py --anomaly --train data/network_stats.csv
"""
import argparse
import os
import sys

BACKEND = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND)

from app.core.config import settings  # noqa: E402


def train_roberta(train_csv: str, epochs: int = 3, batch: int = 16) -> None:
    """Fine-tune RoBERTa for scam/phishing text classification.

    Expected CSV columns: text,label  (label ∈ SAFE, SPAM, SCAM, PHISHING)
    Suggested public datasets (check licenses): PhishTank-likes for email text,
    SMS spam collections, Enron phishing subsets, or your own labeled data.
    """
    import pandas as pd
    import torch
    from datasets import Dataset
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                              TrainingArguments, Trainer)
    from sklearn.model_selection import train_test_split

    df = pd.read_csv(train_csv)
    assert {"text", "label"} <= set(df.columns), "CSV must have 'text' and 'label' columns"
    labels = ["SAFE", "SPAM", "SCAM", "PHISHING"]
    df = df[df["label"].isin(labels)]
    train_df, eval_df = train_test_split(df, test_size=0.15, stratify=df["label"], random_state=42)

    model_dir = settings.MODEL_PATH
    base = "roberta-base"
    tokenizer = AutoTokenizer.from_pretrained(base)
    model = AutoModelForSequenceClassification.from_pretrained(
        base, num_labels=len(labels),
        id2label={i: l for i, l in enumerate(labels)},
        label2id={l: i for i, l in enumerate(labels)})

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, padding="max_length", max_length=256)

    train_ds = Dataset.from_pandas(train_df[["text", "label"]]).map(
        lambda r: {**tokenize(r), "labels": labels.index(r["label"])})
    eval_ds = Dataset.from_pandas(eval_df[["text", "label"]]).map(
        lambda r: {**tokenize(r), "labels": labels.index(r["label"])})

    args = TrainingArguments(
        output_dir="out/roberta", num_train_epochs=epochs, per_device_train_batch_size=batch,
        evaluation_strategy="epoch", save_strategy="epoch", logging_steps=50, load_best_model_at_end=True)
    trainer = Trainer(model=model, args=args, train_dataset=train_ds, eval_dataset=eval_ds)
    trainer.train()

    metrics = trainer.evaluate()
    print("Honest evaluation metrics:", metrics)
    os.makedirs(model_dir, exist_ok=True)
    model.save_pretrained(model_dir)
    tokenizer.save_pretrained(model_dir)
    with open(os.path.join(model_dir, "EVALUATION.txt"), "w") as f:
        f.write(str(metrics) + "\n\nDataset: " + train_csv + "\n")
    print(f"Saved RoBERTa to {model_dir}. Include EVALUATION.txt with real numbers.")


def train_url(train_csv: str) -> None:
    """Train XGBoost URL classifier. Expected CSV: url,label (label: 0=benign,1=phishing)."""
    import pandas as pd
    import xgboost as xgb
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    from app.services.rule_engine import FEATURE_NAMES, extract_url_features

    df = pd.read_csv(train_csv)
    assert {"url", "label"} <= set(df.columns), "CSV must have 'url' and 'label' columns"
    X = [extract_url_features(u).to_vector() for u in df["url"]]
    y = df["label"].astype(int).values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    model = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                              eval_metric="logloss")
    model.fit(Xtr, ytr)
    print(classification_report(yte, model.predict(Xte)))  # print REAL metrics

    os.makedirs(settings.URL_MODEL_PATH, exist_ok=True)
    out = os.path.join(settings.URL_MODEL_PATH, "model.json")
    model.get_booster().save_model(out)
    with open(os.path.join(settings.URL_MODEL_PATH, "FEATURES.txt"), "w") as f:
        f.write("\n".join(FEATURE_NAMES))
    print(f"Saved XGBoost to {out}")


def train_anomaly(train_csv: str) -> None:
    """Train Isolation Forest on metadata features. Expected CSV columns:
    connection_count, bytes_sent, bytes_received, host_is_ip, suspicious_tld, distinct_ports"""
    import joblib
    import pandas as pd
    from sklearn.ensemble import IsolationForest

    df = pd.read_csv(train_csv)
    cols = ["connection_count", "bytes_sent", "bytes_received",
            "host_is_ip", "suspicious_tld", "distinct_ports"]
    assert set(cols) <= set(df.columns), f"CSV must include {cols}"
    X = df[cols].values

    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)

    os.makedirs(settings.ANOMALY_MODEL_PATH, exist_ok=True)
    out = os.path.join(settings.ANOMALY_MODEL_PATH, "model.pkl")
    joblib.dump(model, out)
    print(f"Saved Isolation Forest to {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CyberShield AI models")
    parser.add_argument("--roberta", action="store_true")
    parser.add_argument("--url", action="store_true")
    parser.add_argument("--anomaly", action="store_true")
    parser.add_argument("--train", required=True, help="Path to training CSV")
    parser.add_argument("--epochs", type=int, default=3)
    args = parser.parse_args()

    if args.roberta:
        train_roberta(args.train, epochs=args.epochs)
    elif args.url:
        train_url(args.train)
    elif args.anomaly:
        train_anomaly(args.train)
    else:
        print("Choose one: --roberta | --url | --anomaly")
