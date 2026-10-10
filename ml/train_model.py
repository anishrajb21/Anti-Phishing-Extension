"""
Train and Export Calibrated Phishing Detection Model
Trains a Logistic Regression classifier, selects optimal threshold on validation set,
and exports model weights to model/phishing_model.json and model/model_metadata.json.
"""

import os
import sys
import json
import argparse
from datetime import datetime

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

from ml.data_loader import load_dataset, extract_dataset_features, split_data_leakage_free
from ml.feature_extractor import FEATURE_NAMES

MODEL_OUT_PATH = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model.json')
METADATA_OUT_PATH = os.path.join(os.path.dirname(__file__), '..', 'model', 'model_metadata.json')


def tune_threshold(model: LogisticRegression, X_val: np.ndarray, y_val: np.ndarray) -> float:
    """Selects the probability threshold that maximizes F1 while keeping FPR <= 0.05."""
    probs = model.predict_proba(X_val)[:, 1]
    candidate_thresholds = np.linspace(0.2, 0.8, 61)

    best_thresh = 0.5
    best_f1 = -1.0

    for thresh in candidate_thresholds:
        preds = (probs >= thresh).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_val, preds).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1 = f1_score(y_val, preds, zero_division=0)

        # Prioritize low false positive rate (FPR <= 0.05)
        if fpr <= 0.05 and f1 > best_f1:
            best_f1 = f1
            best_thresh = thresh

    # If no threshold achieved FPR <= 0.05, pick threshold with max F1
    if best_f1 < 0:
        for thresh in candidate_thresholds:
            preds = (probs >= thresh).astype(int)
            f1 = f1_score(y_val, preds, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_thresh = thresh

    return float(round(best_thresh, 3))


def evaluate_metrics(y_true: np.ndarray, probs: np.ndarray, threshold: float) -> dict:
    """Computes comprehensive security classification metrics."""
    preds = (probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, preds).ravel()

    precision = float(precision_score(y_true, preds, zero_division=0))
    recall = float(recall_score(y_true, preds, zero_division=0))
    f1 = float(f1_score(y_true, preds, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    roc_auc = float(roc_auc_score(y_true, probs)) if len(np.unique(y_true)) > 1 else 0.0
    pr_auc = float(average_precision_score(y_true, probs)) if len(np.unique(y_true)) > 1 else 0.0

    return {
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1Score': round(f1, 4),
        'falsePositiveRate': round(fpr, 4),
        'falseNegativeRate': round(fnr, 4),
        'rocAuc': round(roc_auc, 4),
        'prAuc': round(pr_auc, 4),
        'confusionMatrix': {
            'trueNegatives': int(tn),
            'falsePositives': int(fp),
            'falseNegatives': int(fn),
            'truePositives': int(tp)
        }
    }


def train_and_export(data_path: str = None, random_state: int = 42):
    print("=" * 60)
    print("PhishLens Web Shield: Model Training Pipeline")
    print("=" * 60)

    # 1. Load Data
    df = load_dataset(data_path) if data_path else load_dataset()
    print(f"[1/6] Loaded {len(df)} URLs (Legitimate: {(df['label'] == 0).sum()}, Phishing: {(df['label'] == 1).sum()})")

    # 2. Extract Features
    X, y, feature_names = extract_dataset_features(df)
    print(f"[2/6] Extracted {X.shape[1]} features across {X.shape[0]} samples.")

    # 3. Leakage-free Split
    splits = split_data_leakage_free(X, y, random_state=random_state)
    X_train, y_train = splits['X_train'], splits['y_train']
    X_val, y_val = splits['X_val'], splits['y_val']
    X_test, y_test = splits['X_test'], splits['y_test']
    print(f"[3/6] Split data: Train={len(y_train)}, Val={len(y_val)}, Test={len(y_test)}")

    # 4. Train Baseline (Dummy) and Logistic Regression
    baseline = DummyClassifier(strategy='most_frequent')
    baseline.fit(X_train, y_train)
    baseline_acc = float(baseline.score(X_test, y_test))

    clf = LogisticRegression(
        C=1.0,
        class_weight='balanced',
        solver='lbfgs',
        max_iter=1000,
        random_state=random_state
    )
    clf.fit(X_train, y_train)
    print("[4/6] Fitted Logistic Regression with balanced class weights.")

    # 5. Tune Decision Threshold on Validation Set
    val_probs = clf.predict_proba(X_val)[:, 1]
    optimal_threshold = tune_threshold(clf, X_val, y_val)
    val_metrics = evaluate_metrics(y_val, val_probs, optimal_threshold)
    print(f"[5/6] Validation threshold tuned to {optimal_threshold}. Val F1: {val_metrics['f1Score']}, Val FPR: {val_metrics['falsePositiveRate']}")

    # 6. Evaluate on Held-out Test Set
    test_probs = clf.predict_proba(X_test)[:, 1]
    test_metrics = evaluate_metrics(y_test, test_probs, optimal_threshold)
    print(f"[6/6] Held-out Test Evaluation: Precision={test_metrics['precision']}, Recall={test_metrics['recall']}, F1={test_metrics['f1Score']}, ROC-AUC={test_metrics['rocAuc']}")

    # Prepare Model Payload for Extension Runtime
    weights = [float(round(w, 4)) for w in clf.coef_[0]]
    bias = float(round(clf.intercept_[0], 4))

    model_payload = {
        'modelType': 'logistic_regression',
        'version': '1.1.0',
        'description': 'Calibrated Logistic Regression model for URL phishing detection',
        'features': feature_names,
        'weights': weights,
        'bias': bias,
        'threshold': optimal_threshold,
        'trainingInfo': {
            'trainingDate': datetime.now().strftime('%Y-%m-%d'),
            'sampleSize': int(len(df)),
            'trainSamples': int(len(y_train)),
            'valSamples': int(len(y_val)),
            'testSamples': int(len(y_test)),
            'accuracy': float(round((test_metrics['confusionMatrix']['truePositives'] + test_metrics['confusionMatrix']['trueNegatives']) / len(y_test), 4)),
            'precision': test_metrics['precision'],
            'recall': test_metrics['recall'],
            'f1Score': test_metrics['f1Score'],
            'rocAuc': test_metrics['rocAuc'],
            'prAuc': test_metrics['prAuc'],
            'baselineAccuracy': round(baseline_acc, 4),
            'provenance': 'Curated benchmark dataset combining Tranco Top 1M domains and synthetic/verified phishing kits'
        },
        'normalization': {
            'urlLength': {'divide': 100, 'cap': 5.0},
            'numDots': {'divide': 5, 'cap': 5.0},
            'numHyphens': {'divide': 5, 'cap': 5.0},
            'numSpecialChars': {'divide': 10, 'cap': 5.0},
            'domainEntropy': {'divide': 5, 'cap': 5.0},
            'numDigits': {'divide': 10, 'cap': 5.0},
            'hostnameLength': {'divide': 50, 'cap': 5.0}
        }
    }

    # Prepare Detailed Metadata
    metadata_payload = {
        'modelVersion': '1.1.0',
        'trainedAt': datetime.now().isoformat(),
        'optimalThreshold': optimal_threshold,
        'validationMetrics': val_metrics,
        'testMetrics': test_metrics,
        'featureWeights': {name: w for name, w in zip(feature_names, weights)},
        'bias': bias,
        'hyperparameters': {
            'penalty': 'l2',
            'C': 1.0,
            'class_weight': 'balanced',
            'solver': 'lbfgs'
        },
        'datasetProvenance': {
            'source': 'Curated Tranco legitimate domains + Synthetic/verified phishing lures',
            'license': 'Open / Research dataset',
            'limitations': 'Client-side URL features alone cannot inspect DOM content, rendered layout, or dynamic payload changes.'
        }
    }

    # Write files
    os.makedirs(os.path.dirname(MODEL_OUT_PATH), exist_ok=True)
    with open(MODEL_OUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(model_payload, f, indent=2)
    print(f"Exported model to: {MODEL_OUT_PATH}")

    with open(METADATA_OUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(metadata_payload, f, indent=2)
    print(f"Exported metadata to: {METADATA_OUT_PATH}")
    print("=" * 60)

    return model_payload, metadata_payload


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train PhishLens ML Model")
    parser.add_argument('--data-path', type=str, default=None, help="Custom CSV dataset path")
    args = parser.parse_args()
    train_and_export(data_path=args.data_path)
