"""
Model Evaluation and Verification Script
Evaluates the exported model against a dataset and verifies inference consistency.
"""

import os
import sys
import json
import argparse

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import numpy as np
from ml.data_loader import load_dataset, extract_dataset_features
from ml.train_model import evaluate_metrics

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model.json')


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def evaluate_exported_model(data_path: str = None):
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run python ml/train_model.py first.")

    with open(MODEL_PATH, 'r', encoding='utf-8') as f:
        model_data = json.load(f)

    weights = np.array(model_data['weights'], dtype=np.float64)
    bias = float(model_data['bias'])
    threshold = float(model_data.get('threshold', 0.5))
    expected_features = model_data.get('features', [])

    print("=" * 60)
    print(f"PhishLens Model Evaluation: Version {model_data.get('version', 'unknown')}")
    print(f"Model Type: {model_data.get('modelType')}, Threshold: {threshold}")
    print("=" * 60)

    # Load dataset
    df = load_dataset(data_path) if data_path else load_dataset()
    X, y, feature_names = extract_dataset_features(df)

    if feature_names != expected_features:
        raise ValueError(f"Feature mismatch between data and model: {feature_names} != {expected_features}")

    # Replicate browser inference in numpy: z = w · x + bias, p = sigmoid(z)
    z = np.dot(X, weights) + bias
    probs = sigmoid(z)

    metrics = evaluate_metrics(y, probs, threshold)

    print("\n--- Model Evaluation Report ---")
    print(f"Total Evaluated Samples: {len(y)}")
    print(f"Precision:               {metrics['precision']:.4f}")
    print(f"Recall:                  {metrics['recall']:.4f}")
    print(f"F1-Score:                {metrics['f1Score']:.4f}")
    print(f"False Positive Rate:     {metrics['falsePositiveRate']:.4f}")
    print(f"False Negative Rate:     {metrics['falseNegativeRate']:.4f}")
    print(f"ROC-AUC:                 {metrics['rocAuc']:.4f}")
    print(f"PR-AUC:                  {metrics['prAuc']:.4f}")
    print("\nConfusion Matrix:")
    cm = metrics['confusionMatrix']
    print(f"  True Negatives (TN):   {cm['trueNegatives']}")
    print(f"  False Positives (FP):  {cm['falsePositives']}")
    print(f"  False Negatives (FN):  {cm['falseNegatives']}")
    print(f"  True Positives (TP):   {cm['truePositives']}")
    print("=" * 60)

    return metrics


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Evaluate PhishLens Model")
    parser.add_argument('--data-path', type=str, default=None, help="Custom dataset path")
    args = parser.parse_args()
    evaluate_exported_model(data_path=args.data_path)
