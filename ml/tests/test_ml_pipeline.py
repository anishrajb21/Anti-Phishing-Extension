"""
Tests for Machine Learning Training, Feature Extraction, and Evaluation
"""

import os
import sys
import json
import numpy as np
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from ml.feature_extractor import (
    extract_features_from_url,
    levenshtein_distance,
    detect_impersonation,
    calculate_entropy,
    FEATURE_NAMES
)
from ml.data_loader import load_dataset, extract_dataset_features, split_data_leakage_free
from ml.train_model import train_and_export, evaluate_metrics, MODEL_OUT_PATH, METADATA_OUT_PATH


def test_levenshtein_distance():
    assert levenshtein_distance('google', 'google') == 0
    assert levenshtein_distance('google', 'g00gle') == 2
    assert levenshtein_distance('paypal', 'paypa1') == 1
    assert levenshtein_distance('', 'abc') == 3


def test_detect_impersonation():
    # Legitimate brand
    assert detect_impersonation('google', 'google.com') == 0.0

    # Lookalike leetspeak
    assert detect_impersonation('paypa1', 'paypa1.com') >= 0.9

    # Combosquatting
    assert detect_impersonation('paypal-update', 'paypal-update.com') >= 0.85

    # Subdomain spoofing
    assert detect_impersonation('attacker', 'paypal.com.attacker.com') >= 0.85

    # Unrelated
    assert detect_impersonation('wikipedia', 'wikipedia.org') == 0.0


def test_entropy_calculation():
    # Zero entropy for identical characters
    assert calculate_entropy('aaaa') == 0.0
    # Higher entropy for random strings
    assert calculate_entropy('abcdefgh') > 2.5


def test_feature_extractor_structure():
    url = "https://login.paypal-security.xyz:8080/auth?ref=portal"
    res = extract_features_from_url(url)

    assert 'raw' in res
    assert 'normalized' in res
    assert len(res['normalized']) == len(FEATURE_NAMES)
    assert res['raw']['hasHTTPS'] == 1
    assert res['raw']['hasSuspiciousTLD'] == 1
    assert res['raw']['typosquattingScore'] > 0


def test_dataset_splitting_no_leakage():
    df = load_dataset()
    X, y, _ = extract_dataset_features(df)
    splits = split_data_leakage_free(X, y, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, random_state=42)

    X_train, y_train = splits['X_train'], splits['y_train']
    X_val, y_val = splits['X_val'], splits['y_val']
    X_test, y_test = splits['X_test'], splits['y_test']

    assert len(X_train) + len(X_val) + len(X_test) == len(X)
    assert len(y_train) + len(y_val) + len(y_test) == len(y)
    # Stratification check: labels exist in both sets
    assert 0 in y_train and 1 in y_train
    assert 0 in y_val and 1 in y_val
    assert 0 in y_test and 1 in y_test


def test_model_training_and_export():
    model_payload, metadata_payload = train_and_export(random_state=42)

    assert os.path.exists(MODEL_OUT_PATH)
    assert os.path.exists(METADATA_OUT_PATH)

    assert model_payload['modelType'] == 'logistic_regression'
    assert len(model_payload['weights']) == len(FEATURE_NAMES)
    assert isinstance(model_payload['bias'], float)
    assert 0.0 < model_payload['threshold'] < 1.0

    # Ensure evaluation metrics exist in metadata
    assert 'testMetrics' in metadata_payload
    assert metadata_payload['testMetrics']['rocAuc'] >= 0.70
