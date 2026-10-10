"""
Data Loader & Preprocessor for Phishing URL Datasets
Handles provenance tracking, deduplication, and leakage-free splitting.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from ml.feature_extractor import extract_features_from_url, FEATURE_NAMES

DATASET_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), 'data', 'curated_urls.csv')


def load_dataset(csv_path: str = DATASET_DEFAULT_PATH) -> pd.DataFrame:
    """Loads and validates the URL dataset."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}")

    df = pd.read_csv(csv_path)
    required_cols = {'url', 'label'}
    if not required_cols.issubset(df.columns):
        raise ValueError(f"Dataset must contain columns: {required_cols}. Found: {df.columns.tolist()}")

    # Deduplicate by URL
    initial_len = len(df)
    df = df.drop_duplicates(subset=['url']).reset_index(drop=True)
    dedup_len = len(df)

    if dedup_len < initial_len:
        print(f"[DataLoader] Removed {initial_len - dedup_len} duplicate URLs.")

    return df


def extract_dataset_features(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Extracts normalized feature vectors for each URL in DataFrame."""
    X_list = []
    y_list = []

    for _, row in df.iterrows():
        url = str(row['url'])
        label = int(row['label'])
        feat = extract_features_from_url(url)
        X_list.append(feat['normalized'])
        y_list.append(label)

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list, dtype=np.int32)
    return X, y, FEATURE_NAMES


def split_data_leakage_free(
    X: np.ndarray,
    y: np.ndarray,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42
) -> dict:
    """
    Splits features and labels into Train, Validation, and Test sets
    with stratification and strict leakage prevention.
    """
    assert abs((train_ratio + val_ratio + test_ratio) - 1.0) < 1e-5, "Ratios must sum to 1.0"

    # Step 1: Split out test set first
    test_size = test_ratio
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y,
        test_size=test_size,
        stratify=y,
        random_state=random_state
    )

    # Step 2: Split train and val from trainval
    val_rel_size = val_ratio / (train_ratio + val_ratio)
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval,
        test_size=val_rel_size,
        stratify=y_trainval,
        random_state=random_state
    )

    return {
        'X_train': X_train, 'y_train': y_train,
        'X_val': X_val, 'y_val': y_val,
        'X_test': X_test, 'y_test': y_test
    }
