"""
preprocess.py
--------------
Loads the raw NSL-KDD text files and turns them into clean, numeric,
model-ready data. Run this file directly to test it:

    python src/preprocess.py
"""

import os
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

# Categorical columns that are text, not numbers (models need numbers)
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def load_raw_data(data_dir="data"):
    """
    STEP 1: Load the raw text files into pandas DataFrames.
    Why: pandas gives us a table (like Excel) we can inspect and manipulate
    easily, instead of raw text.
    """
    train_path = os.path.join(data_dir, "KDDTrain+.txt")
    test_path = os.path.join(data_dir, "KDDTest+.txt")

    train_df = pd.read_csv(train_path, names=COLUMN_NAMES)
    test_df = pd.read_csv(test_path, names=COLUMN_NAMES)

    return train_df, test_df


def simplify_labels(df):
    """
    STEP 2: Collapse the ~23 specific attack names (like 'neptune', 'smurf',
    'satan'...) into a simple binary label: 'normal' or 'attack'.

    Why: For a beginner-friendly NIDS demo, "is this traffic dangerous?"
    (binary) is much easier to build, explain, and evaluate than guessing
    the exact attack type (multi-class). It's also how most real intro
    NIDS projects start.
    """
    df = df.copy()
    df["binary_label"] = df["label"].apply(lambda x: "normal" if x == "normal" else "attack")
    return df


def drop_useless_columns(df):
    """
    STEP 3: Drop columns that don't help the model.
    - 'difficulty_level' is a scoring artifact from the dataset creators,
      not a real network feature.
    - 'num_outbound_cmds' and 'is_host_login' are almost always 0 for every
      row (zero variance), so they carry no useful information.
    Why: Extra useless columns just add noise and slow training.
    """
    cols_to_drop = ["difficulty_level"]
    for c in ["num_outbound_cmds"]:
        if c in df.columns and df[c].nunique() <= 1:
            cols_to_drop.append(c)
    return df.drop(columns=cols_to_drop, errors="ignore")


def encode_categorical(train_df, test_df):
    """
    STEP 4: Convert text categories (protocol_type='tcp', service='http',
    flag='SF', etc.) into numbers using LabelEncoder.

    Why: ML models are just math — they can't multiply or compare the word
    "tcp". We map each unique category to an integer (tcp=0, udp=1, icmp=2...).

    Important detail: we FIT the encoder on the combined train+test
    categories, so if the test set contains a category the train set
    didn't have, it doesn't crash.
    """
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        combined = pd.concat([train_df[col], test_df[col]], axis=0)
        le.fit(combined)
        train_df[col] = le.transform(train_df[col])
        test_df[col] = le.transform(test_df[col])
        encoders[col] = le

    # Also encode the target label: normal=0, attack=1
    label_encoder = LabelEncoder()
    label_encoder.fit(["normal", "attack"])
    train_df["binary_label"] = label_encoder.transform(train_df["binary_label"])
    test_df["binary_label"] = label_encoder.transform(test_df["binary_label"])
    encoders["label"] = label_encoder

    return train_df, test_df, encoders


def scale_features(train_df, test_df, feature_cols):
    """
    STEP 5: Scale numeric features to a similar range using StandardScaler
    (mean=0, std=1).

    Why: Some features are tiny (like 'land' which is 0 or 1) and others
    are huge (like 'src_bytes' which can be in the millions). Without
    scaling, models like distance-based ones get dominated by the
    large-range features, and even tree models train more reliably on
    scaled data for consistency across the pipeline.
    """
    scaler = StandardScaler()
    train_scaled = train_df.copy()
    test_scaled = test_df.copy()

    train_scaled[feature_cols] = scaler.fit_transform(train_df[feature_cols])
    test_scaled[feature_cols] = scaler.transform(test_df[feature_cols])

    return train_scaled, test_scaled, scaler


def preprocess_pipeline(data_dir="data"):
    """
    Runs all steps in order and returns model-ready train/test splits.
    This is the single function everything else (train.py, app.py) will call.
    """
    train_df, test_df = load_raw_data(data_dir)

    train_df = simplify_labels(train_df)
    test_df = simplify_labels(test_df)

    train_df = drop_useless_columns(train_df)
    test_df = drop_useless_columns(test_df)

    train_df, test_df, encoders = encode_categorical(train_df, test_df)

    # Original text label ('label' column) no longer needed after encoding
    train_df = train_df.drop(columns=["label"])
    test_df = test_df.drop(columns=["label"])

    feature_cols = [c for c in train_df.columns if c != "binary_label"]

    train_df, test_df, scaler = scale_features(train_df, test_df, feature_cols)

    X_train, y_train = train_df[feature_cols], train_df["binary_label"]
    X_test, y_test = test_df[feature_cols], test_df["binary_label"]

    artifacts = {"encoders": encoders, "scaler": scaler, "feature_cols": feature_cols}
    return X_train, y_train, X_test, y_test, artifacts


if __name__ == "__main__":
    X_train, y_train, X_test, y_test, artifacts = preprocess_pipeline()
    print("Train shape:", X_train.shape)
    print("Test shape:", X_test.shape)
    print("\nClass balance in train set:")
    print(y_train.value_counts())
    print("\n0 = attack, 1 = normal (check artifacts['encoders']['label'].classes_)")
    print(artifacts["encoders"]["label"].classes_)
