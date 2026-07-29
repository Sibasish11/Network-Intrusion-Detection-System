import os
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB

from preprocess import preprocess_pipeline

MODELS_DIR = "models"


def get_models():
  
    return {
        "decision_tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "random_forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1),
        "naive_bayes": GaussianNB(),
    }


def train_all(data_dir="data"):
    os.makedirs(MODELS_DIR, exist_ok=True)

    print("Loading and preprocessing data...")
    X_train, y_train, X_test, y_test, artifacts = preprocess_pipeline(data_dir)

    joblib.dump(artifacts, os.path.join(MODELS_DIR, "artifacts.joblib"))

    scaler = artifacts["scaler"]
    feature_cols = artifacts["feature_cols"]
    X_test_raw = X_test.copy()
    X_test_raw[feature_cols] = scaler.inverse_transform(X_test[feature_cols])

    joblib.dump((X_test, y_test, X_test_raw), os.path.join(MODELS_DIR, "test_data.joblib"))

    models = get_models()
    trained = {}

    for name, model in models.items():
        print(f"\nTraining {name} ...")
        model.fit(X_train, y_train)
        trained[name] = model
        joblib.dump(model, os.path.join(MODELS_DIR, f"{name}.joblib"))
        print(f"{name} saved to models/{name}.joblib")

    print("\nAll models trained and saved in the 'models/' folder.")
    return trained, X_train, y_train, X_test, y_test


if __name__ == "__main__":
    train_all()
