import os
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB

from preprocess import preprocess_pipeline

MODELS_DIR = "models"


def get_models():
    """
    Defines the 3 models with reasonable beginner-friendly settings.

    - max_depth on the tree stops it from growing too complex and
      memorizing the training data (overfitting).
    - n_estimators=100 for the forest means 100 trees vote together.
    - random_state=42 makes results reproducible every time you run it.
    """
    return {
        "decision_tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "random_forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1),
        "naive_bayes": GaussianNB(),
    }


def train_all(data_dir="data"):
    os.makedirs(MODELS_DIR, exist_ok=True)

    print("Loading and preprocessing data...")
    X_train, y_train, X_test, y_test, artifacts = preprocess_pipeline(data_dir)

    # Save the preprocessing artifacts (scaler + encoders) so app.py can
    # transform new/incoming data the exact same way the training data was.
    joblib.dump(artifacts, os.path.join(MODELS_DIR, "artifacts.joblib"))

    # Also save an UNSCALED copy of the test features, purely so the demo
    # app can show human-readable numbers (e.g. src_bytes=491) instead of
    # standardized values (e.g. src_bytes=-0.42). Models still predict on
    # the scaled X_test, saved right alongside it.
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
