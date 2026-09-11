import os
import joblib
import matplotlib
matplotlib.use("Agg")  # so it works without a display, just saves images
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

MODELS_DIR = "models"
RESULTS_DIR = "static"  # so the Flask app can also show these images

MODEL_NAMES = ["decision_tree", "random_forest", "naive_bayes"]


def load_everything():
    artifacts = joblib.load(os.path.join(MODELS_DIR, "artifacts.joblib"))
    X_test, y_test, _X_test_raw = joblib.load(os.path.join(MODELS_DIR, "test_data.joblib"))
    models = {name: joblib.load(os.path.join(MODELS_DIR, f"{name}.joblib")) for name in MODEL_NAMES}
    return models, X_test, y_test, artifacts


def evaluate_model(name, model, X_test, y_test):
    y_pred = model.predict(X_test)

    # label encoding was: 0 = attack, 1 = normal (alphabetical order)
    # we treat "attack" as the "positive" class we care about detecting
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label=0)
    rec = recall_score(y_test, y_pred, pos_label=0)
    f1 = f1_score(y_test, y_pred, pos_label=0)

    print(f"\n===== {name} =====")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}  (of flagged attacks, how many were real)")
    print(f"Recall   : {rec:.4f}  (of real attacks, how many were caught)")
    print(f"F1-score : {f1:.4f}")
    print("\nFull classification report:")
    print(classification_report(y_test, y_pred, target_names=["attack", "normal"]))

    cm = confusion_matrix(y_test, y_pred)
    plot_confusion_matrix(cm, name)

    return {"model": name, "accuracy": acc, "precision": prec, "recall": rec, "f1": f1}


def plot_confusion_matrix(cm, name):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    plt.figure(figsize=(5, 4))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["attack", "normal"], yticklabels=["attack", "normal"]
    )
    plt.title(f"Confusion Matrix - {name}")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, f"confusion_{name}.png"))
    plt.close()


def main():
    models, X_test, y_test, artifacts = load_everything()
    results = []
    for name, model in models.items():
        results.append(evaluate_model(name, model, X_test, y_test))

    print("\n\n===== Summary (sorted by F1-score) =====")
    results.sort(key=lambda r: r["f1"], reverse=True)
    for r in results:
        print(f"{r['model']:15s} | Acc: {r['accuracy']:.4f} | Prec: {r['precision']:.4f} | "
              f"Rec: {r['recall']:.4f} | F1: {r['f1']:.4f}")


if __name__ == "__main__":
    main()
