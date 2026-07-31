import os
import joblib
import random
from flask import Flask, render_template, jsonify

app = Flask(__name__)

MODELS_DIR = "models"
MODEL_NAMES = ["decision_tree", "random_forest", "naive_bayes"]

artifacts = joblib.load(os.path.join(MODELS_DIR, "artifacts.joblib"))
X_test, y_test, X_test_raw = joblib.load(os.path.join(MODELS_DIR, "test_data.joblib"))
models = {name: joblib.load(os.path.join(MODELS_DIR, f"{name}.joblib")) for name in MODEL_NAMES}
label_encoder = artifacts["encoders"]["label"]  # to turn 0/1 back into "attack"/"normal"

DISPLAY_COLS = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "count", "srv_count", "logged_in", "serror_rate"
]


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/random_sample")
def random_sample():
    idx = random.randint(0, len(X_test) - 1)
    row = X_test.iloc[[idx]]
    true_label = int(y_test.iloc[idx])
    true_label_name = label_encoder.inverse_transform([true_label])[0]

    predictions = {}
    for name, model in models.items():
        pred = int(model.predict(row)[0])
        pred_name = label_encoder.inverse_transform([pred])[0]
        proba = model.predict_proba(row)[0].tolist()
        predictions[name] = {"prediction": pred_name, "confidence": max(proba)}

    raw_row = X_test_raw.iloc[[idx]]
    display_features = {}
    for col in DISPLAY_COLS:
        if col not in raw_row.columns:
            continue
        val = float(raw_row[col].values[0])
        if col == "protocol_type":
            
            code = int(round(val))
            display_features[col] = artifacts["encoders"]["protocol_type"].inverse_transform([code])[0]
        else:
            display_features[col] = round(val, 3)

    return jsonify({
        "features": display_features,
        "true_label": true_label_name,
        "predictions": predictions
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
