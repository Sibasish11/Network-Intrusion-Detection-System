import os
import joblib
import random
from flask import Flask, render_template, jsonify

try:
    import openai
except ImportError:
    openai = None

app = Flask(__name__)

MODELS_DIR = "models"
MODEL_NAMES = ["decision_tree", "random_forest", "naive_bayes"]
OPENAI_MODEL = "gpt-3.5-turbo"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

artifacts = joblib.load(os.path.join(MODELS_DIR, "artifacts.joblib"))
X_test, y_test, X_test_raw = joblib.load(os.path.join(MODELS_DIR, "test_data.joblib"))
models = {name: joblib.load(os.path.join(MODELS_DIR, f"{name}.joblib")) for name in MODEL_NAMES}
label_encoder = artifacts["encoders"]["label"]  # to turn 0/1 back into "attack"/"normal"

# A handful of the most human-readable columns to display in the demo,
# instead of overwhelming the screen with all 40 features.
DISPLAY_COLS = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "count", "srv_count", "logged_in", "serror_rate"
]


def build_explanation_prompt(features, true_label, predictions):
    feature_lines = "\n".join(f"- {k}: {v}" for k, v in features.items())
    prediction_lines = "\n".join(
        f"- {name}: {info['prediction']} ({info['confidence'] * 100:.1f}% confidence)"
        for name, info in predictions.items()
    )
    return (
        "You are an expert network intrusion detection assistant. "
        "A user has a network traffic sample and model predictions. "
        "Explain whether this record is malicious or benign, which models agree or disagree, "
        "and which feature values look important. Keep the answer concise and user-friendly.\n\n"
        f"Features:\n{feature_lines}\n\n"
        f"Ground truth: {true_label}\n\n"
        f"Model predictions:\n{prediction_lines}\n"
    )


def local_ai_explanation(features, true_label, predictions):
    votes = [info["prediction"] for info in predictions.values()]
    attack_votes = votes.count("attack")
    normal_votes = votes.count("normal")
    majority = "attack" if attack_votes > normal_votes else "normal"
    issues = []
    if features.get("logged_in") == 0:
        issues.append("no login activity")
    if features.get("serror_rate", 0) > 0.5:
        issues.append("a high TCP error rate")
    if features.get("protocol_type") in ("icmp", "udp"):
        issues.append("non-TCP traffic")
    if features.get("dst_bytes", 0) > 10000:
        issues.append("large destination byte volume")

    reason = (
        f"It also shows {', '.join(issues)}." if issues else
        "The record has feature values that models often use for attack detection."
    )
    agreement = "The models agree on the verdict." if attack_votes == 0 or normal_votes == 0 else "The models are not unanimous, so this sample is somewhat ambiguous."
    return (
        f"The models lean toward {majority} traffic. {reason} Ground truth is {true_label}. {agreement}"
    )


def get_ai_explanation(features, true_label, predictions):
    if openai is not None and OPENAI_API_KEY:
        openai.api_key = OPENAI_API_KEY
        try:
            prompt = build_explanation_prompt(features, true_label, predictions)
            response = openai.ChatCompletion.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are an assistant that explains network intrusion detection traffic samples."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.4,
                max_tokens=250,
            )
            return response.choices[0].message.content.strip()
        except Exception as exc:
            return f"AI explanation failed: {exc}. Falling back to local explanation."
    return local_ai_explanation(features, true_label, predictions)


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
            # This column was label-encoded (0/1/2...) before scaling, so
            # after inverse-scaling it's a float close to an integer code.
            # Decode it back to the original word (tcp/udp/icmp) for display.
            code = int(round(val))
            display_features[col] = artifacts["encoders"]["protocol_type"].inverse_transform([code])[0]
        else:
            display_features[col] = round(val, 3)

    ai_explanation = get_ai_explanation(display_features, true_label_name, predictions)

    return jsonify({
        "features": display_features,
        "true_label": true_label_name,
        "predictions": predictions,
        "ai_explanation": ai_explanation,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
