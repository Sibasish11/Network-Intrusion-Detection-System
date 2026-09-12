import os
import warnings
warnings.filterwarnings("ignore")
from flask import Flask, render_template, request, jsonify

from src.engine import (
    get_engine, PRESETS, DISPLAY_COLS,
    get_ai_explanation, ask_soc_analyst_chat,
    get_stored_gemini_key, set_stored_gemini_key
)

app = Flask(__name__)
engine = get_engine()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/metadata")
def get_metadata():
    return jsonify({
        "protocols": list(engine.encoders["protocol_type"].classes_),
        "services": sorted(list(engine.encoders["service"].classes_)),
        "flags": list(engine.encoders["flag"].classes_),
        "feature_cols": engine.feature_cols,
        "display_cols": DISPLAY_COLS,
        "presets": PRESETS,
        "models": list(engine.models.keys())
    })


@app.route("/api/presets")
def get_presets():
    return jsonify(PRESETS)


@app.route("/api/predict_manual", methods=["POST"])
def predict_manual():
    try:
        data = request.get_json(force=True) or {}
        user_features = data.get("features", {})
        gemini_key = data.get("gemini_api_key") or request.headers.get("X-Gemini-Api-Key") or get_stored_gemini_key()
        
        if not user_features:
            return jsonify({"error": "No features provided"}), 400

        result = engine.predict_features(user_features)
        risks = engine.extract_risk_factors(user_features)
        
        ai_explanation = get_ai_explanation(
            features=user_features,
            true_label=None,
            predictions=result["predictions"],
            consensus_verdict=result["consensus_verdict"],
            threat_score=result["threat_score"],
            client_api_key=gemini_key
        )

        return jsonify({
            "status": "success",
            "features": user_features,
            "predictions": result["predictions"],
            "threat_score": result["threat_score"],
            "consensus_verdict": result["consensus_verdict"],
            "attack_votes": result["attack_votes"],
            "risk_factors": risks,
            "ai_explanation": ai_explanation,
            "mode": "manual"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/random_sample", methods=["GET", "POST"])
def random_sample():
    try:
        gemini_key = None
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            gemini_key = data.get("gemini_api_key")
        if not gemini_key:
            gemini_key = request.args.get("gemini_api_key") or request.headers.get("X-Gemini-Api-Key") or get_stored_gemini_key()

        sample_data = engine.get_sample()
        
        ai_explanation = get_ai_explanation(
            features=sample_data["features"],
            true_label=sample_data["true_label"],
            predictions=sample_data["predictions"],
            consensus_verdict=sample_data["consensus_verdict"],
            threat_score=sample_data["threat_score"],
            client_api_key=gemini_key
        )
        sample_data["ai_explanation"] = ai_explanation
        sample_data["status"] = "success"
        sample_data["mode"] = "test_dataset"

        return jsonify(sample_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai_chat", methods=["POST"])
def ai_chat():
    """Interactive SOC Analyst Chat for follow-up questions."""
    try:
        data = request.get_json(force=True) or {}
        user_message = data.get("message", "").strip()
        context = data.get("context", {})
        gemini_key = data.get("gemini_api_key") or request.headers.get("X-Gemini-Api-Key") or get_stored_gemini_key()
        
        if not user_message:
            return jsonify({"error": "Message cannot be empty"}), 400

        reply = ask_soc_analyst_chat(user_message, context, api_key=gemini_key)
        return jsonify({"status": "success", "reply": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
