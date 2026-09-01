import os
import joblib
import random
import json
import pandas as pd
import requests
from flask import Flask, render_template, request, jsonify

# Optional google-genai SDK
try:
    from google import genai
except ImportError:
    genai = None

try:
    import openai
except ImportError:
    openai = None

app = Flask(__name__)

MODELS_DIR = "models"
MODEL_NAMES = ["decision_tree", "random_forest", "naive_bayes"]
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_FALLBACK_MODELS = ["gemini-3.7-flash", "gemini-2.5-flash-lite"]

# Load model artifacts once at startup
artifacts = joblib.load(os.path.join(MODELS_DIR, "artifacts.joblib"))
X_test, y_test, X_test_raw = joblib.load(os.path.join(MODELS_DIR, "test_data.joblib"))
models = {name: joblib.load(os.path.join(MODELS_DIR, f"{name}.joblib")) for name in MODEL_NAMES}
label_encoder = artifacts["encoders"]["label"]  # 0: attack, 1: normal or vice versa
feature_cols = artifacts["feature_cols"]
encoders = artifacts["encoders"]
scaler = artifacts["scaler"]

# Human-friendly columns for quick overview
DISPLAY_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "logged_in", "count", "srv_count", "serror_rate", "rerror_rate",
    "same_srv_rate", "diff_srv_rate", "dst_host_count", "dst_host_srv_count"
]

PRESETS = [
    {
        "id": "normal_http",
        "name": "Normal HTTPS Web Browsing",
        "type": "normal",
        "badge": "Benign",
        "description": "Standard encrypted web traffic with established TCP handshake, successful session, and balanced payload transfer.",
        "features": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
            "src_bytes": 312,
            "dst_bytes": 4820,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 6,
            "srv_count": 6,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 35,
            "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.03,
            "dst_host_srv_diff_host_rate": 0.04,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    }
]



def extract_risk_factors(features):
    """Identifies heuristics and suspicious patterns in the provided features."""
    risks = []
    
    # Check flags and error rates
    flag = str(features.get("flag", "SF")).upper()
    if flag in ["S0", "S1", "S2", "S3"]:
        risks.append({"title": "Incomplete TCP Handshake", "desc": f"Connection state '{flag}' indicates SYN received without completing ACK sequence (classic SYN flood signature).", "severity": "high"})
    elif flag in ["REJ", "RSTO", "RSTR"]:
        risks.append({"title": "Connection Rejected / Reset", "desc": f"Flag '{flag}' indicates connection was forcibly reset or refused by the destination host.", "severity": "medium"})

    # Check error rates
    serror = float(features.get("serror_rate", 0))
    if serror > 0.4:
        risks.append({"title": "Elevated SYN Error Rate", "desc": f"SYN error rate is {serror * 100:.1f}%, indicating potential spoofing or network exhaustion.", "severity": "high"})

    rerror = float(features.get("rerror_rate", 0))
    if rerror > 0.4:
        risks.append({"title": "High REJ Error Rate", "desc": f"Host connection reject rate is {rerror * 100:.1f}%, often linked to automated port probing.", "severity": "high"})

    
    failed_logins = int(features.get("num_failed_logins", 0))
    if failed_logins > 0:
        risks.append({"title": "Failed Authentication Sequence", "desc": f"{failed_logins} failed login attempt(s) detected on destination service.", "severity": "high" if failed_logins >= 3 else "medium"})

    if int(features.get("root_shell", 0)) == 1 or int(features.get("su_attempted", 0)) > 0:
        risks.append({"title": "Privilege Escalation Activity", "desc": "Root shell access or su execution requested during session.", "severity": "critical"})

    if int(features.get("num_compromised", 0)) > 0:
        risks.append({"title": "Host Compromise State", "desc": f"{features.get('num_compromised')} compromised system condition(s) recorded.", "severity": "critical"})

    # Connection volume
    count = float(features.get("count", 0))
    if count > 150:
        risks.append({"title": "Abnormal Connection Burst", "desc": f"{int(count)} connections recorded to same destination in short time window.", "severity": "high" if count > 300 else "medium"})

    # Zero payload traffic
    src_bytes = float(features.get("src_bytes", 0))
    dst_bytes = float(features.get("dst_bytes", 0))
    if features.get("protocol_type") == "tcp" and src_bytes == 0 and dst_bytes == 0 and count > 50:
        risks.append({"title": "Zero-Payload Probing", "desc": "0 bytes transferred despite multiple active connection requests.", "severity": "medium"})

    if not risks:
        risks.append({"title": "Standard Traffic Signature", "desc": "No abnormal error rates, zero payload anomalies, or failed authentications observed.", "severity": "info"})

    return risks


def build_explanation_prompt(features, true_label, predictions, consensus_verdict, threat_score):
    feature_lines = "\n".join(f"- {k}: {v}" for k, v in features.items())
    prediction_lines = "\n".join(
        f"- {name.replace('_', ' ').title()}: {info['prediction'].upper()} ({info['confidence'] * 100:.1f}% confidence)"
        for name, info in predictions.items()
    )
    ground_truth_str = f"Ground Truth Dataset Label: {true_label}\n" if true_label else "Mode: User Manual Input Inspection\n"
    
    return (
        "You are an elite Senior Cybersecurity Incident Responder & SOC Analyst. "
        "Analyze the following network traffic telemetry and machine learning intrusion detection predictions.\n\n"
        f"Consensus Verdict: {consensus_verdict.upper()} (Threat Score: {threat_score:.1f}%)\n"
        f"{ground_truth_str}"
        f"Model Predictions:\n{prediction_lines}\n\n"
        f"Key Network Features:\n{feature_lines}\n\n"
        "Provide a concise, professional, and visually structured security analysis formatted in clear Markdown:\n"
        "1. **Threat Assessment & Executive Verdict**: State clearly if this is malicious or benign and whether models reached consensus.\n"
        "2. **Root Cause & Technical Telemetry Analysis**: Explain specifically which parameters (e.g. error rates, connection flags, login states, byte counts) explain the verdict.\n"
        "3. **Attack Classification (if malicious)**: Identify the attack type (e.g. SYN Flood DoS, Nmap Port Scan, FTP Brute Force, Probe/R2L/U2R).\n"
        "4. **Recommended SOC Countermeasures**: Specific actionable firewall (iptables/snort), rate-limiting, or ACL rule recommendations."
    )


def local_ai_explanation(features, true_label, predictions, consensus_verdict, threat_score):
    votes = [info["prediction"] for info in predictions.values()]
    attack_votes = votes.count("attack")
    normal_votes = votes.count("normal")
    
    reasons = []
    flag = str(features.get("flag", "SF")).upper()
    if flag in ["S0", "S1", "S2", "S3"]:
        reasons.append(f"TCP connection state '{flag}' indicates half-open SYN packets without handshake completion")
    if float(features.get("serror_rate", 0)) > 0.3:
        reasons.append(f"high TCP SYN error rate ({float(features.get('serror_rate', 0))*100:.1f}%)")
    if float(features.get("rerror_rate", 0)) > 0.3:
        reasons.append(f"high connection rejection rate ({float(features.get('rerror_rate', 0))*100:.1f}%)")
    if int(features.get("num_failed_logins", 0)) > 0:
        reasons.append(f"{features.get('num_failed_logins')} failed login attempt(s)")
    if int(features.get("root_shell", 0)) == 1:
        reasons.append("root shell privilege escalation attempt")
    if float(features.get("count", 0)) > 150:
        reasons.append(f"high connection density burst ({int(features.get('count', 0))} connections)")
    if features.get("logged_in") == 0 and features.get("protocol_type") == "tcp" and float(features.get("dst_bytes", 0)) == 0 and float(features.get("src_bytes", 0)) == 0:
        reasons.append("zero payload transmission across unauthenticated sessions")

    agreement = "All 3 machine learning models reached complete consensus." if (attack_votes == 3 or normal_votes == 3) else f"Split decision: {attack_votes} model(s) flagged attack vs {normal_votes} normal."
    
    status_headline = "🚨 **MALICIOUS THREAT DETECTED**" if consensus_verdict == "attack" else "🛡️ **BENIGN NETWORK TRAFFIC**"
    
    explanation_parts = [
        f"{status_headline}\n\n",
        f"**Consensus Threat Score**: `{threat_score:.1f}%` ({agreement})\n\n",
        "### Key Findings\n"
    ]
    
    if reasons:
        for r in reasons:
            explanation_parts.append(f"- **Telemetry Alert**: Identified {r}.\n")
    else:
        explanation_parts.append("- **Telemetry Alert**: Standard traffic pattern consistent with normal established service operations.\n")

    if consensus_verdict == "attack":
        explanation_parts.append("\n### Recommended Actions\n")
        explanation_parts.append("- Implement rate-limiting or drop SYN packets from suspect source CIDR.\n")
        explanation_parts.append("- Review firewall access control lists (ACLs) and enable SYN cookies.\n")
        explanation_parts.append("- Inspect host authentication audit logs for unauthorized credential brute forcing.")
    else:
        explanation_parts.append("\n### Status\n- Traffic passes baseline security criteria. No immediate mitigation required.")

    return "".join(explanation_parts)


def call_gemini_api(api_key, prompt):
    """Calls Gemini API using google-genai SDK or direct REST API."""
    if not api_key:
        return None
        
    # Attempt 1: Using google-genai SDK
    if genai is not None:
        try:
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt
            )
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            # Fallback to secondary model if needed
            for fallback in GEMINI_FALLBACK_MODELS:
                try:
                    response = client.models.generate_content(
                        model=fallback,
                        contents=prompt
                    )
                    if response and response.text:
                        return response.text.strip()
                except Exception:
                    pass

    # Attempt 2: Direct REST endpoint (zero SDK dependency risk)
    for model_name in [GEMINI_MODEL] + GEMINI_FALLBACK_MODELS:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [
                    {
                        "parts": [
                            {"text": prompt}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 1024
                }
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and "text" in parts[0]:
                        return parts[0]["text"].strip()
            elif resp.status_code == 400 or resp.status_code == 403:
                # Key error or permission error
                err_msg = resp.json().get("error", {}).get("message", resp.text)
                return f"⚠️ **Gemini API Error**: {err_msg}. Check your API Key."
        except Exception as req_err:
            continue

    return None


def get_ai_explanation(features, true_label, predictions, consensus_verdict, threat_score, client_api_key=None):
    api_key = client_api_key or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")
    
    if api_key:
        prompt = build_explanation_prompt(features, true_label, predictions, consensus_verdict, threat_score)
        gemini_result = call_gemini_api(api_key, prompt)
        if gemini_result:
            return gemini_result
            
        # Fallback to OpenAI if configured
        if openai is not None and (api_key.startswith("sk-") or os.getenv("OPENAI_API_KEY")):
            try:
                oa_key = os.getenv("OPENAI_API_KEY") or api_key
                openai.api_key = oa_key
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a senior SOC analyst explaining network intrusion detection telemetry."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=400
                )
                return response.choices[0].message.content.strip()
            except Exception:
                pass

    return local_ai_explanation(features, true_label, predictions, consensus_verdict, threat_score)


def process_features_and_predict(raw_features):
    """Takes a dictionary of raw features, encodes, scales, and runs all 3 ML models."""
    # Complete missing features with neutral defaults
    complete_row = {col: 0.0 for col in feature_cols}
    complete_row.update(raw_features)
    
    # Encode categorical fields
    for cat_col in ["protocol_type", "service", "flag"]:
        val = complete_row.get(cat_col, "tcp")
        enc = encoders[cat_col]
        if isinstance(val, str):
            if val in enc.classes_:
                complete_row[cat_col] = enc.transform([val])[0]
            else:
                complete_row[cat_col] = 0
        else:
            try:
                complete_row[cat_col] = int(val)
            except (ValueError, TypeError):
                complete_row[cat_col] = 0

    # Ensure all columns are numeric
    for col in feature_cols:
        try:
            complete_row[col] = float(complete_row[col])
        except (ValueError, TypeError):
            complete_row[col] = 0.0

    df_single = pd.DataFrame([complete_row])[feature_cols]
    df_scaled = df_single.copy()
    df_scaled[feature_cols] = scaler.transform(df_single[feature_cols])

    predictions = {}
    attack_scores = []
    
    for name, model in models.items():
        pred_code = int(model.predict(df_scaled)[0])
        pred_label = label_encoder.inverse_transform([pred_code])[0]
        
        # Probabilities
        proba = model.predict_proba(df_scaled)[0]
        classes = list(label_encoder.classes_)
        attack_idx = classes.index("attack") if "attack" in classes else 0
        attack_prob = float(proba[attack_idx])
        conf = float(max(proba))
        
        attack_scores.append(attack_prob)
        predictions[name] = {
            "prediction": pred_label,
            "confidence": conf,
            "attack_probability": attack_prob
        }

    # Consensus threat score: average attack probability
    threat_score = (sum(attack_scores) / len(attack_scores)) * 100
    attack_votes = sum(1 for p in predictions.values() if p["prediction"] == "attack")
    consensus_verdict = "attack" if attack_votes >= 2 else "normal"
    
    return {
        "predictions": predictions,
        "threat_score": round(threat_score, 1),
        "consensus_verdict": consensus_verdict,
        "attack_votes": attack_votes,
        "total_models": len(models)
    }


# =====================================================================
# ROUTES & APIS
# =====================================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/metadata")
def get_metadata():
    return jsonify({
        "protocols": list(encoders["protocol_type"].classes_),
        "services": sorted(list(encoders["service"].classes_)),
        "flags": list(encoders["flag"].classes_),
        "feature_cols": feature_cols,
        "display_cols": DISPLAY_COLS,
        "presets": PRESETS,
        "models": list(models.keys())
    })


@app.route("/api/presets")
def get_presets():
    return jsonify(PRESETS)


@app.route("/api/predict_manual", methods=["POST"])
def predict_manual():
    try:
        data = request.get_json(force=True) or {}
        user_features = data.get("features", {})
        gemini_key = data.get("gemini_api_key") or request.headers.get("X-Gemini-Api-Key")
        
        if not user_features:
            return jsonify({"error": "No features provided"}), 400

        result = process_features_and_predict(user_features)
        risks = extract_risk_factors(user_features)
        
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
            gemini_key = request.args.get("gemini_api_key") or request.headers.get("X-Gemini-Api-Key")

        idx = random.randint(0, len(X_test) - 1)
        row = X_test.iloc[[idx]]
        true_label_code = int(y_test.iloc[idx])
        true_label_name = label_encoder.inverse_transform([true_label_code])[0]

        predictions = {}
        attack_scores = []
        classes = list(label_encoder.classes_)
        attack_idx = classes.index("attack") if "attack" in classes else 0

        for name, model in models.items():
            pred = int(model.predict(row)[0])
            pred_name = label_encoder.inverse_transform([pred])[0]
            proba = model.predict_proba(row)[0]
            attack_prob = float(proba[attack_idx])
            attack_scores.append(attack_prob)
            
            predictions[name] = {
                "prediction": pred_name,
                "confidence": float(max(proba)),
                "attack_probability": attack_prob,
                "is_correct": bool(pred_name == true_label_name)
            }

        threat_score = round((sum(attack_scores) / len(attack_scores)) * 100, 1)
        attack_votes = sum(1 for p in predictions.values() if p["prediction"] == "attack")
        consensus_verdict = "attack" if attack_votes >= 2 else "normal"

        raw_row = X_test_raw.iloc[[idx]]
        display_features = {}
        all_features = {}
        
        for col in feature_cols:
            if col not in raw_row.columns:
                continue
            val = float(raw_row[col].values[0])
            if col in ["protocol_type", "service", "flag"]:
                code = int(round(val))
                try:
                    name_val = encoders[col].inverse_transform([code])[0]
                except Exception:
                    name_val = str(code)
                all_features[col] = name_val
                if col in DISPLAY_COLS:
                    display_features[col] = name_val
            else:
                num_val = round(val, 3) if val < 10 else int(round(val))
                all_features[col] = num_val
                if col in DISPLAY_COLS:
                    display_features[col] = num_val

        risks = extract_risk_factors(all_features)

        ai_explanation = get_ai_explanation(
            features=display_features,
            true_label=true_label_name,
            predictions=predictions,
            consensus_verdict=consensus_verdict,
            threat_score=threat_score,
            client_api_key=gemini_key
        )

        return jsonify({
            "status": "success",
            "sample_index": idx,
            "features": display_features,
            "all_features": all_features,
            "true_label": true_label_name,
            "predictions": predictions,
            "threat_score": threat_score,
            "consensus_verdict": consensus_verdict,
            "attack_votes": attack_votes,
            "risk_factors": risks,
            "ai_explanation": ai_explanation,
            "mode": "test_dataset"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai_chat", methods=["POST"])
def ai_chat():
    """Interactive SOC Analyst Chat for follow-up questions."""
    try:
        data = request.get_json(force=True) or {}
        user_message = data.get("message", "").strip()
        context = data.get("context", {})
        gemini_key = data.get("gemini_api_key") or request.headers.get("X-Gemini-Api-Key") or os.getenv("GEMINI_API_KEY")
        
        if not user_message:
            return jsonify({"error": "Message cannot be empty"}), 400

        # Construct contextual prompt for conversational SOC assistant
        prompt = (
            "You are an expert Cybersecurity SOC Analyst & Incident Response Assistant for a Network Intrusion Detection System (NIDS).\n"
            f"Active Network Traffic Context:\n"
            f"- Consensus Verdict: {context.get('consensus_verdict', 'Unknown').upper()}\n"
            f"- Threat Score: {context.get('threat_score', 'N/A')}%\n"
            f"- Model Predictions: {json.dumps(context.get('predictions', {}))}\n"
            f"- Network Features: {json.dumps(context.get('features', {}))}\n\n"
            f"User Question: {user_message}\n\n"
            "Provide a crisp, direct, and actionable answer. Include specific technical details, packet analysis, or firewall rules (e.g., iptables, snort, pfSense) where appropriate."
        )

        if gemini_key:
            reply = call_gemini_api(gemini_key, prompt)
            if reply:
                return jsonify({"status": "success", "reply": reply})

        # Local intelligent heuristic fallback for common questions
        msg_lower = user_message.lower()
        if "firewall" in msg_lower or "rule" in msg_lower or "block" in msg_lower or "iptables" in msg_lower:
            protocol = context.get('features', {}).get('protocol_type', 'tcp')
            service = context.get('features', {}).get('service', 'any')
            reply = (
                "### 🛡️ Recommended Firewall Mitigation Rules\n\n"
                f"Based on the analyzed `{protocol}` traffic targeting `{service}`:\n\n"
                "**1. Linux iptables Rule (Rate-limit suspicious bursts):**\n"
                "```bash\n"
                f"iptables -A INPUT -p {protocol} -m state --state NEW -m limit --limit 20/minute --limit-burst 100 -j ACCEPT\n"
                f"iptables -A INPUT -p {protocol} -m state --state NEW -j DROP\n"
                "```\n\n"
                "**2. Snort IDS Signature:**\n"
                "```snort\n"
                f'alert {protocol} any any -> $HOME_NET any (msg:"NIDS Alert: Suspicious High-Frequency Connection Burst"; flow:to_server; threshold:type threshold, track by_src, count 50, seconds 5; sid:1000001; rev:1;)\n'
                "```\n\n"
                "*Tip: Provide your Gemini API key in the top bar to get dynamic, bespoke AI rule synthesis!*"
            )
        elif "why" in msg_lower or "reason" in msg_lower or "explain" in msg_lower:
            reply = (
                "### 🔍 Telemetry Breakdown\n\n"
                f"The models evaluated the session features. High connection rates (`count`), uncompleted handshakes (`flag`), "
                f"or elevated SYN/REJ errors trigger high tree split activations in Random Forest and Decision Trees.\n\n"
                "Provide a Gemini API Key in the top header to unlock deep reasoning models for step-by-step feature importance trees."
            )
        else:
            reply = (
                f"### SOC Analyst Note\n\n"
                f"Regarding `{user_message}`: The current traffic profile has a threat score of **{context.get('threat_score', 0)}%**.\n"
                f"To enable real-time conversational reasoning with Gemini 2.5/3.7, enter your Gemini API Key in the top-right manager."
            )

        return jsonify({"status": "success", "reply": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)

