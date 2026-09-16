import os
import json
import random
import warnings
warnings.filterwarnings("ignore")
import joblib
import pandas as pd
import requests

try:
    from google import genai
except ImportError:
    genai = None

try:
    import openai
except ImportError:
    openai = None

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".nids_config.json")
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_NAMES = ["decision_tree", "random_forest", "naive_bayes"]

GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_FALLBACK_MODELS = ["gemini-3.7-flash", "gemini-2.5-flash-lite"]

DISPLAY_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "logged_in", "count", "srv_count", "serror_rate", "rerror_rate",
    "same_srv_rate", "diff_srv_rate", "dst_host_count", "dst_host_srv_count"
]

PRESETS = [
    {
        "id": "normal_http",
        "name": "Normal HTTPS Web Browsing",
        "category": "Benign",
        "type": "normal",
        "badge": "Benign Traffic",
        "description": "Standard encrypted web session with completed TCP 3-way handshake, normal payload transfer, and zero authentication anomalies.",
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
    },
    {
        "id": "normal_ssh",
        "name": "Normal Secure Shell (SSH) Admin Session",
        "category": "Benign",
        "type": "normal",
        "badge": "Benign Admin",
        "description": "Authenticated interactive SSH management terminal session with low packet volume and verified login credentials.",
        "features": {
            "duration": 42,
            "protocol_type": "tcp",
            "service": "ssh",
            "flag": "SF",
            "src_bytes": 1840,
            "dst_bytes": 2420,
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
            "count": 2,
            "srv_count": 2,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 12,
            "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.08,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    {
        "id": "syn_flood",
        "name": "SYN Flood Denial of Service (Neptune DoS)",
        "category": "DoS Attack",
        "type": "attack",
        "badge": "High Severity DoS",
        "description": "Massive barrage of half-open TCP SYN connection requests designed to exhaust destination connection backlog queues (S0 flag, 100% SYN error).",
        "features": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "private",
            "flag": "S0",
            "src_bytes": 0,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 312,
            "srv_count": 18,
            "serror_rate": 1.0,
            "srv_serror_rate": 1.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 0.06,
            "diff_srv_rate": 0.07,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255,
            "dst_host_srv_count": 18,
            "dst_host_same_srv_rate": 0.07,
            "dst_host_diff_srv_rate": 0.06,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 1.0,
            "dst_host_srv_serror_rate": 1.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    {
        "id": "port_scan",
        "name": "Nmap Stealth Port Scan / Reconnaissance (Probe)",
        "category": "Reconnaissance",
        "type": "attack",
        "badge": "Probe Attack",
        "description": "Rapid scanning across high port ranges with high connection rejection rates (REJ) and zero payload transfer to map open network daemon services.",
        "features": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "private",
            "flag": "REJ",
            "src_bytes": 0,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 220,
            "srv_count": 2,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 1.0,
            "srv_rerror_rate": 1.0,
            "same_srv_rate": 0.01,
            "diff_srv_rate": 0.72,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255,
            "dst_host_srv_count": 2,
            "dst_host_same_srv_rate": 0.01,
            "dst_host_diff_srv_rate": 0.09,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 1.0,
            "dst_host_srv_rerror_rate": 1.0
        }
    },
    {
        "id": "ftp_brute_force",
        "name": "FTP Credential Dictionary Brute Force (R2L Attack)",
        "category": "Remote-to-Local",
        "type": "attack",
        "badge": "Brute Force R2L",
        "description": "Repetitive unauthorized login attempts with failed credentials targeting an unencrypted File Transfer Protocol daemon service.",
        "features": {
            "duration": 6,
            "protocol_type": "tcp",
            "service": "ftp",
            "flag": "SF",
            "src_bytes": 220,
            "dst_bytes": 1180,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 3,
            "num_failed_logins": 5,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "is_host_login": 0,
            "is_guest_login": 1,
            "count": 15,
            "srv_count": 15,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 28,
            "dst_host_srv_count": 28,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.04,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    {
        "id": "privilege_escalation",
        "name": "Buffer Overflow / Root Shell Privilege Escalation (U2R)",
        "category": "User-to-Root",
        "type": "attack",
        "badge": "Critical U2R",
        "description": "Exploitation of a local vulnerability to execute shell commands, spawn a root shell, and manipulate restricted system files.",
        "features": {
            "duration": 34,
            "protocol_type": "tcp",
            "service": "telnet",
            "flag": "SF",
            "src_bytes": 2850,
            "dst_bytes": 14600,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 5,
            "num_failed_logins": 0,
            "logged_in": 1,
            "num_compromised": 3,
            "root_shell": 1,
            "su_attempted": 1,
            "num_root": 4,
            "num_file_creations": 2,
            "num_shells": 1,
            "num_access_files": 2,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 1,
            "srv_count": 1,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 1,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 1.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    {
        "id": "smurf_flood",
        "name": "ICMP Broadcast Smurf Amplification Flood (DoS)",
        "category": "DoS Attack",
        "type": "attack",
        "badge": "ICMP Flood",
        "description": "Volumetric ICMP echo amplification attack utilizing broadcast reflection to swamp target bandwidth and CPU processing.",
        "features": {
            "duration": 0,
            "protocol_type": "icmp",
            "service": "ecr_i",
            "flag": "SF",
            "src_bytes": 1032,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 511,
            "srv_count": 511,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255,
            "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 1.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    }
]


class NIDSEngine:
    """Singleton NIDS ML & Telemetry Reasoning Engine."""

    def __init__(self, models_dir=MODELS_DIR):
        self.models_dir = models_dir
        self.artifacts = None
        self.models = {}
        self.X_test = None
        self.y_test = None
        self.X_test_raw = None
        self.label_encoder = None
        self.feature_cols = []
        self.encoders = {}
        self.scaler = None
        self.load_artifacts()

    def load_artifacts(self):
        """Loads trained models, preprocessing encoders, and test data."""
        art_path = os.path.join(self.models_dir, "artifacts.joblib")
        test_path = os.path.join(self.models_dir, "test_data.joblib")

        if not os.path.exists(art_path) or not os.path.exists(test_path):
            raise FileNotFoundError(f"Model artifacts not found in '{self.models_dir}'. Please run 'python src/train.py' first.")

        self.artifacts = joblib.load(art_path)
        self.X_test, self.y_test, self.X_test_raw = joblib.load(test_path)
        self.models = {name: joblib.load(os.path.join(self.models_dir, f"{name}.joblib")) for name in MODEL_NAMES}
        
        self.label_encoder = self.artifacts["encoders"]["label"]
        self.feature_cols = self.artifacts["feature_cols"]
        self.encoders = self.artifacts["encoders"]
        self.scaler = self.artifacts["scaler"]

    def extract_risk_factors(self, features):
        """Identifies heuristics and suspicious patterns in the provided features."""
        risks = []
        
        # Check flags and error rates
        flag = str(features.get("flag", "SF")).upper()
        if flag in ["S0", "S1", "S2", "S3"]:
            risks.append({
                "title": "Incomplete TCP Handshake",
                "desc": f"Connection state '{flag}' indicates SYN packet received without completing ACK sequence (classic SYN flood DoS signature).",
                "severity": "critical" if flag == "S0" else "high"
            })
        elif flag in ["REJ", "RSTO", "RSTR"]:
            risks.append({
                "title": "Connection Rejected / Reset",
                "desc": f"Flag '{flag}' indicates connection was forcibly reset or refused by the target host (typical port scanning behavior).",
                "severity": "high"
            })

        # Error rates
        serror = float(features.get("serror_rate", 0))
        if serror > 0.4:
            risks.append({
                "title": "Elevated SYN Error Rate",
                "desc": f"SYN error rate is {serror * 100:.1f}%, indicating potential half-open exhaustion or address spoofing.",
                "severity": "high"
            })

        rerror = float(features.get("rerror_rate", 0))
        if rerror > 0.4:
            risks.append({
                "title": "High Host Reject Rate",
                "desc": f"Host connection reject rate is {rerror * 100:.1f}%, linked to automated network enumeration / probing.",
                "severity": "high"
            })

        # Authentication & privilege indicators
        failed_logins = int(features.get("num_failed_logins", 0))
        if failed_logins > 0:
            risks.append({
                "title": "Authentication Failure Sequence",
                "desc": f"{failed_logins} failed login attempt(s) detected on target service.",
                "severity": "high" if failed_logins >= 3 else "medium"
            })

        if int(features.get("root_shell", 0)) == 1 or int(features.get("su_attempted", 0)) > 0:
            risks.append({
                "title": "Privilege Escalation Activity",
                "desc": "Root shell access or su execution requested during the session.",
                "severity": "critical"
            })

        if int(features.get("num_compromised", 0)) > 0:
            risks.append({
                "title": "Host Compromise State",
                "desc": f"{features.get('num_compromised')} compromised system condition(s) recorded on host.",
                "severity": "critical"
            })

        # Connection volume
        count = float(features.get("count", 0))
        if count > 150:
            risks.append({
                "title": "Abnormal Connection Burst",
                "desc": f"{int(count)} connection requests recorded to same destination in short time window.",
                "severity": "high" if count > 300 else "medium"
            })

        # Zero payload traffic
        src_bytes = float(features.get("src_bytes", 0))
        dst_bytes = float(features.get("dst_bytes", 0))
        if features.get("protocol_type") == "tcp" and src_bytes == 0 and dst_bytes == 0 and count > 30:
            risks.append({
                "title": "Zero-Payload Probing",
                "desc": "0 bytes transferred despite multiple active connection requests (silent scanner indicator).",
                "severity": "medium"
            })

        if not risks:
            risks.append({
                "title": "Standard Traffic Signature",
                "desc": "No abnormal error rates, zero-payload anomalies, or failed authentications observed.",
                "severity": "info"
            })

        return risks

    def predict_features(self, raw_features):
        """Preprocesses raw dictionary features and runs Decision Tree, Random Forest, Naive Bayes."""
        complete_row = {col: 0.0 for col in self.feature_cols}
        complete_row.update(raw_features)
        
        # Categorical encoding
        for cat_col in ["protocol_type", "service", "flag"]:
            val = complete_row.get(cat_col, "tcp")
            enc = self.encoders[cat_col]
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

        for col in self.feature_cols:
            try:
                complete_row[col] = float(complete_row[col])
            except (ValueError, TypeError):
                complete_row[col] = 0.0

        df_single = pd.DataFrame([complete_row])[self.feature_cols]
        df_scaled = df_single.copy()
        df_scaled[self.feature_cols] = self.scaler.transform(df_single[self.feature_cols])

        predictions = {}
        attack_scores = []
        classes = list(self.label_encoder.classes_)
        attack_idx = classes.index("attack") if "attack" in classes else 0
        
        for name, model in self.models.items():
            pred_code = int(model.predict(df_scaled)[0])
            pred_label = self.label_encoder.inverse_transform([pred_code])[0]
            
            proba = model.predict_proba(df_scaled)[0]
            attack_prob = float(proba[attack_idx])
            conf = float(max(proba))
            
            attack_scores.append(attack_prob)
            predictions[name] = {
                "prediction": pred_label,
                "confidence": conf,
                "attack_probability": attack_prob
            }

        threat_score = round((sum(attack_scores) / len(attack_scores)) * 100, 1)
        attack_votes = sum(1 for p in predictions.values() if p["prediction"] == "attack")
        consensus_verdict = "attack" if attack_votes >= 2 else "normal"
        
        return {
            "predictions": predictions,
            "threat_score": threat_score,
            "consensus_verdict": consensus_verdict,
            "attack_votes": attack_votes,
            "total_models": len(self.models)
        }

    def get_sample(self, index=None):
        """Retrieves a sample from the test dataset by index or at random."""
        total_samples = len(self.X_test)
        idx = random.randint(0, total_samples - 1) if index is None else (index % total_samples)
        
        row = self.X_test.iloc[[idx]]
        true_label_code = int(self.y_test.iloc[idx])
        true_label_name = self.label_encoder.inverse_transform([true_label_code])[0]

        predictions = {}
        attack_scores = []
        classes = list(self.label_encoder.classes_)
        attack_idx = classes.index("attack") if "attack" in classes else 0

        for name, model in self.models.items():
            pred = int(model.predict(row)[0])
            pred_name = self.label_encoder.inverse_transform([pred])[0]
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

        raw_row = self.X_test_raw.iloc[[idx]]
        display_features = {}
        all_features = {}
        
        for col in self.feature_cols:
            if col not in raw_row.columns:
                continue
            val = float(raw_row[col].values[0])
            if col in ["protocol_type", "service", "flag"]:
                code = int(round(val))
                try:
                    name_val = self.encoders[col].inverse_transform([code])[0]
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

        risks = self.extract_risk_factors(all_features)

        return {
            "sample_index": idx,
            "features": display_features,
            "all_features": all_features,
            "true_label": true_label_name,
            "predictions": predictions,
            "threat_score": threat_score,
            "consensus_verdict": consensus_verdict,
            "attack_votes": attack_votes,
            "total_models": len(self.models),
            "risk_factors": risks
        }

    def evaluate_all_models(self):
        """Evaluates all loaded models on the full test dataset and returns metrics and confusion matrices."""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
        results = {}
        
        for name, model in self.models.items():
            y_pred = model.predict(self.X_test)
            acc = accuracy_score(self.y_test, y_pred)
            prec = precision_score(self.y_test, y_pred, pos_label=0, zero_division=0)
            rec = recall_score(self.y_test, y_pred, pos_label=0, zero_division=0)
            f1 = f1_score(self.y_test, y_pred, pos_label=0, zero_division=0)
            cm = confusion_matrix(self.y_test, y_pred)

            results[name] = {
                "name": name,
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1": f1,
                "confusion_matrix": cm.tolist()
            }
        return results


# =====================================================================
# CONFIGURATION & KEY STORAGE
# =====================================================================

def load_config():
    """Loads saved configuration (e.g. API keys) from disk."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_config(key, value):
    """Saves a configuration key-value pair to disk."""
    config = load_config()
    config[key] = value
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Warning: Failed to save config: {e}")


def get_stored_gemini_key():
    config = load_config()
    return config.get("gemini_api_key") or os.getenv("GEMINI_API_KEY")


def set_stored_gemini_key(api_key):
    save_config("gemini_api_key", api_key.strip() if api_key else "")


# =====================================================================
# FIREWALL RULE & COUNTERMEASURE GENERATOR
# =====================================================================

def generate_firewall_rules(features, verdict="attack"):
    """Generates concrete firewall & IDS rules based on packet telemetry."""
    protocol = features.get("protocol_type", "tcp")
    service = features.get("service", "any")
    flag = features.get("flag", "SF")
    
    iptables_rules = []
    snort_rules = []
    nftables_rules = []

    if verdict == "attack":
        if flag in ["S0", "S1", "S2"]:
            iptables_rules.append(f"iptables -A INPUT -p {protocol} --syn -m limit --limit 10/s --limit-burst 30 -j ACCEPT")
            iptables_rules.append(f"iptables -A INPUT -p {protocol} --syn -j DROP")
            snort_rules.append(f'alert {protocol} any any -> $HOME_NET any (msg:"NIDS Alert: TCP SYN Flood Anomaly"; flags:S; threshold:type threshold, track by_src, count 40, seconds 3; sid:1000101; rev:1;)')
            nftables_rules.append(f"nft add rule inet filter input {protocol} flags syn limit rate 10/second burst 30 packets accept")
            nftables_rules.append(f"nft add rule inet filter input {protocol} flags syn drop")
        elif flag in ["REJ", "RSTO"]:
            iptables_rules.append(f"iptables -A INPUT -p {protocol} -m recent --name PORTSCAN --set")
            iptables_rules.append(f"iptables -A INPUT -p {protocol} -m recent --name PORTSCAN --update --seconds 60 --hitcount 20 -j DROP")
            snort_rules.append(f'alert {protocol} any any -> $HOME_NET any (msg:"NIDS Alert: Rapid Port Scan Detection"; flow:stateless; threshold:type threshold, track by_src, count 25, seconds 5; sid:1000102; rev:1;)')
            nftables_rules.append(f"nft add rule inet filter input ct state new,untracked limit rate over 20/minute drop")
        elif features.get("num_failed_logins", 0) > 0:
            iptables_rules.append(f"iptables -A INPUT -p {protocol} -m state --state NEW -m recent --set --name BRUTEFORCE")
            iptables_rules.append(f"iptables -A INPUT -p {protocol} -m state --state NEW -m recent --update --seconds 60 --hitcount 5 --name BRUTEFORCE -j DROP")
            snort_rules.append(f'alert {protocol} any any -> $HOME_NET any (msg:"NIDS Alert: Authentication Brute Force"; content:"Login incorrect"; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000103; rev:1;)')
        else:
            iptables_rules.append(f"iptables -A INPUT -p {protocol} -m limit --limit 25/minute --limit-burst 100 -j ACCEPT")
            iptables_rules.append(f"iptables -A INPUT -p {protocol} -j DROP")
            snort_rules.append(f'alert {protocol} any any -> $HOME_NET any (msg:"NIDS Alert: Anomalous High Density Traffic"; threshold:type threshold, track by_src, count 100, seconds 10; sid:1000104; rev:1;)')
    else:
        iptables_rules.append(f"# Benign traffic pattern - Standard stateful allowance:")
        iptables_rules.append(f"iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
        iptables_rules.append(f"iptables -A INPUT -p {protocol} -m state --state NEW -j ACCEPT")
        snort_rules.append(f'# No malicious signature triggered for verified standard {protocol}/{service} session.')
        nftables_rules.append(f"nft add rule inet filter input ct state established,related accept")

    return {
        "iptables": "\n".join(iptables_rules),
        "snort": "\n".join(snort_rules),
        "nftables": "\n".join(nftables_rules) if nftables_rules else None
    }


# =====================================================================
# AI SOC ANALYST REASONING & CHAT
# =====================================================================

def build_explanation_prompt(features, true_label, predictions, consensus_verdict, threat_score):
    feature_lines = "\n".join(f"- {k}: {v}" for k, v in features.items())
    prediction_lines = "\n".join(
        f"- {name.replace('_', ' ').title()}: {info['prediction'].upper()} ({info['confidence'] * 100:.1f}% confidence)"
        for name, info in predictions.items()
    )
    ground_truth_str = f"Ground Truth Dataset Label: {true_label}\n" if true_label else "Mode: Live / Manual Telemetry Inspection\n"
    
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
        except Exception:
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
                "contents": [{"parts": [{"text": prompt}]}],
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
            elif resp.status_code in (400, 403):
                err_msg = resp.json().get("error", {}).get("message", resp.text)
                return f"Gemini API Warning: {err_msg} (Check your API Key)."
        except Exception:
            continue

    return None


def local_ai_explanation(features, true_label, predictions, consensus_verdict, threat_score):
    """Heuristic fallback SOC analysis when no external LLM API key is provided."""
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
    
    parts = [
        f"{status_headline}\n\n",
        f"**Consensus Threat Score**: `{threat_score:.1f}%` ({agreement})\n\n",
        "### Key Findings\n"
    ]
    
    if reasons:
        for r in reasons:
            parts.append(f"- **Telemetry Alert**: Identified {r}.\n")
    else:
        parts.append("- **Telemetry Alert**: Standard traffic pattern consistent with normal established service operations.\n")

    rules = generate_firewall_rules(features, consensus_verdict)
    if consensus_verdict == "attack":
        parts.append("\n### Recommended Actions & Firewall Rules\n")
        parts.append("```bash\n" + rules["iptables"] + "\n```\n")
        parts.append("```snort\n" + rules["snort"] + "\n```\n")
    else:
        parts.append("\n### Status\n- Traffic passes baseline security criteria. Normal stateful inspection active.")

    return "".join(parts)


def get_ai_explanation(features, true_label, predictions, consensus_verdict, threat_score, client_api_key=None):
    """Retrieves AI SOC explanation via Gemini, OpenAI, or local fallback engine."""
    api_key = client_api_key or get_stored_gemini_key() or os.getenv("OPENAI_API_KEY")
    
    if api_key:
        prompt = build_explanation_prompt(features, true_label, predictions, consensus_verdict, threat_score)
        gemini_result = call_gemini_api(api_key, prompt)
        if gemini_result:
            return gemini_result
            
        # Fallback to OpenAI if key starts with sk-
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


def ask_soc_analyst_chat(user_message, context=None, api_key=None):
    """Answers user SOC cybersecurity questions using Gemini, OpenAI, or local knowledge."""
    context = context or {}
    key = api_key or get_stored_gemini_key() or os.getenv("OPENAI_API_KEY")
    
    prompt = (
        "You are an expert Cybersecurity SOC Analyst & Incident Response Assistant for a Network Intrusion Detection System (NIDS).\n"
        f"Active Network Traffic Context:\n"
        f"- Consensus Verdict: {context.get('consensus_verdict', 'Unknown').upper()}\n"
        f"- Threat Score: {context.get('threat_score', 'N/A')}%\n"
        f"- Model Predictions: {json.dumps(context.get('predictions', {}))}\n"
        f"- Network Features: {json.dumps(context.get('features', {}))}\n\n"
        f"User Question: {user_message}\n\n"
        "Provide a crisp, direct, and actionable answer. Include specific technical details, packet analysis, or firewall rules (e.g., iptables, snort, pfSense, nftables) where appropriate."
    )

    if key:
        reply = call_gemini_api(key, prompt)
        if reply:
            return reply

    # Local Intelligent Fallback
    msg_lower = user_message.lower()
    features = context.get('features', {})
    verdict = context.get('consensus_verdict', 'normal')

    if any(w in msg_lower for w in ["firewall", "rule", "block", "iptables", "snort", "mitigat"]):
        rules = generate_firewall_rules(features, verdict)
        return (
            "### 🛡️ Recommended Firewall Mitigation Rules\n\n"
            "**1. Linux iptables Rule:**\n"
            f"```bash\n{rules['iptables']}\n```\n\n"
            "**2. Snort IDS Signature:**\n"
            f"```snort\n{rules['snort']}\n```\n\n"
            "*(Tip: Configure a Gemini API Key to unlock real-time contextual policy synthesis!)*"
        )
    elif any(w in msg_lower for w in ["why", "reason", "explain", "how"]):
        return (
            "### 🔍 Telemetry Breakdown & ML Logic\n\n"
            f"- **Threat Score**: {context.get('threat_score', 0)}%\n"
            f"- **Verdict**: {verdict.upper()}\n"
            "High connection count bursts (`count`), uncompleted SYN handshakes (`flag`=S0), and elevated error rates "
            "trigger deep split branches in Random Forest and Decision Tree estimators.\n\n"
            "*(Set a Gemini API Key in Settings to enable deep multi-turn LLM threat investigations.)*"
        )
    else:
        return (
            f"### 🛡️ SOC Analyst Note\n\n"
            f"Telemetry Profile Threat Score is **{context.get('threat_score', 0)}%** ({verdict.upper()}).\n"
            f"Query: `{user_message}`\n\n"
            "To activate full bidirectional LLM cyber intelligence in the terminal, configure your Gemini API Key in option 7."
        )


# Singleton instance helper
_engine_instance = None

def get_engine():
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = NIDSEngine()
    return _engine_instance
