#  Network Intrusion Detection System

A machine learning powered Network Intrusion Detection System (NIDS) with a friendly web dashboard. Feed it a network connection's traffic features and it tells you ,in plain English,  whether that traffic looks normal or malicious, how confident it is, and what you should do about it.

<p align="center">
  <a href="https://network-intrusion-detection-system-p0ng.onrender.com/"><img src="https://img.shields.io/badge/demo-live-brightgreen" alt="Live Demo"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/flask-3.x-black" alt="Flask">
  <img src="https://img.shields.io/badge/scikit--learn-1.5-orange" alt="scikit-learn">
  <img src="https://img.shields.io/github/stars/Sibasish11/Network-Intrusion-Detection-System?style=social" alt="Stars">
</p>

**[Try the live demo →](https://network-intrusion-detection-system-p0ng.onrender.com/)**

---

## Overview

Under the hood, the app takes the classic network-flow feature set (things like `duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes`, login and error-rate statistics, and host-based traffic aggregates) and runs it through three independently trained classifiers — **Decision Tree**, **Random Forest**, and **Naive Bayes**. Their votes are combined into a consensus verdict and a 0–100% threat score.

On top of that, a rule-based engine flags specific suspicious patterns (incomplete handshakes, error-rate spikes, failed logins, privilege-escalation attempts, connection bursts, and more), and an optional AI layer , powered by Google Gemini or OpenAI , turns all of it into a short, readable incident report, styled like something a SOC analyst would write. No API key? No problem — a built-in local explanation engine covers the same ground.

## ✨ Features

- **Ensemble detection** : three models vote independently, and their agreement becomes a single threat score
- **Manual inspection** : enter your own connection features and get an instant verdict
- **Random sample explorer** : pull a real record from the held-out test set and compare the prediction against the ground-truth label
- **Curated presets** : one click example traffic scenarios, handy for quick demos
- **Rule-based risk factors** : surfaces handshake anomalies, error-rate spikes, failed logins, root-shell attempts, and connection bursts without needing an LLM
- **AI SOC analyst** : optional Gemini/OpenAI integration writes a plain-English threat assessment plus suggested firewall and IDS rules
- **Follow-up chat** : ask the "analyst" why something was flagged, or ask for a ready-to-use `iptables`/Snort rule
- **Works offline** : every feature above still functions with zero API keys configured, just with simpler local explanations

## How It Works

1. Traffic features arrive : typed in manually, chosen from a preset, or pulled at random from the test set.
2. Missing fields are filled with neutral defaults, categorical fields (`protocol_type`, `service`, `flag`) are label-encoded, and the row is scaled with the saved `scaler`.
3. The three models — Decision Tree, Random Forest, Naive Bayes — each classify the row and report a confidence score.
4. Votes combine into a consensus verdict (an "attack" verdict needs at least 2 of 3 models to agree) and a threat score (the average attack probability across all three).
5. A heuristic risk-factor engine checks for known red flags in the raw features.
6. Everything gets handed to the AI explanation layer, which writes a short analyst-style report — or falls back to a local template if no API key is set.

## Tech Stack

| Layer | Tools |
|---|---|
| Backend | Python, Flask, Gunicorn |
| Machine Learning | scikit-learn, pandas, NumPy, joblib |
| AI Explanations | Google Gemini (`google-genai`), OpenAI, with a local rule-based fallback |
| Frontend | HTML/CSS/JS templates rendered by Flask |
| Exploration / Training | Jupyter, matplotlib, seaborn |

## Project Structure

```
Network-Intrusion-Detection-System/
├── app.py              # Flask app — routes, prediction pipeline, AI explanation logic
├── requirements.txt    # Python dependencies
├── models/              # Trained model artifacts (.joblib), encoders, scaler, held-out test data
├── data/                 # Raw and/or processed traffic data used for training
├── dataset/              # Dataset files
├── src/                  # Training & preprocessing scripts / notebooks
├── templates/             # HTML templates (Jinja2)
├── static/                # CSS, JS, and other front-end assets
├── assets/                # Images and supporting assets
└── .gitignore
```

## Getting Started

### Prerequisites

- Python 3.9+

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Sibasish11/Network-Intrusion-Detection-System.git
cd Network-Intrusion-Detection-System

# 2. (Recommended) create and activate a virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Environment Variables (optional)

The app runs fully offline out of the box. If you'd like AI-generated SOC reports instead of the local rule-based ones, set one of the following before starting the app:

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | Enables Google Gemini explanations and chat (defaults to `gemini-2.5-flash`, with automatic fallback models) |
| `OPENAI_API_KEY` | Enables OpenAI (`gpt-3.5-turbo`) explanations if Gemini isn't configured |

You can also paste a Gemini key directly into the web UI — it's only used for that request and isn't required to run the app.

## API Reference

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Serves the main dashboard |
| `GET` | `/api/metadata` | Returns protocol/service/flag options, feature columns, presets, and available models |
| `GET` | `/api/presets` | Returns the list of curated traffic presets |
| `POST` | `/api/predict_manual` | Runs the ensemble on a user-supplied set of features |
| `GET`/`POST` | `/api/random_sample` | Pulls a random row from the held-out test set and compares the prediction to ground truth |
| `POST` | `/api/ai_chat` | Follow-up Q&A with the AI SOC analyst about the current traffic context |

##  Model Details

- Each of the three models is a **binary classifier** — it predicts `normal` vs. `attack`, along with a confidence/probability score.
- The feature set is the classic ~41-column network-flow schema (duration, protocol, service, flag, byte counts, login stats, error rates, host-based aggregates, and so on) familiar from NSL-KDD/KDD-Cup-style intrusion datasets.
- The consensus verdict is `attack` when at least 2 of 3 models agree; the threat score is the average attack probability across all three.
- Specific attack sub-types (DoS, Probe, R2L, U2R) and named techniques (SYN flood, port scan, brute force, etc.) come from the risk-factor heuristics and the AI explanation layer — the classifiers themselves only decide normal vs. attack.

## Ideas for Contributors

A few directions this project could grow in, if you're looking for something to build:

- [ ] Native multi-class classification (DoS / Probe / R2L / U2R) instead of heuristic sub-typing
- [ ] Batch CSV upload for analyzing many connections at once
- [ ] A model-comparison view (accuracy, precision, recall, ROC curves)
- [ ] A `Dockerfile` for one-command deployment

## Contributing

Contributions are welcome and appreciated. If you'd like to help out:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-idea`)
3. Commit your changes
4. Open a pull request describing what you changed and why

Bug reports and feature suggestions are just as welcome as code — feel free to open an issue.
