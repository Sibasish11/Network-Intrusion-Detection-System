# Product Requirements Document
## Network Intrusion Detection System (NIDS)

| | |
|---|---|
| **Status** | Draft |
| **Version** | 0.1 |
| **Repository** | Network-Intrusion-Detection-System |
| **Location** | `dataset/CIC Research/prd.md` |
| **Last updated** | September 2026 |

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals & Objectives](#3-goals--objectives)
4. [Scope](#4-scope)
5. [Users & Stakeholders](#5-users--stakeholders)
6. [Dataset](#6-dataset)
7. [Functional Requirements](#7-functional-requirements)
8. [Non-Functional Requirements](#8-non-functional-requirements)
9. [Technical Approach](#9-technical-approach)
10. [Success Metrics](#10-success-metrics)
11. [Milestones & Timeline](#11-milestones--timeline)
12. [Risks & Assumptions](#12-risks--assumptions)
13. [Future Enhancements](#13-future-enhancements)
14. [References](#14-references)

---

## 1. Executive Summary

This project delivers a machine-learning-based **Network Intrusion Detection System (NIDS)** that classifies network traffic as either benign or one of four attack categories — **DoS**, **Probe**, **R2L**, and **U2R** — using features derived from the CIC dataset. Three classifiers — **Random Forest**, **SVM**, and **XGBoost** — are trained on the same data and benchmarked against each other so the best-performing model (or a combination of them) can be recommended for detection use.

The deliverable is a reproducible research pipeline covering data ingestion, preprocessing, feature selection, model training, evaluation, and comparison, along with documentation that lets others reproduce and extend the results.

## 2. Problem Statement

Traditional signature-based intrusion detection struggles against novel or disguised attacks and tends to generate a high volume of false positives. Machine-learning-based detection can learn patterns directly from labeled traffic data and generalize better to attack variants — but only if:

- The training data is representative of real attack behavior.
- Class imbalance (attacks are rare relative to benign traffic) is handled correctly.
- Models are evaluated with metrics that reflect security priorities — e.g., recall on rare attack classes matters more than raw accuracy, since a missed attack is far costlier than a false alarm.

This project addresses the problem by building and comparing multiple classifiers on a labeled intrusion dataset, with particular attention to correctly identifying minority attack classes (typically **U2R** and **R2L**, which are the rarest and hardest to detect).

## 3. Goals & Objectives

| Goal | Description |
|---|---|
| G1 | Build a clean, reproducible data pipeline from raw CIC dataset files to model-ready features |
| G2 | Train and tune three classifiers — Random Forest, SVM, XGBoost — on the same feature set |
| G3 | Evaluate and compare models using metrics appropriate for imbalanced, multi-class security data |
| G4 | Identify the best-performing model (or combination) for each attack category |
| G5 | Document findings so the pipeline can be reused, extended, or deployed later |

**Non-goals for this phase:** real-time packet capture, production deployment, or live sensor integration (see [Scope](#4-scope)).

## 4. Scope

### In Scope
- Data loading and cleaning for the CIC dataset
- Feature engineering / feature selection (e.g., correlation filtering, importance ranking)
- Handling class imbalance (e.g., SMOTE, class weighting, undersampling)
- Training Random Forest, SVM, and XGBoost classifiers
- Multi-class classification across Normal, DoS, Probe, R2L, and U2R
- Model evaluation, comparison, and reporting
- Documented, reusable notebooks/scripts

### Out of Scope
- Live network traffic capture or real-time inference
- Deployment as a production security appliance
- Deep learning approaches (candidate for a future phase)
- Integration with SIEM/SOC tooling

## 5. Users & Stakeholders

| Role | Interest |
|---|---|
| Project author / researcher | A working, well-evaluated classification pipeline |
| Security/ML students reading the repo | A documented, reproducible IDS research example |
| Future contributors | A pipeline they can extend — new models, real-time inference, new datasets |

## 6. Dataset

### 6.1 Source
The project uses network traffic data from the **CIC (Canadian Institute for Cybersecurity) dataset** family. Once the specific file(s) are added under `dataset/CIC Research/`, this section should name the exact release (e.g., CICIDS2017, CICIDS2018) and its column schema, since feature sets differ between CIC releases.

### 6.2 Attack Categories

| Category | Full name | Description |
|---|---|---|
| Normal | — | Benign, non-malicious traffic |
| DoS | Denial of Service | Traffic that overwhelms a service or host to deny it to legitimate users |
| Probe | Probing / Surveillance | Reconnaissance traffic that scans hosts and ports to find vulnerabilities |
| R2L | Remote to Local | An attacker without a local account attempts to gain local access to a machine |
| U2R | User to Root | An attacker with local access attempts to escalate to root/administrator privileges |

### 6.3 Features
Feature columns will be drawn from the CIC flow-level exports (e.g., flow duration, packet counts, byte counts, inter-arrival times, TCP flag counts). Add a finalized feature dictionary here once the dataset file(s) are in place.

### 6.4 Preprocessing Requirements
- Handle missing and infinite values (common in flow-based CIC exports)
- Encode categorical fields (e.g., protocol type)
- Normalize/scale numeric features (required for SVM; optional for tree-based models)
- Address class imbalance across the five classes
- Split into train/validation/test sets, stratified by class

## 7. Functional Requirements

| ID | Requirement |
|---|---|
| FR-1 | The system shall load and merge raw CIC dataset file(s) into a single working dataset |
| FR-2 | The system shall clean the dataset (nulls, infinities, duplicate rows) |
| FR-3 | The system shall engineer/select features relevant to intrusion classification |
| FR-4 | The system shall address class imbalance prior to training |
| FR-5 | The system shall train a Random Forest classifier on the processed dataset |
| FR-6 | The system shall train an SVM classifier on the processed dataset |
| FR-7 | The system shall train an XGBoost classifier on the processed dataset |
| FR-8 | The system shall evaluate each model on held-out test data using per-class and aggregate metrics |
| FR-9 | The system shall produce a comparison report/table across all three models |
| FR-10 | The system shall persist trained models (e.g., via `joblib`/`pickle`) for reuse |

## 8. Non-Functional Requirements

| Category | Requirement |
|---|---|
| Reproducibility | Fixed random seeds; pinned dependency versions; documented pipeline steps |
| Performance | Training completes in a reasonable time on a single development machine — no distributed training required for this phase |
| Maintainability | Clear, modular notebook/script structure separating preprocessing, training, and evaluation |
| Documentation | README and this PRD kept current as the pipeline evolves |
| Portability | Runs from a standard Python environment (e.g., `requirements.txt` or `environment.yml`) |

## 9. Technical Approach

### 9.1 Pipeline Overview
1. **Ingestion** — load raw CIC CSV file(s) from `dataset/CIC Research/`
2. **Cleaning** — remove/impute nulls and infinite values, drop duplicates
3. **Feature engineering** — select or derive the most informative flow-level features
4. **Balancing** — apply resampling or class weighting to address imbalance
5. **Splitting** — stratified train/validation/test split
6. **Training** — fit Random Forest, SVM, and XGBoost on the same splits
7. **Evaluation** — score each model with the metrics in [Section 10](#10-success-metrics)
8. **Comparison & reporting** — summarize results in tables/plots (confusion matrices, ROC curves)

### 9.2 Models

| Model | Why it's included |
|---|---|
| Random Forest | Strong tabular-data baseline; handles non-linear relationships and yields feature importances with little tuning |
| SVM | Effective in high-dimensional feature spaces; a useful comparison point against tree ensembles |
| XGBoost | Gradient boosting often achieves state-of-the-art results on tabular/flow data and handles imbalance well via class weighting |

## 10. Success Metrics

| Metric | Why it matters |
|---|---|
| Accuracy | Overall correctness — least informative alone, given class imbalance |
| Precision (per class) | Of traffic predicted as a given attack class, how much truly was |
| Recall (per class) | Of real attacks in a given class, how many were actually caught — critical for rare classes like U2R/R2L |
| F1-score (macro & weighted) | Balances precision and recall, especially across imbalanced classes |
| Confusion matrix | Shows exactly which classes are confused with each other |
| ROC-AUC / PR-AUC | Threshold-independent view of separability, especially for minority classes |

**Target:** no single attack class should fall below an agreed recall threshold (to be set once a baseline run exists) — minority-class detection should not be sacrificed for headline accuracy.

## 11. Milestones & Timeline

| Phase | Deliverable | Status |
|---|---|---|
| 1. Data prep | Cleaned, documented dataset + feature dictionary | Not started |
| 2. Baseline models | First-pass Random Forest, SVM, XGBoost trained | Not started |
| 3. Tuning | Hyperparameter tuning + imbalance handling | Not started |
| 4. Evaluation | Full metric suite + comparison report | Not started |
| 5. Documentation | Final README, results write-up, PRD finalized | Not started |

*(Durations are intentionally left open — fill in once a timeline is confirmed.)*

## 12. Risks & Assumptions

**Assumptions**
- The specific CIC dataset file(s) will be added under `dataset/CIC Research/` before pipeline work begins
- A single-machine environment is sufficient for training — no distributed compute needed

**Risks**

| Risk | Mitigation |
|---|---|
| Severe class imbalance skews results toward the majority (Normal) class | Use resampling, class weighting, and per-class metrics rather than accuracy alone |
| Feature leakage (e.g., IP/port fields that memorize rather than generalize) | Review features for leakage before training; drop identifiers not available at detection time |
| Dataset-specific overfitting — results may not generalize beyond CIC data | State this limitation explicitly in the final report; consider cross-dataset validation as future work |

## 13. Future Enhancements
- Real-time / streaming inference on live traffic
- Deep-learning baselines (e.g., autoencoders for anomaly detection, LSTMs for sequential flow data)
- Ensembling/stacking the three models
- Deployment as a lightweight API or dashboard
- Evaluation on additional CIC releases (e.g., CICIDS2018, CIC-DDoS2019) to test generalization

## 14. References
- Canadian Institute for Cybersecurity (CIC) dataset collection — University of New Brunswick
- scikit-learn documentation (Random Forest, SVM)
- XGBoost documentation

---
*This is a first-draft PRD scaffolded from the repository's stated description. Update the dataset specifics, timeline, and success thresholds once the CIC data file(s) are added to `dataset/CIC Research/`.*
