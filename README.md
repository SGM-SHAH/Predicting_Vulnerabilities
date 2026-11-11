# 🛡️ Cyber Threat Intelligence — Exploit Prediction & Vulnerability Triage Engine

A Java-based desktop application that uses **Cyber Threat Intelligence (CTI)** techniques to **predict and prioritize exploited vulnerabilities** using data from CISA KEV, NIST NVD, and FIRST EPSS datasets. It helps security analysts focus their limited triage budget on the CVEs most likely to be exploited in the wild.

---

## 📌 Overview

Security teams face thousands of new CVEs every month. This tool tackles the core research question:

> **"Which vulnerabilities will be exploited in the real world — and in what order should analysts investigate them?"**

The engine trains multiple ranking models on historical CVE data, evaluates them against standard IR metrics, and surfaces a prioritized triage table so analysts can catch the most dangerous threats within a fixed review budget (top-K).

---

## ✨ Features

- 📂 **Auto-detects CSV datasets** from a folder (KEV, NVD, EPSS) by filename matching
- 🕒 **Time-aware chronological train/test split** to prevent data leakage
- 🤖 **Four ranking models** compared side-by-side:
  - Hybrid Threat Intelligence Scorer (EPSS + CVSS + NLP Exploit Indicators)
  - Gradient Boosting / Random Forest Ensemble
  - EPSS Score Ranking Benchmark
  - CVSS Severity Score Baseline
- 📊 **Full evaluation metrics**: PR-AUC, ROC-AUC, Precision@K, Recall@K, NDCG@K, Brier Score
- 🗂️ **Interactive triage table** showing top-ranked CVEs with exploit probability, KEV status, vendor/product, CVSS, EPSS, and ransomware flag
- 🔄 **Reproducible runs** via configurable random seed
- ⚡ **Background pipeline execution** with live progress bar and log console

---

## 📁 Repository Structure

```
Predicting_Vulnerabilities/
├── WorkingCTIPredictorApp.java          # Main application (GUI + pipeline)
├── CyberThreatIntelligenceApp.java      # Supplementary CTI analysis module
├── CyberThreatPredictorApp.java         # Alternate predictor implementation
├── vulnerabilities_data.csv             # NIST NVD dataset (~282 MB, stored via Git LFS)
├── known_exploited_vulnerabilities.csv  # CISA KEV catalog
├── epss_scores-2026-10-20 (1).csv       # FIRST EPSS scores
├── .gitattributes                       # Git LFS tracking config
└── README.md
```

---

## 🗃️ Datasets

| Dataset | Source | Description |
|---------|--------|-------------|
| `vulnerabilities_data.csv` | [NIST NVD](https://nvd.nist.gov/) | Full NVD CVE records with CVSS scores and descriptions |
| `known_exploited_vulnerabilities.csv` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Ground truth — CVEs confirmed as exploited in the wild |
| `epss_scores-2026-10-20 (1).csv` | [FIRST EPSS](https://www.first.org/epss/) | Exploit Prediction Scoring System daily scores |

> **Note:** `vulnerabilities_data.csv` is ~282 MB and is stored using [Git LFS](https://git-lfs.github.com/).  
> Run `git lfs pull` after cloning to download it.

---

## 🚀 Getting Started

### Prerequisites

- Java JDK 11 or higher
- Git LFS (to download the large NVD dataset)

### Clone & Setup

```bash
# Clone the repository
git clone https://github.com/SGM-SHAH/Predicting_Vulnerabilities.git
cd Predicting_Vulnerabilities

# Pull Git LFS files (large CSVs)
git lfs pull
```

### Compile & Run

```bash
# Compile
javac WorkingCTIPredictorApp.java

# Run
java WorkingCTIPredictorApp
```

---

## 🖥️ How to Use

1. **Launch** the application — the GUI opens automatically.
2. **Select Dataset Folder** — click *Browse Folder* and point to the folder containing all three CSV files.
3. **Configure Parameters:**
   - **Chronological Cutoff** — date to split train/test (default: `2026-03-01`)
   - **Prediction Horizon (Days)** — lookahead window for exploitation (default: `90`)
   - **Analyst Budget (K)** — how many top alerts the analyst reviews (default: `100`)
   - **Max NVD Rows** — cap on records to process (default: `20000`)
   - **Random Seed** — for reproducibility (default: `42`)
4. **Select Model** — choose the primary ranking model, or tick *Compare All Models Simultaneously*.
5. **Click "Run Pipeline"** — results appear in two tabs:
   - **Tab 1 — Training Log & Metrics:** Full evaluation table (PR-AUC, ROC-AUC, NDCG@K, etc.)
   - **Tab 2 — Caught Vulnerabilities:** Prioritized CVE triage table (top 400 predictions)

---

## 📈 Evaluation Metrics

| Metric | Description |
|--------|-------------|
| **PR-AUC** | Area under the Precision-Recall curve — key for imbalanced datasets |
| **ROC-AUC** | Area under the ROC curve — overall discrimination ability |
| **Precision@K** | Fraction of top-K predictions that are truly exploited |
| **Recall@K** | Fraction of all exploited CVEs caught in top-K |
| **NDCG@K** | Normalized Discounted Cumulative Gain — ranking quality within budget |
| **Brier Score** | Calibration of predicted probabilities (lower is better) |

---

## 🧠 Models

### 1. Hybrid Threat Intelligence Scorer *(Recommended)*
Combines EPSS score, CVSS severity, ransomware association flag, NLP keyword signals from CVE descriptions (e.g., "exploit", "remote code execution"), and temporal features into a single composite score.

### 2. Gradient Boosting / Random Forest Ensemble
Ensemble approach that weights multiple signals including CVSS, EPSS, ransomware flag, and KEV recency patterns.

### 3. EPSS Score Ranking Benchmark
Ranks CVEs purely by their FIRST EPSS score — a standard industry benchmark.

### 4. CVSS Severity Score Baseline
Ranks CVEs by CVSS score alone — the simplest baseline, widely used but not exploit-specific.

---

## 📊 Sample Output

```
==========================================================================================
CTI ENGINE: TIME-AWARE EXPLOIT PREDICTION & VULNERABILITY CATCHING
==========================================================================================
[STEP 1] Loading CISA KEV Catalog...
[STEP 2] Loading FIRST EPSS Scores...
[STEP 3] Parsing NIST NVD Dataset & Joining Records...
[STEP 4] Executing Time-Aware Chronological Split (Cutoff: 2026-03-01)...
 -> Train Set: 14823 CVEs | Test Set: 5177 CVEs (Contains 312 actual exploited KEVs)

[STEP 5] Scoring & Evaluating Models on Test Set (Budget K = 100)...
Model / Strategy                           | PR-AUC   | ROC-AUC  | Prec@K   | Recall@K | NDCG@K   | Brier
------------------------------------------------------------------------------------------------------------------
Hybrid Threat Intelligence Scorer (EPSS+…) | 0.7821   | 0.8934   | 0.6700   | 0.2147   | 0.7103   | 0.0412
Gradient Boosting / Random Forest Ensemble | 0.7345   | 0.8711   | 0.6200   | 0.1987   | 0.6834   | 0.0487
EPSS Score Ranking Benchmark               | 0.6912   | 0.8502   | 0.5900   | 0.1891   | 0.6421   | 0.0531
CVSS Severity Score Baseline               | 0.5234   | 0.7103   | 0.3800   | 0.1218   | 0.4812   | 0.0734
```

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

This project is for academic and research purposes.

---

## 👤 Author

**SGM SHAH**  
GitHub: [@SGM-SHAH](https://github.com/SGM-SHAH)
