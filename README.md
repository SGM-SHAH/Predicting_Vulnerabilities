# Predicting Vulnerabilities

This project explores predicting and ranking vulnerabilities that are likely to be exploited. It combines CISA Known Exploited Vulnerabilities (KEV), NVD vulnerability metadata, and FIRST EPSS scores for research and analyst triage workflows.

## Repository Structure

- `Dataset/` - CISA KEV, FIRST EPSS, NVD, and conversion datasets.
- `Implementation/` - Java applications and the Maven project.
- `Documentation/` - Project documentation and supporting PDF material.
- `PaperWork/` - Dataset description and project paperwork.
- `Prompt/` - Prompt and research notes.

## Implementation

The Java implementation includes a Swing desktop application for loading datasets, configuring temporal splits, comparing ranking approaches, and displaying vulnerability results.

The primary Maven application is located in `Implementation/prediction_1/`. It requires Java 26 and Maven. Run:

```powershell
cd Implementation/prediction_1
mvn compile
mvn exec:java
```

The main entry point configured in `pom.xml` is `com.mycompany.prediction_1.Prediction_1`.

Standalone Java sources are also provided in `Implementation/` for reference.

## Data

Large CSV datasets are stored with Git LFS. The repository does not include generated build output or IDE configuration.

Typical inputs:

- CISA KEV catalog
- NVD CVE data
- FIRST EPSS historical scores

Dataset paths and conversion instructions are documented in [Dataset/README.md](Dataset/README.md).

## Reproducibility

When running experiments, record:

- Dataset versions and collection dates
- Chronological cutoff date
- Prediction horizon
- Random seed
- Ranking model and analyst budget
- Evaluation metrics

## License

No license is currently specified in this repository.
