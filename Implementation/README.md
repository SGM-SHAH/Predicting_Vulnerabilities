# Implementation Guide

## Maven Application

The Maven project is in `prediction_1/`.

Requirements:

- Java 26
- Maven 3.9 or newer

Build and run:

```powershell
cd prediction_1
mvn clean compile
mvn exec:java
```

The configured main class is `com.mycompany.prediction_1.Prediction_1`.

## Desktop Application

The Swing application expects CSV or JSON source paths to be selected from the interface. It supports:

- KEV label integration
- EPSS score integration
- NVD feature integration
- Temporal cutoff configuration
- Prediction horizon configuration
- Analyst budget ranking
- Model comparison

## Standalone Sources

`WorkingCTIPredictorApp.java` and `WorkingCTIPredictorApp.txt` contain standalone application variants. The sources under `prediction_1/src/main/java/` are the Maven-managed implementation.
