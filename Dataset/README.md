# Dataset Guide

Place source datasets in this directory or provide their paths through the desktop application.

## Files

- `known_exploited_vulnerabilities.csv` - CISA Known Exploited Vulnerabilities data. Used as exploitation labels.
- `epss_scores-2026-10-20 (1).csv` - FIRST EPSS probability data.
- `vulnerabilities_data.csv` - NVD vulnerability data.
- `dataset2/nvdcve-2.0-2026.json` - NVD JSON source.
- `dataset2/convert.py` - Converts the NVD JSON dataset to Excel.

## Converting NVD JSON

Run the conversion script from `Dataset/dataset2/`:

```powershell
pip install pandas openpyxl
python convert.py
```

The script currently writes `vulnerabilities_data.xlsx` next to itself. Update `input_file` and `output_file` in `convert.py` when using a different NVD feed or output name.

## CSV Handling

CSV datasets are tracked with Git LFS because they may exceed GitHub's normal file size limit. Install Git LFS and fetch LFS objects before processing them:

```powershell
git lfs install
git lfs pull
```
