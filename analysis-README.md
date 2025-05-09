# Prowler AWS Security Historical Analysis Tool

This repository contains Python scripts for analyzing historical AWS security findings from Prowler reports. These tools help you track security posture changes over time, identify trends, and prioritize remediation efforts.

## Features

### Historical Analysis (`prowler_historical_analysis.py`)

- **Time-based Trend Analysis**: Track changes in your AWS security posture over days, weeks, or months
- **Status and Severity Tracking**: Visualize how PASS/FAIL findings and Critical/High/Medium/Low issues evolve
- **Multi-Account Support**: Compare security posture across different AWS accounts
- **Interactive HTML Reports**: Generate comprehensive visual reports with key metrics
- **Top Issue Identification**: Identify the most frequent security issues across your AWS environment

### Remediation Tracking (`prowler_remediation_tracking.py`)

- **Resource-Level Tracking**: Track the remediation status of individual resources over time
- **Prioritized Remediation Plans**: Generate actionable remediation plans based on severity and age
- **Remediation Rate Analysis**: Measure your team's remediation effectiveness over time
- **Mean Time to Remediate**: Track how quickly different severity issues are being fixed
- **Finding Age Analysis**: Identify stale security findings that need attention

## Requirements

- Python 3.6+
- pandas
- matplotlib
- seaborn
- numpy

Install required packages:

```bash
pip install pandas matplotlib seaborn numpy
```

## Usage

### Historical Analysis

```bash
python prowler_historical_analysis.py --input <input_directory_or_files> --output <output_directory> [--report]
```

Parameters:
- `--input` or `-i`: Directory containing Prowler CSV files or comma-separated list of CSV files
- `--output` or `-o`: Directory for output files and visualizations
- `--report` or `-r`: Generate HTML report (optional)

Example:
```bash
# Analyze all CSVs in a directory
python prowler_historical_analysis.py --input ./prowler_reports/ --output analysis_results --report

# Analyze specific CSV files
python prowler_historical_analysis.py --input "may_report.csv,june_report.csv" --output comparison --report
```

### Remediation Tracking

```bash
python prowler_remediation_tracking.py --input <input_directory_or_file> --output <output_directory>
```

Parameters:
- `--input` or `-i`: Directory containing Prowler CSV files or path to a single CSV file
- `--output` or `-o`: Directory for output files and visualizations

Example:
```bash
python prowler_remediation_tracking.py --input ./prowler_reports/ --output remediation_results
```

## Input Data Format

The tools expect Prowler CSV output with semicolon (`;`) as delimiter. Example format:

```
AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_EMAIL;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION;ACCOUNT
```

## Output

### Historical Analysis Outputs

- **Visual Charts**: PNG images showing trends over time
- **Trend Data**: CSV files with aggregated trend data
- **HTML Report**: Comprehensive report with all visualizations and metrics

### Remediation Tracking Outputs

- **Remediation Status**: CSV tracking remediation status for each resource
- **Prioritized Plan**: CSV with prioritized remediation tasks
- **Remediation Metrics**: Visualizations showing remediation effectiveness
- **HTML Report**: Summary report with key remediation metrics and visuals

## Integration with Prowler

These tools are designed to work with [Prowler](https://github.com/prowler-cloud/prowler), an AWS security assessment tool. To collect data for analysis:

1. Install Prowler:
   ```bash
   pip install prowler
   ```

2. Run Prowler with CSV output:
   ```bash
   prowler aws --output-modes csv --output-directory ./prowler_reports
   ```

3. Run historical analysis on collected data:
   ```bash
   python prowler_historical_analysis.py --input ./prowler_reports/ --output analysis_results --report
   ```

## Best Practices

- Run Prowler scans on a regular schedule (weekly or monthly)
- Store scan results in a consistent location with date-based naming
- Use the remediation tracking tool to generate prioritized fix lists
- Review historical trends quarterly to measure security improvement

## License

This project is licensed under the MIT License - see the LICENSE file for details.