#!/bin/bash
# Example usage commands for prowler_historical_analysis.py

# Save the Python script
cat > prowler_historical_analysis.py << 'EOF'
# Copy and paste the entire python script here
EOF

# Make it executable
chmod +x prowler_historical_analysis.py

# Example 1: Analyze a single CSV file
python prowler_historical_analysis.py --input prowler_report_2025-05-01.csv --output analysis_results

# Example 2: Analyze multiple CSV files
python prowler_historical_analysis.py --input "prowler_report_2025-05-01.csv,prowler_report_2025-04-01.csv,prowler_report_2025-03-01.csv" --output quarterly_analysis

# Example 3: Analyze all CSV files in a directory
python prowler_historical_analysis.py --input ./prowler_reports/ --output monthly_trend_analysis

# Example 4: Generate an HTML report
python prowler_historical_analysis.py --input ./prowler_reports/ --output report_with_visuals --report

# Example 5: Analyze and compare AWS accounts
mkdir -p ./prowler_reports/
# Download reports or copy them
# Then run:
python prowler_historical_analysis.py --input ./prowler_reports/ --output account_comparison --report
