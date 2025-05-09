import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import os
import numpy as np
import glob
from pathlib import Path
import re

def load_and_combine_prowler_csvs(directory_path=None, file_pattern="*.csv", file_list=None):
    """
    Load and combine multiple Prowler CSV reports from a directory
    
    Parameters:
    -----------
    directory_path : str
        Path to directory containing Prowler CSV reports
    file_pattern : str
        Pattern to match CSV files (default: "*.csv")
    file_list : list
        List of specific files to load instead of using directory_path
        
    Returns:
    --------
    pandas.DataFrame
        Combined data from all CSV files
    """
    if file_list:
        csv_files = file_list
    elif directory_path:
        csv_files = glob.glob(os.path.join(directory_path, file_pattern))
    else:
        raise ValueError("Either directory_path or file_list must be provided")
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found matching pattern {file_pattern}")
    
    print(f"Found {len(csv_files)} CSV files to analyze")
    
    # Create empty list to store dataframes
    dfs = []
    
    # Load each CSV file and append to the list
    for file in csv_files:
        try:
            # Read with semicolon delimiter, handle missing values
            temp_df = pd.read_csv(file, sep=';', na_values=['', 'None', 'NULL'], 
                                 low_memory=False, on_bad_lines='warn')
            
            # Add source file info
            filename = os.path.basename(file)
            temp_df['SOURCE_FILE'] = filename
            
            # Append to list
            dfs.append(temp_df)
            print(f"Loaded {filename} with {len(temp_df)} rows")
        except Exception as e:
            print(f"Error loading {file}: {e}")
    
    # Combine all dataframes
    if not dfs:
        raise ValueError("No valid CSV files could be loaded")
        
    df = pd.concat(dfs, ignore_index=True)
    
    # Clean up column names (strip whitespace)
    df.columns = df.columns.str.strip()
    
    return df

def analyze_prowler_history(csv_files_or_dir):
    """
    Analyze historical Prowler AWS security reports to identify trends over time.
    
    Parameters:
    -----------
    csv_files_or_dir : str or list
        Either a directory path containing CSV files or a list of CSV file paths
    """
    # Load data from one or more CSV files
    if isinstance(csv_files_or_dir, list):
        df = load_and_combine_prowler_csvs(file_list=csv_files_or_dir)
    else:
        df = load_and_combine_prowler_csvs(directory_path=csv_files_or_dir)
    
    # Convert timestamp to datetime
    df['TIMESTAMP'] = pd.to_datetime(df['TIMESTAMP'])
    
    # Sort by timestamp
    df = df.sort_values('TIMESTAMP')
    
    print(f"Analysis of Prowler reports from {df['TIMESTAMP'].min()} to {df['TIMESTAMP'].max()}")
    print(f"Total findings: {len(df)}")
    
    # Calculate time span of the data
    time_span = df['TIMESTAMP'].max() - df['TIMESTAMP'].min()
    print(f"Report timespan: {time_span.days} days")
    
    # Create appropriate time grouping based on the timespan
    if time_span.days > 365:
        # Group by month if more than a year
        df['TIME_GROUP'] = df['TIMESTAMP'].dt.to_period('M')
        time_unit = "month"
    elif time_span.days > 60:
        # Group by week if a few months
        df['TIME_GROUP'] = df['TIMESTAMP'].dt.to_period('W')
        time_unit = "week"
    else:
        # Group by day if less than 60 days
        df['TIME_GROUP'] = df['TIMESTAMP'].dt.to_period('D')
        time_unit = "day"
    
    # Convert period to string for easier handling in graphs
    df['TIME_GROUP'] = df['TIME_GROUP'].astype(str)
    
    # Analyze key aspects of the data
    
    # 1. Count unique accounts, regions, and services
    unique_accounts = df['ACCOUNT_UID'].nunique()
    unique_regions = df['REGION'].nunique()
    unique_services = df['SERVICE_NAME'].nunique()
    
    print(f"Analysis spans {unique_accounts} AWS accounts, {unique_regions} regions, and {unique_services} AWS services")
    
    # 2. Get distribution of findings by status
    status_counts = df['STATUS'].value_counts()
    print("\nFindings by Status:")
    for status, count in status_counts.items():
        print(f"  {status}: {count} ({count/len(df)*100:.1f}%)")
    
    # 3. Get distribution of findings by severity
    severity_counts = df['SEVERITY'].value_counts()
    print("\nFindings by Severity:")
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count} ({count/len(df)*100:.1f}%)")
    
    # 4. Top failing checks
    top_checks = df[df['STATUS'] == 'FAIL'].groupby(['CHECK_ID', 'CHECK_TITLE']).size().sort_values(ascending=False).head(10)
    print("\nTop 10 Failing Checks:")
    for (check_id, check_title), count in top_checks.items():
        print(f"  {check_id}: {check_title} - {count} findings")
    
    return df, time_unit

def analyze_account_level_metrics(df):
    """
    Analyze metrics at the AWS account level
    
    Parameters:
    -----------
    df : pandas.DataFrame
        The processed Prowler data
        
    Returns:
    --------
    pandas.DataFrame
        Account-level metrics DataFrame
    """
    # Group by account and calculate metrics
    account_metrics = []
    
    for account, account_df in df.groupby('ACCOUNT_UID'):
        # Skip if account ID is missing
        if pd.isna(account) or account == '':
            continue
            
        # Get the latest data for this account
        latest_date = account_df['TIMESTAMP'].max()
        latest_df = account_df[account_df['TIMESTAMP'] == latest_date]
        
        # Calculate metrics
        total_findings = len(latest_df)
        fail_count = len(latest_df[latest_df['STATUS'] == 'FAIL'])
        pass_count = len(latest_df[latest_df['STATUS'] == 'PASS'])
        
        # Calculate pass percentage
        if total_findings > 0:
            pass_percentage = (pass_count / total_findings) * 100
        else:
            pass_percentage = 0
            
        # Count by severity
        severity_counts = {}
        for severity in ['critical', 'high', 'medium', 'low', 'informational']:
            # Try both cases
            count = len(latest_df[(latest_df['SEVERITY'] == severity) | 
                                  (latest_df['SEVERITY'] == severity.upper())])
            severity_counts[severity] = count
        
        # Get account name if available
        account_name = account_df['ACCOUNT_NAME'].iloc[0] if not pd.isna(account_df['ACCOUNT_NAME'].iloc[0]) else 'Unknown'
        
        # Add to metrics list
        account_metrics.append({
            'ACCOUNT_UID': account,
            'ACCOUNT_NAME': account_name,
            'TOTAL_FINDINGS': total_findings,
            'FAIL_COUNT': fail_count,
            'PASS_COUNT': pass_count,
            'PASS_PERCENTAGE': pass_percentage,
            'CRITICAL': severity_counts['critical'],
            'HIGH': severity_counts['high'],
            'MEDIUM': severity_counts['medium'],
            'LOW': severity_counts['low'],
            'INFO': severity_counts['informational'],
        })
    
    # Convert to DataFrame
    account_metrics_df = pd.DataFrame(account_metrics)
    
    return account_metrics_df

def create_visualizations(df, time_unit, output_dir=None):
    """
    Create visualizations from the Prowler data to show trends over time
    
    Parameters:
    -----------
    df : pandas.DataFrame
        The processed Prowler data
    time_unit : str
        The time unit used for grouping (day, week, month)
    output_dir : str, optional
        Directory to save visualizations
    """
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Set the style
    sns.set(style="whitegrid")
    plt.rcParams.update({'font.size': 12})
    
    # 1. Overall findings trend over time
    plt.figure(figsize=(12, 6))
    findings_over_time = df.groupby('TIME_GROUP').size()
    findings_over_time.plot(kind='line', marker='o')
    plt.title(f'Total Findings by {time_unit.capitalize()}')
    plt.xlabel(f'{time_unit.capitalize()}')
    plt.ylabel('Number of Findings')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    if output_dir:
        plt.savefig(os.path.join(output_dir, 'total_findings_trend.png'))
    plt.close()
    
    # 2. Findings by status over time
    plt.figure(figsize=(14, 7))
    status_over_time = df.pivot_table(
        index='TIME_GROUP', 
        columns='STATUS', 
        aggfunc='size', 
        fill_value=0
    )
    
    # Define colors for status
    status_colors = {'PASS': 'green', 'FAIL': 'red', 'INFO': 'blue', 
                    'WARNING': 'orange', 'MANUAL': 'purple'}
    
    # Filter columns to only include statuses we have colors for
    available_statuses = [col for col in status_over_time.columns if col in status_colors]
    
    # Plot with custom colors if available
    if available_statuses:
        status_over_time[available_statuses].plot(
            kind='bar', 
            stacked=True, 
            color=[status_colors[col] for col in available_statuses]
        )
    else:
        status_over_time.plot(kind='bar', stacked=True)
        
    plt.title(f'Findings by Status Over Time')
    plt.xlabel(f'{time_unit.capitalize()}')
    plt.ylabel('Number of Findings')
    plt.legend(title='Status')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    if output_dir:
        plt.savefig(os.path.join(output_dir, 'status_trend.png'))
    plt.close()
    
    # 3. Findings by severity over time
    plt.figure(figsize=(14, 7))
    severity_over_time = df.pivot_table(
        index='TIME_GROUP', 
        columns='SEVERITY', 
        aggfunc='size', 
        fill_value=0
    )
    
    # Custom severity order (handle both upper and lowercase variants)
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
    lowercase_severity_order = [s.lower() for s in severity_order]
    
    # Map actual column names to our ordered list
    available_columns = []
    for col in severity_over_time.columns:
        col_upper = col.upper() if isinstance(col, str) else col
        if col_upper in severity_order or (isinstance(col, str) and col.lower() in lowercase_severity_order):
            available_columns.append(col)
    
    # Create a colormap for severity levels
    severity_colors = {
        'CRITICAL': 'darkred', 'critical': 'darkred',
        'HIGH': 'red', 'high': 'red',
        'MEDIUM': 'orange', 'medium': 'orange',
        'LOW': 'gold', 'low': 'gold',
        'INFORMATIONAL': 'blue', 'informational': 'blue',
        'INFO': 'blue', 'info': 'blue'
    }
    
    # Plot with available columns
    if available_columns:
        severity_over_time[available_columns].plot(
            kind='bar', 
            stacked=True, 
            color=[severity_colors.get(col, 'gray') for col in available_columns]
        )
    else:
        severity_over_time.plot(kind='bar', stacked=True)
    
    plt.title(f'Findings by Severity Over Time')
    plt.xlabel(f'{time_unit.capitalize()}')
    plt.ylabel('Number of Findings')
    plt.legend(title='Severity')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    if output_dir:
        plt.savefig(os.path.join(output_dir, 'severity_trend.png'))
    plt.close()
    
    # 4. Top failing checks over time
    # Get the top 5 most frequent failing checks
    top_failing_checks = df[df['STATUS'] == 'FAIL'].groupby('CHECK_ID').size().nlargest(5).index.tolist()
    
    # Filter data to only include these top failing checks
    top_checks_df = df[df['CHECK_ID'].isin(top_failing_checks)]
    
    plt.figure(figsize=(15, 8))
    
    # Create pivot table for top failing checks over time
    checks_over_time = pd.pivot_table(
        top_checks_df,
        index='TIME_GROUP',
        columns='CHECK_ID',
        values='FINDING_UID',
        aggfunc='count',
        fill_value=0
    )
    
    # Plot each check as a line
    checks_over_time.plot(kind='line', marker='o', linewidth=2)
    
    plt.title('Top 5 Failing Checks Over Time')
    plt.xlabel(f'{time_unit.capitalize()}')
    plt.ylabel('Number of Findings')
    plt.legend(title='Check ID')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    if output_dir:
        plt.savefig(os.path.join(output_dir, 'top_failing_checks_trend.png'))
    plt.close()
    
    # 5. Service distribution pie chart (current state)
    plt.figure(figsize=(12, 8))
    
    # Get the most recent timestamp
    latest_time = df['TIMESTAMP'].max()
    
    # Filter for the most recent data (within 1 day of the latest timestamp)
    latest_df = df[df['TIMESTAMP'] >= (latest_time - pd.Timedelta(days=1))]
    
    # Count findings by service
    service_counts = latest_df['SERVICE_NAME'].value_counts().nlargest(10)
    
    # Plot pie chart
    plt.pie(service_counts, labels=service_counts.index, autopct='%1.1f%%', 
            startangle=90, shadow=True)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    plt.title('Current Distribution of Findings by AWS Service')
    plt.tight_layout()
    if output_dir:
        plt.savefig(os.path.join(output_dir, 'service_distribution_pie.png'))
    plt.close()
    
    # 6. Remediation progress - FAIL to PASS transition over time
    # This requires pairing findings across time periods by their resource ID
    
    # Get all time periods in order
    all_time_periods = sorted(df['TIME_GROUP'].unique())
    
    # Track resources that change from FAIL to PASS
    remediation_tracker = {}
    
    # Initialize storage for remediation counts
    remediation_counts = {period: 0 for period in all_time_periods[1:]}  # Skip first period
    
    # Group by resource and check ID
    resource_groups = df.groupby(['RESOURCE_UID', 'CHECK_ID'])
    
    # For each resource+check combination
    for (resource, check), group in resource_groups:
        if len(group) < 2:
            continue  # Skip if there's only one observation
            
        # Sort by timestamp
        group = group.sort_values('TIMESTAMP')
        
        # Check for transitions from FAIL to PASS
        status_sequence = group['STATUS'].tolist()
        
        for i in range(1, len(status_sequence)):
            if status_sequence[i-1] == 'FAIL' and status_sequence[i] == 'PASS':
                # We found a remediation
                time_period = group['TIME_GROUP'].iloc[i]
                if time_period in remediation_counts:
                    remediation_counts[time_period] += 1
    
    # Convert to DataFrame for plotting
    remediation_df = pd.DataFrame({
        'TIME_GROUP': list(remediation_counts.keys()),
        'Remediations': list(remediation_counts.values())
    })
    
    # Plot remediation trend
    plt.figure(figsize=(12, 6))
    plt.bar(remediation_df['TIME_GROUP'], remediation_df['Remediations'], color='green')
    plt.title('Resources Remediated Over Time (FAIL → PASS)')
    plt.xlabel(f'{time_unit.capitalize()}')
    plt.ylabel('Number of Remediations')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    if output_dir:
        plt.savefig(os.path.join(output_dir, 'remediation_trend.png'))
    plt.close()
    
    # 7. Account comparison bar chart
    account_metrics = analyze_account_level_metrics(df)
    
    if len(account_metrics) > 0:
        plt.figure(figsize=(14, 8))
        
        # Sort by pass percentage
        account_metrics = account_metrics.sort_values('PASS_PERCENTAGE', ascending=False)
        
        # Create bar chart
        x = np.arange(len(account_metrics))
        width = 0.35
        
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Create pass and fail bars
        ax.bar(x - width/2, account_metrics['PASS_PERCENTAGE'], width, label='Pass %', color='green')
        ax.bar(x + width/2, 100 - account_metrics['PASS_PERCENTAGE'], width, label='Fail %', color='red')
        
        # Add labels and legend
        ax.set_title('AWS Account Compliance Comparison')
        ax.set_xlabel('AWS Account')
        ax.set_ylabel('Percentage')
        ax.set_xticks(x)
        
        # Use account name if available, otherwise account ID
        account_labels = []
        for _, row in account_metrics.iterrows():
            if pd.notna(row['ACCOUNT_NAME']) and row['ACCOUNT_NAME'] != '':
                # Truncate long account names
                name = row['ACCOUNT_NAME']
                if len(name) > 15:
                    name = name[:12] + '...'
                account_labels.append(name)
            else:
                # Truncate account ID for display
                account_id = str(row['ACCOUNT_UID'])
                if len(account_id) > 6:
                    account_id = account_id[:6] + '...'
                account_labels.append(account_id)
                
        ax.set_xticklabels(account_labels, rotation=45, ha='right')
        ax.legend()
        
        # Add percentage labels on bars
        for i, v in enumerate(account_metrics['PASS_PERCENTAGE']):
            ax.text(i - width/2, v + 1, f"{v:.1f}%", ha='center', va='bottom')
            ax.text(i + width/2, 100 - v + 1, f"{100-v:.1f}%", ha='center', va='bottom')
            
        ax.set_ylim(0, 110)  # Leave room for labels
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        
        if output_dir:
            plt.savefig(os.path.join(output_dir, 'account_compliance_comparison.png'))
        plt.close()

def generate_html_report(df, time_unit, output_dir):
    """
    Generate an HTML report with all visualizations and analysis
    
    Parameters:
    -----------
    df : pandas.DataFrame
        The processed Prowler data
    time_unit : str
        The time unit used for grouping (day, week, month)
    output_dir : str
        Directory to save the HTML report
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Path for HTML report
    report_path = os.path.join(output_dir, 'prowler_trend_report.html')
    
    # Get summary statistics
    total_findings = len(df)
    unique_accounts = df['ACCOUNT_UID'].nunique()
    unique_regions = df['REGION'].nunique()
    unique_resources = df['RESOURCE_UID'].nunique()
    
    # Count findings by status
    status_counts = df['STATUS'].value_counts()
    fail_count = status_counts.get('FAIL', 0)
    pass_count = status_counts.get('PASS', 0)
    
    # Calculate pass percentage
    if total_findings > 0:
        pass_percentage = (pass_count / total_findings) * 100
    else:
        pass_percentage = 0
    
    # Get time range
    start_date = df['TIMESTAMP'].min().strftime('%Y-%m-%d')
    end_date = df['TIMESTAMP'].max().strftime('%Y-%m-%d')
    
    # Get top failing checks
    top_fails = df[df['STATUS'] == 'FAIL'].groupby(['CHECK_ID', 'CHECK_TITLE']).size().sort_values(ascending=False).head(10)
    
    # Create a list of image files
    image_files = [
        ('total_findings_trend.png', 'Total Findings Over Time'),
        ('status_trend.png', 'Findings by Status Over Time'),
        ('severity_trend.png', 'Findings by Severity Over Time'),
        ('top_failing_checks_trend.png', 'Top Failing Checks Over Time'),
        ('service_distribution_pie.png', 'Current Distribution by AWS Service'),
        ('remediation_trend.png', 'Resources Remediated Over Time'),
        ('account_compliance_comparison.png', 'AWS Account Compliance Comparison')
    ]
    
    # Create HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Prowler AWS Security Findings Historical Analysis</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                color: #333;
            }}
            h1, h2, h3 {{
                color: #0066cc;
            }}
            .header {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 20px;
                border-left: 5px solid #0066cc;
            }}
            .summary {{
                display: flex;
                flex-wrap: wrap;
                gap: 20px;
                margin-bottom: 30px;
            }}
            .metric {{
                background-color: #f8f9fa;
                padding: 15px;
                border-radius: 5px;
                flex: 1 1 200px;
                text-align: center;
                border: 1px solid #ddd;
            }}
            .metric h3 {{
                margin-top: 0;
                color: #555;
            }}
            .metric .value {{
                font-size: 24px;
                font-weight: bold;
                color: #0066cc;
            }}
            .section {{
                margin-bottom: 40px;
                background-color: white;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }}
            table, th, td {{
                border: 1px solid #ddd;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            .visualization {{
                margin: 30px 0;
                text-align: center;
            }}
            .visualization img {{
                max-width: 100%;
                height: auto;
                border: 1px solid #ddd;
                border-radius: 5px;
            }}
            .high {{
                color: #d73a49;
            }}
            .medium {{
                color: #f66a0a;
            }}
            .low {{
                color: #e4cb16;
            }}
            .info {{
                color: #0366d6;
            }}
            .pass {{
                color: #28a745;
            }}
            .fail {{
                color: #d73a49;
            }}
            footer {{
                margin-top: 50px;
                text-align: center;
                color: #777;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Prowler AWS Security Findings Historical Analysis</h1>
            <p>Analysis period: {start_date} to {end_date}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary">
                <div class="metric">
                    <h3>Total Findings</h3>
                    <div class="value">{total_findings}</div>
                </div>
                <div class="metric">
                    <h3>AWS Accounts</h3>
                    <div class="value">{unique_accounts}</div>
                </div>
                <div class="metric">
                    <h3>AWS Regions</h3>
                    <div class="value">{unique_regions}</div>
                </div>
                <div class="metric">
                    <h3>Unique Resources</h3>
                    <div class="value">{unique_resources}</div>
                </div>
                <div class="metric">
                    <h3>Pass Percentage</h3>
                    <div class="value">{pass_percentage:.1f}%</div>
                </div>
                <div class="metric">
                    <h3>Fail Count</h3>
                    <div class="value" style="color: #d73a49;">{fail_count}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Top 10 Failing Checks</h2>
            <table>
                <tr>
                    <th>Check ID</th>
                    <th>Check Title</th>
                    <th>Count</th>
                </tr>
    """
    
    # Add rows for top failing checks
    for (check_id, check_title), count in top_fails.items():
        html_content += f"""
                <tr>
                    <td>{check_id}</td>
                    <td>{check_title}</td>
                    <td>{count}</td>
                </tr>
        """
    
    html_content += """
            </table>
        </div>
        
        <div class="section">
            <h2>Visualizations</h2>
    """
    
    # Add visualizations
    for img_file, title in image_files:
        img_path = os.path.join(output_dir, img_file)
        if os.path.exists(img_path):
            html_content += f"""
            <div class="visualization">
                <h3>{title}</h3>
                <img src="{img_file}" alt="{title}">
            </div>
            """
    
    # Close HTML tags
    html_content += """
        </div>
        
        <footer>
            <p>Generated on """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </footer>
    </body>
    </html>
    """
    
    # Write HTML to file
    with open(report_path, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report generated at: {report_path}")

def main():
    """
    Main function to run the analysis
    """
    import argparse
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Analyze Prowler AWS security findings over time')
    parser.add_argument('--input', '-i', required=True, help='Directory containing Prowler CSV files or a comma-separated list of CSV files')
    parser.add_argument('--output', '-o', default='prowler_analysis_results', help='Output directory for visualizations')
    parser.add_argument('--report', '-r', action='store_true', help='Generate HTML report')
    
    args = parser.parse_args()
    
    # Check if input is a directory or list of files
    if ',' in args.input:
        # Input is a list of files
        csv_files = args.input.split(',')
        print(f"Analyzing {len(csv_files)} CSV files")
        df, time_unit = analyze_prowler_history(csv_files)
    else:
        # Input is a directory
        print(f"Analyzing CSV files in directory: {args.input}")
        df, time_unit = analyze_prowler_history(args.input)
    
    # Create visualizations
    print(f"Creating visualizations in directory: {args.output}")
    create_visualizations(df, time_unit, args.output)
    
    # Generate HTML report if requested
    if args.report:
        print("Generating HTML report...")
        generate_html_report(df, time_unit, args.output)
    
    print(f"Analysis complete. Results saved to {args.output}")

if __name__ == "__main__":
    main()