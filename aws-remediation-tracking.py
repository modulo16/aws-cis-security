#!/usr/bin/env python3
"""
AWS Prowler Remediation Tracking

This script analyzes Prowler security findings over time to track remediation progress
and generate prioritized remediation plans.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import argparse
import os
import numpy as np
import glob

def load_prowler_csvs(input_path):
    """
    Load one or more Prowler CSV reports
    
    Parameters:
    -----------
    input_path : str
        Directory containing CSV files or a single CSV file path
        
    Returns:
    --------
    pandas.DataFrame
        Combined Prowler data
    """
    # Check if input is a directory or file
    if os.path.isdir(input_path):
        # Find all CSV files in directory
        csv_files = glob.glob(os.path.join(input_path, "*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in {input_path}")
        print(f"Found {len(csv_files)} CSV files in {input_path}")
    else:
        # Treat as a single file
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        csv_files = [input_path]
        print(f"Using single CSV file: {input_path}")
    
    # Load and combine CSV files
    dfs = []
    for file in csv_files:
        try:
            print(f"Loading {file}...")
            df = pd.read_csv(file, sep=';', na_values=['', 'None', 'NULL'], 
                            low_memory=False, on_bad_lines='warn')
            # Add source file for reference
            df['SOURCE_FILE'] = os.path.basename(file)
            dfs.append(df)
        except Exception as e:
            print(f"Error loading {file}: {e}")
    
    if not dfs:
        raise ValueError("No valid CSV files could be loaded")
    
    # Combine all dataframes
    combined_df = pd.concat(dfs, ignore_index=True)
    
    # Clean up column names
    combined_df.columns = combined_df.columns.str.strip()
    
    # Convert timestamp to datetime
    combined_df['TIMESTAMP'] = pd.to_datetime(combined_df['TIMESTAMP'])
    
    return combined_df

def track_resource_remediation(df):
    """
    Track remediation status for each AWS resource over time
    
    Parameters:
    -----------
    df : pandas.DataFrame
        The Prowler findings data
        
    Returns:
    --------
    pandas.DataFrame
        Resource-level remediation tracking
    """
    print("Tracking resource-level remediation status...")
    
    # Group by resource and check
    resource_groups = df.groupby(['RESOURCE_UID', 'CHECK_ID'])
    
    # Store remediation data
    remediation_data = []
    
    # Process each resource group
    total_groups = len(resource_groups)
    print(f"Processing {total_groups} resource+check combinations...")
    
    # Counter for progress updates
    counter = 0
    
    for (resource_uid, check_id), group in resource_groups:
        # Update progress counter
        counter += 1
        if counter % 1000 == 0:
            print(f"Processed {counter}/{total_groups} resources...")
        
        # Skip resources with missing IDs
        if pd.isna(resource_uid) or resource_uid == '':
            continue
        
        # Sort by timestamp
        group = group.sort_values('TIMESTAMP')
        
        # Extract timestamps and statuses
        timestamps = group['TIMESTAMP'].tolist()
        statuses = group['STATUS'].tolist()
        
        # Skip if only one observation
        if len(timestamps) < 2:
            continue
        
        # Extract first and latest timestamps
        first_detected = timestamps[0]
        last_checked = timestamps[-1]
        
        # Determine current status
        current_status = statuses[-1]
        
        # Build status history
        status_changes = []
        prev_status = None
        for i, (status, timestamp) in enumerate(zip(statuses, timestamps)):
            if status != prev_status:
                status_changes.append(f"{status} ({timestamp.strftime('%Y-%m-%d')})")
                prev_status = status
        
        status_history = " → ".join(status_changes)
        
        # Check for fail to pass transitions (remediations)
        remediated = False
        remediation_time = None
        
        for i in range(1, len(statuses)):
            if statuses[i-1] == 'FAIL' and statuses[i] == 'PASS':
                remediated = True
                remediation_time = timestamps[i]
                break
        
        # Calculate time to remediate
        time_to_remediate = None
        if remediated:
            time_to_remediate = (remediation_time - first_detected).days
        
        # Calculate days in current state
        days_in_current_state = 0
        if len(timestamps) > 1:
            # Find when status last changed
            last_change_idx = 0
            for i in range(len(statuses) - 1, 0, -1):
                if statuses[i] != statuses[i-1]:
                    last_change_idx = i
                    break
            
            last_change_time = timestamps[last_change_idx]
            days_in_current_state = (last_checked - last_change_time).days
        
        # Add to remediation data
        remediation_data.append({
            'RESOURCE_UID': resource_uid,
            'CHECK_ID': check_id,
            'SEVERITY': group['SEVERITY'].iloc[0],
            'CHECK_TITLE': group['CHECK_TITLE'].iloc[0],
            'FIRST_DETECTED': first_detected,
            'LAST_CHECKED': last_checked,
            'CURRENT_STATUS': current_status,
            'WAS_REMEDIATED': remediated,
            'REMEDIATION_DATE': remediation_time,
            'DAYS_TO_REMEDIATE': time_to_remediate,
            'DAYS_IN_CURRENT_STATE': days_in_current_state,
            'STATUS_HISTORY': status_history,
            'RESOURCE_TYPE': group['RESOURCE_TYPE'].iloc[0] if 'RESOURCE_TYPE' in group.columns else None,
            'RESOURCE_NAME': group['RESOURCE_NAME'].iloc[0] if 'RESOURCE_NAME' in group.columns else None,
            'REGION': group['REGION'].iloc[0],
            'ACCOUNT_UID': group['ACCOUNT_UID'].iloc[0],
            'REMEDIATION_TEXT': group['REMEDIATION_RECOMMENDATION_TEXT'].iloc[0] 
                if 'REMEDIATION_RECOMMENDATION_TEXT' in group.columns else None
        })
    
    # Convert to DataFrame
    remediation_df = pd.DataFrame(remediation_data)
    
    print(f"Created remediation tracking for {len(remediation_df)} resources")
    
    return remediation_df

def generate_remediation_plan(remediation_df, output_file=None):
    """
    Generate a prioritized remediation plan
    
    Parameters:
    -----------
    remediation_df : pandas.DataFrame
        Remediation tracking data
    output_file : str, optional
        Path to save the remediation plan CSV
        
    Returns:
    --------
    pandas.DataFrame
        Prioritized remediation plan
    """
    print("Generating prioritized remediation plan...")
    
    # Filter for current fails
    current_fails = remediation_df[remediation_df['CURRENT_STATUS'] == 'FAIL'].copy()
    
    if len(current_fails) == 0:
        print("No current failures found!")
        return pd.DataFrame()
    
    print(f"Found {len(current_fails)} current failures to prioritize")
    
    # Map severity to numeric scores
    severity_map = {
        'CRITICAL': 5, 'critical': 5,
        'HIGH': 4, 'high': 4,
        'MEDIUM': 3, 'medium': 3,
        'LOW': 2, 'low': 2,
        'INFORMATIONAL': 1, 'informational': 1,
        'INFO': 1, 'info': 1
    }
    
    # Calculate age of findings
    current_fails['AGE_DAYS'] = (current_fails['LAST_CHECKED'] - current_fails['FIRST_DETECTED']).dt.days
    
    # Convert severity to numeric score
    current_fails['SEVERITY_SCORE'] = current_fails['SEVERITY'].map(
        lambda x: severity_map.get(x, 1) if isinstance(x, str) else 1
    )
    
    # Calculate priority score
    # Formula: (Severity Score * 10) + min(Age in days, 100)/10
    # This weights severity heavily but also considers age
    current_fails['PRIORITY_SCORE'] = (current_fails['SEVERITY_SCORE'] * 10) + \
                                     (current_fails['AGE_DAYS'].clip(upper=100) / 10)
    
    # Sort by priority score (descending)
    remediation_plan = current_fails.sort_values('PRIORITY_SCORE', ascending=False)
    
    # Assign priority category
    def assign_priority(score):
        if score >= 45:  # Critical + older than 50 days
            return 'Critical'
        elif score >= 35:  # High + older than 50 days or Critical + newer
            return 'High'
        elif score >= 25:  # Medium + older or High + newer
            return 'Medium'
        else:
            return 'Low'
    
    remediation_plan['PRIORITY'] = remediation_plan['PRIORITY_SCORE'].apply(assign_priority)
    
    # Select and reorder columns for output
    output_columns = [
        'PRIORITY', 'SEVERITY', 'AGE_DAYS', 'CHECK_ID', 'CHECK_TITLE', 
        'RESOURCE_NAME', 'RESOURCE_TYPE', 'REGION', 'ACCOUNT_UID',
        'FIRST_DETECTED', 'RESOURCE_UID', 'REMEDIATION_TEXT'
    ]
    
    # Ensure all columns exist
    available_columns = [col for col in output_columns if col in remediation_plan.columns]
    remediation_plan = remediation_plan[available_columns]
    
    # Save to CSV if output file specified
    if output_file:
        remediation_plan.to_csv(output_file, index=False)
        print(f"Saved remediation plan to {output_file}")
    
    return remediation_plan

def create_remediation_visualizations(remediation_df, output_dir):
    """
    Create visualizations for remediation analysis
    
    Parameters:
    -----------
    remediation_df : pandas.DataFrame
        Remediation tracking data
    output_dir : str
        Directory to save visualizations
    """
    print("Creating remediation visualizations...")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Set style
    sns.set(style="whitegrid")
    plt.rcParams.update({'font.size': 12})
    
    # 1. Current Status Distribution
    plt.figure(figsize=(10, 8))
    status_counts = remediation_df['CURRENT_STATUS'].value_counts()
    
    # Define colors for status
    status_colors = {'PASS': 'green', 'FAIL': 'red', 'INFO': 'blue', 'WARNING': 'orange'}
    colors = [status_colors.get(status, 'gray') for status in status_counts.index]
    
    # Create pie chart
    plt.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%',
            colors=colors, startangle=90, shadow=True)
    plt.axis('equal')
    plt.title('Current Remediation Status')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'current_status_distribution.png'))
    plt.close()
    
    # 2. Remediation Rate Over Time
    # Group by month and calculate remediation rate
    if 'WAS_REMEDIATED' in remediation_df.columns:
        remediation_df['MONTH'] = remediation_df['FIRST_DETECTED'].dt.to_period('M')
        
        # Count resources and remediations by month
        monthly_stats = remediation_df.groupby('MONTH').agg({
            'RESOURCE_UID': 'count',
            'WAS_REMEDIATED': 'sum'
        }).reset_index()
        
        # Calculate remediation rate
        monthly_stats['REMEDIATION_RATE'] = (monthly_stats['WAS_REMEDIATED'] / 
                                           monthly_stats['RESOURCE_UID'] * 100)
        
        # Convert period to string for plotting
        monthly_stats['MONTH_STR'] = monthly_stats['MONTH'].astype(str)
        
        plt.figure(figsize=(12, 6))
        plt.bar(monthly_stats['MONTH_STR'], monthly_stats['REMEDIATION_RATE'], color='teal')
        plt.title('Monthly Remediation Rate')
        plt.xlabel('Month')
        plt.ylabel('Remediation Rate (%)')
        plt.xticks(rotation=45)
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'monthly_remediation_rate.png'))
        plt.close()
    
    # 3. Time to Remediate by Severity
    if 'DAYS_TO_REMEDIATE' in remediation_df.columns:
        # Filter for remediated resources with valid time data
        remediated = remediation_df[
            (remediation_df['WAS_REMEDIATED'] == True) & 
            (remediation_df['DAYS_TO_REMEDIATE'].notna())
        ]
        
        if len(remediated) > 0:
            plt.figure(figsize=(12, 6))
            
            # Group by severity and calculate mean remediation time
            severity_times = remediated.groupby('SEVERITY')['DAYS_TO_REMEDIATE'].mean().sort_values(ascending=False)
            
            # Plot bar chart
            ax = severity_times.plot(kind='bar', color='olive')
            plt.title('Average Days to Remediate by Severity')
            plt.xlabel('Severity')
            plt.ylabel('Days')
            plt.grid(True, linestyle='--', alpha=0.7)
            
            # Add data labels
            for i, value in enumerate(severity_times):
                ax.text(i, value + 0.5, f"{value:.1f}", ha='center')
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'time_to_remediate_by_severity.png'))
            plt.close()
    
    # 4. Age Distribution of Open Findings
    open_findings = remediation_df[remediation_df['CURRENT_STATUS'] == 'FAIL']
    
    if len(open_findings) > 0:
        # Calculate age if not already done
        if 'AGE_DAYS' not in open_findings.columns:
            open_findings['AGE_DAYS'] = (open_findings['LAST_CHECKED'] - 
                                       open_findings['FIRST_DETECTED']).dt.days
        
        plt.figure(figsize=(12, 6))
        
        # Create age bins
        bins = [0, 7, 30, 90, 180, 365, float('inf')]
        labels = ['<1 week', '1-4 weeks', '1-3 months', '3-6 months', '6-12 months', '>1 year']
        
        open_findings['AGE_GROUP'] = pd.cut(open_findings['AGE_DAYS'], bins=bins, labels=labels)
        
        # Count findings by age group
        age_counts = open_findings['AGE_GROUP'].value_counts().sort_index()
        
        # Create bar chart
        ax = age_counts.plot(kind='bar', color='firebrick')
        plt.title('Age Distribution of Open Findings')
        plt.xlabel('Time Since First Detection')
        plt.ylabel('Number of Findings')
        plt.grid(True, linestyle='--', alpha=0.7)
        
        # Add count labels
        for i, count in enumerate(age_counts):
            ax.text(i, count + 0.5, str(count), ha='center')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'open_findings_age_distribution.png'))
        plt.close()
    
    # 5. Top Checks Awaiting Remediation
    if len(open_findings) > 0:
        plt.figure(figsize=(14, 8))
        
        # Group by check and count
        check_counts = open_findings.groupby(['CHECK_ID', 'CHECK_TITLE']).size()
        top_checks = check_counts.sort_values(ascending=False).head(10)
        
        # Create horizontal bar chart
        ax = top_checks.plot(kind='barh', color='darkred')
        plt.title('Top 10 Checks Awaiting Remediation')
        plt.xlabel('Number of Resources')
        plt.tight_layout()
        
        # Add count labels
        for i, count in enumerate(top_checks):
            ax.text(count + 0.5, i, str(count), va='center')
        
        plt.savefig(os.path.join(output_dir, 'top_checks_awaiting_remediation.png'))
        plt.close()

def generate_html_report(remediation_df, remediation_plan, output_dir):
    """
    Generate an HTML report with remediation analysis
    
    Parameters:
    -----------
    remediation_df : pandas.DataFrame
        Remediation tracking data
    remediation_plan : pandas.DataFrame
        Prioritized remediation plan
    output_dir : str
        Output directory
    """
    print("Generating HTML remediation report...")
    
    # Path for HTML report
    report_path = os.path.join(output_dir, 'remediation_report.html')
    
    # Calculate summary statistics
    total_resources = len(remediation_df)
    remediated_count = sum(remediation_df['WAS_REMEDIATED'] == True)
    open_count = sum(remediation_df['CURRENT_STATUS'] == 'FAIL')
    
    # Calculate remediation rate
    if total_resources > 0:
        remediation_rate = (remediated_count / total_resources) * 100
    else:
        remediation_rate = 0
    
    # Count by severity for open findings
    open_by_severity = remediation_df[remediation_df['CURRENT_STATUS'] == 'FAIL']['SEVERITY'].value_counts()
    
    # Create list of image files
    image_files = [
        ('current_status_distribution.png', 'Current Remediation Status'),
        ('monthly_remediation_rate.png', 'Monthly Remediation Rate'),
        ('time_to_remediate_by_severity.png', 'Average Time to Remediate by Severity'),
        ('open_findings_age_distribution.png', 'Age Distribution of Open Findings'),
        ('top_checks_awaiting_remediation.png', 'Top Checks Awaiting Remediation')
    ]
    
    # Create HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AWS Security Remediation Analysis</title>
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
            .critical {{
                background-color: #ffdddd;
            }}
            .high {{
                background-color: #ffeeee;
            }}
            .medium {{
                background-color: #fff8dd;
            }}
            .low {{
                background-color: #f0f0f0;
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
            <h1>AWS Security Remediation Analysis</h1>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        </div>
        
        <div class="section">
            <h2>Remediation Summary</h2>
            <div class="summary">
                <div class="metric">
                    <h3>Total Resources</h3>
                    <div class="value">{total_resources}</div>
                </div>
                <div class="metric">
                    <h3>Resources Remediated</h3>
                    <div class="value" style="color: #28a745;">{remediated_count}</div>
                </div>
                <div class="metric">
                    <h3>Open Findings</h3>
                    <div class="value" style="color: #d73a49;">{open_count}</div>
                </div>
                <div class="metric">
                    <h3>Remediation Rate</h3>
                    <div class="value">{remediation_rate:.1f}%</div>
                </div>
            </div>
            
            <h3>Open Findings by Severity</h3>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
    """
    
    # Add rows for open findings by severity
    for severity, count in open_by_severity.items():
        html_content += f"""
                <tr>
                    <td>{severity}</td>
                    <td>{count}</td>
                </tr>
        """
    
    html_content += """
            </table>
        </div>
        
        <div class="section">
            <h2>Top Priority Remediations</h2>
    """
    
    # Add remediation plan if available
    if remediation_plan is not None and len(remediation_plan) > 0:
        html_content += """
            <table>
                <tr>
                    <th>Priority</th>
                    <th>Severity</th>
                    <th>Age (Days)</th>
                    <th>Check ID</th>
                    <th>Resource</th>
                    <th>Region</th>
                </tr>
        """
        
        # Add top 20 items from remediation plan
        for _, item in remediation_plan.head(20).iterrows():
            # Determine row class based on priority
            row_class = item['PRIORITY'].lower() if 'PRIORITY' in item else ''
            
            # Get resource name or ID
            resource = item.get('RESOURCE_NAME', item.get('RESOURCE_UID', 'Unknown'))
            
            html_content += f"""
                <tr class="{row_class}">
                    <td>{item.get('PRIORITY', 'Unknown')}</td>
                    <td>{item.get('SEVERITY', 'Unknown')}</td>
                    <td>{item.get('AGE_DAYS', 'Unknown')}</td>
                    <td>{item.get('CHECK_ID', 'Unknown')}</td>
                    <td>{resource}</td>
                    <td>{item.get('REGION', 'Unknown')}</td>
                </tr>
            """
        
        html_content += """
            </table>
            <p>See the full remediation plan in the CSV file.</p>
        """
    else:
        html_content += """
            <p>No remediation items available.</p>
        """
    
    html_content += """
        </div>
        
        <div class="section">
            <h2>Remediation Analysis</h2>
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
    
    # Close HTML
    html_content += """
        </div>
        
        <footer>
            <p>Generated by Prowler Remediation Tracking Tool</p>
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
    Main function to run remediation analysis
    """
    parser = argparse.ArgumentParser(description='Analyze AWS Security Remediation from Prowler Reports')
    parser.add_argument('--input', '-i', required=True, help='Directory containing Prowler CSV files or path to single CSV')
    parser.add_argument('--output', '-o', default='remediation_analysis', help='Output directory for results')
    
    args = parser.parse_args()
    
    # Create output directory
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Load Prowler data
    df = load_prowler_csvs(args.input)
    
    # Track remediation status
    remediation_df = track_resource_remediation(df)
    
    # Save remediation tracking data
    remediation_csv = os.path.join(args.output, 'remediation_tracking.csv')
    remediation_df.to_csv(remediation_csv, index=False)
    print(f"Saved remediation tracking data to {remediation_csv}")
    
    # Generate prioritized remediation plan
    remediation_plan = generate_remediation_plan(
        remediation_df, 
        output_file=os.path.join(args.output, 'remediation_plan.csv')
    )
    
    # Create visualizations
    create_remediation_visualizations(remediation_df, args.output)
    
    # Generate HTML report
    generate_html_report(remediation_df, remediation_plan, args.output)
    
    print(f"Analysis complete. Results saved to {args.output}")

if __name__ == "__main__":
    main()