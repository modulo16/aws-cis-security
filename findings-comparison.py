import pandas as pd
import os
import glob
import json
import matplotlib.pyplot as plt
from datetime import datetime
import re
import numpy as np

class FindingsAnalyzer:
    """
    Class to analyze and compare findings over time.
    """
    
    def __init__(self, base_dir):
        """
        Initialize the analyzer with the directory containing analysis outputs.
        
        Parameters:
        base_dir (str): Base directory containing analysis outputs from different runs
        """
        self.base_dir = base_dir
        self.runs = []
        self.summaries = {}
        self.merged_data = {}
        self.comparison_results = {}
    
    def discover_runs(self):
        """
        Discover all analysis runs in the base directory.
        Assumes each run is in a subdirectory with a timestamp pattern.
        """
        # Look for directories with timestamp-like names: YYYY-MM-DD_HH-MM-SS
        pattern = re.compile(r'\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}')
        
        # Find all subdirectories
        all_dirs = [d for d in os.listdir(self.base_dir) 
                   if os.path.isdir(os.path.join(self.base_dir, d))]
        
        # Filter for timestamp directories
        self.runs = [d for d in all_dirs if pattern.match(d)]
        self.runs.sort()  # Sort chronologically
        
        print(f"Discovered {len(self.runs)} analysis runs:")
        for run in self.runs:
            print(f"  - {run}")
            
        return self.runs
    
    def load_summaries(self):
        """
        Load summary data from each run.
        """
        for run in self.runs:
            run_dir = os.path.join(self.base_dir, run)
            summary_file = os.path.join(run_dir, "analysis_summary.json")
            
            if os.path.exists(summary_file):
                try:
                    with open(summary_file, 'r') as f:
                        self.summaries[run] = json.load(f)
                    print(f"Loaded summary for {run}")
                except Exception as e:
                    print(f"Error loading summary for {run}: {str(e)}")
        
        return self.summaries
    
    def load_merged_data(self):
        """
        Load the merged data from each run.
        """
        for run in self.runs:
            run_dir = os.path.join(self.base_dir, run)
            merged_file = os.path.join(run_dir, "merged_complete.csv")
            
            if os.path.exists(merged_file):
                try:
                    df = pd.read_csv(merged_file, sep=';')
                    self.merged_data[run] = df
                    print(f"Loaded merged data for {run}: {df.shape[0]} records")
                except Exception as e:
                    print(f"Error loading merged data for {run}: {str(e)}")
        
        return self.merged_data
    
    def compare_severity_counts(self):
        """
        Compare the count of findings by severity across runs.
        
        Returns:
        DataFrame: The comparison results
        """
        if not self.summaries:
            print("No summaries loaded. Please run load_summaries() first.")
            return None
        
        # Extract severity counts from each run
        severity_data = {}
        for run, summary in self.summaries.items():
            if 'by_severity' in summary:
                severity_data[run] = summary['by_severity']
        
        if not severity_data:
            print("No severity data found in summaries.")
            return None
        
        # Convert to DataFrame
        severity_df = pd.DataFrame(severity_data).T
        severity_df.index.name = 'run'
        severity_df = severity_df.reset_index()
        
        # Add a date column for easier visualization
        severity_df['date'] = severity_df['run'].apply(
            lambda x: datetime.strptime(x, '%Y-%m-%d_%H-%M-%S').strftime('%Y-%m-%d')
        )
        
        # Sort by run date
        severity_df = severity_df.sort_values('run')
        
        self.comparison_results['severity_counts'] = severity_df
        return severity_df
    
    def compare_status_counts(self):
        """
        Compare the count of findings by status across runs.
        
        Returns:
        DataFrame: The comparison results
        """
        if not self.summaries:
            print("No summaries loaded. Please run load_summaries() first.")
            return None
        
        # Extract status counts from each run
        status_data = {}
        for run, summary in self.summaries.items():
            if 'by_status' in summary:
                status_data[run] = summary['by_status']
        
        if not status_data:
            print("No status data found in summaries.")
            return None
        
        # Convert to DataFrame
        status_df = pd.DataFrame(status_data).T
        status_df.index.name = 'run'
        status_df = status_df.reset_index()
        
        # Add a date column for easier visualization
        status_df['date'] = status_df['run'].apply(
            lambda x: datetime.strptime(x, '%Y-%m-%d_%H-%M-%S').strftime('%Y-%m-%d')
        )
        
        # Sort by run date
        status_df = status_df.sort_values('run')
        
        self.comparison_results['status_counts'] = status_df
        return status_df
    
    def compare_project_counts(self):
        """
        Compare the count of findings by project across runs.
        
        Returns:
        DataFrame: The comparison results
        """
        if not self.summaries:
            print("No summaries loaded. Please run load_summaries() first.")
            return None
        
        # Extract project counts from each run
        project_data = {}
        for run, summary in self.summaries.items():
            if 'by_project' in summary:
                project_data[run] = summary['by_project']
        
        if not project_data:
            print("No project data found in summaries.")
            return None
        
        # Convert to DataFrame - this is more complex because projects may vary across runs
        df_list = []
        for run, projects in project_data.items():
            run_df = pd.DataFrame([projects])
            run_df['run'] = run
            df_list.append(run_df)
        
        project_df = pd.concat(df_list, ignore_index=True)
        project_df['date'] = project_df['run'].apply(
            lambda x: datetime.strptime(x, '%Y-%m-%d_%H-%M-%S').strftime('%Y-%m-%d')
        )
        
        # Sort by run date
        project_df = project_df.sort_values('run')
        
        self.comparison_results['project_counts'] = project_df
        return project_df
    
    def find_recurring_findings(self):
        """
        Identify findings that occur across multiple runs.
        
        Returns:
        DataFrame: Findings that appear in multiple runs
        """
        if not self.merged_data:
            print("No merged data loaded. Please run load_merged_data() first.")
            return None
        
        # We need a unique identifier for each finding - let's use a combination of columns
        # This depends on your data structure - adjust as needed
        all_findings = []
        
        for run, df in self.merged_data.items():
            if df.empty:
                continue
                
            # Create a copy of the data with run information
            run_df = df.copy()
            run_df['RUN'] = run
            run_df['DATE'] = datetime.strptime(run, '%Y-%m-%d_%H-%M-%S').strftime('%Y-%m-%d')
            
            # Try to create a finding ID - adjust these columns based on your actual data
            id_columns = []
            for col in ['FINDING_ID', 'TITLE', 'DESCRIPTION', 'RESOURCE_ID']:
                if col in run_df.columns:
                    id_columns.append(col)
            
            if id_columns:
                run_df['FINDING_SIGNATURE'] = run_df[id_columns].apply(
                    lambda row: '_'.join(str(val) for val in row), axis=1
                )
                all_findings.append(run_df)
        
        if not all_findings:
            print("Could not create finding signatures from the available data.")
            return None
        
        # Combine all findings
        combined_df = pd.concat(all_findings, ignore_index=True)
        
        # Count occurrences of each finding
        finding_counts = combined_df['FINDING_SIGNATURE'].value_counts()
        recurring_findings = finding_counts[finding_counts > 1].index.tolist()
        
        # Filter for recurring findings
        recurring_df = combined_df[combined_df['FINDING_SIGNATURE'].isin(recurring_findings)]
        
        # Group by finding and collect the runs where each appears
        recurring_grouped = recurring_df.groupby('FINDING_SIGNATURE').agg({
            'RUN': lambda x: list(sorted(set(x))),
            'SEVERITY': 'first',
            'STATUS': 'first'
        }).reset_index()
        
        # Add count of runs where each finding appears
        recurring_grouped['NUM_RUNS'] = recurring_grouped['RUN'].apply(len)
        
        # Sort by number of runs (descending)
        recurring_grouped = recurring_grouped.sort_values('NUM_RUNS', ascending=False)
        
        self.comparison_results['recurring_findings'] = recurring_grouped
        return recurring_grouped
    
    def find_new_findings(self):
        """
        Identify findings that are new in each run compared to the previous run.
        
        Returns:
        dict: New findings for each run
        """
        if not self.merged_data or len(self.merged_data) < 2:
            print("Need at least two runs with merged data to compare.")
            return None
        
        new_findings = {}
        sorted_runs = sorted(self.merged_data.keys())
        
        for i in range(1, len(sorted_runs)):
            prev_run = sorted_runs[i-1]
            curr_run = sorted_runs[i]
            
            prev_df = self.merged_data[prev_run]
            curr_df = self.merged_data[curr_run]
            
            # Create finding signatures as before
            for df in [prev_df, curr_df]:
                id_columns = []
                for col in ['FINDING_ID', 'TITLE', 'DESCRIPTION', 'RESOURCE_ID']:
                    if col in df.columns:
                        id_columns.append(col)
                
                if id_columns:
                    df['FINDING_SIGNATURE'] = df[id_columns].apply(
                        lambda row: '_'.join(str(val) for val in row), axis=1
                    )
            
            # Find signatures in current run but not in previous run
            if 'FINDING_SIGNATURE' in prev_df.columns and 'FINDING_SIGNATURE' in curr_df.columns:
                prev_signatures = set(prev_df['FINDING_SIGNATURE'])
                curr_signatures = set(curr_df['FINDING_SIGNATURE'])
                
                new_signatures = curr_signatures - prev_signatures
                new_df = curr_df[curr_df['FINDING_SIGNATURE'].isin(new_signatures)]
                
                if not new_df.empty:
                    new_findings[curr_run] = new_df
                    print(f"Found {len(new_df)} new findings in {curr_run} compared to {prev_run}")
            else:
                print(f"Could not create finding signatures for {prev_run} or {curr_run}")
        
        self.comparison_results['new_findings'] = new_findings
        return new_findings
    
    def find_fixed_findings(self):
        """
        Identify findings that were fixed in each run compared to the previous run.
        
        Returns:
        dict: Fixed findings for each run
        """
        if not self.merged_data or len(self.merged_data) < 2:
            print("Need at least two runs with merged data to compare.")
            return None
        
        fixed_findings = {}
        sorted_runs = sorted(self.merged_data.keys())
        
        for i in range(1, len(sorted_runs)):
            prev_run = sorted_runs[i-1]
            curr_run = sorted_runs[i]
            
            prev_df = self.merged_data[prev_run]
            curr_df = self.merged_data[curr_run]
            
            # Create finding signatures
            for df in [prev_df, curr_df]:
                id_columns = []
                for col in ['FINDING_ID', 'TITLE', 'DESCRIPTION', 'RESOURCE_ID']:
                    if col in df.columns:
                        id_columns.append(col)
                
                if id_columns:
                    df['FINDING_SIGNATURE'] = df[id_columns].apply(
                        lambda row: '_'.join(str(val) for val in row), axis=1
                    )
            
            # Find signatures in previous run but not in current run
            if 'FINDING_SIGNATURE' in prev_df.columns and 'FINDING_SIGNATURE' in curr_df.columns:
                prev_signatures = set(prev_df['FINDING_SIGNATURE'])
                curr_signatures = set(curr_df['FINDING_SIGNATURE'])
                
                fixed_signatures = prev_signatures - curr_signatures
                fixed_df = prev_df[prev_df['FINDING_SIGNATURE'].isin(fixed_signatures)]
                
                if not fixed_df.empty:
                    fixed_findings[curr_run] = fixed_df
                    print(f"Found {len(fixed_df)} fixed findings in {curr_run} compared to {prev_run}")
            else:
                print(f"Could not create finding signatures for {prev_run} or {curr_run}")
        
        self.comparison_results['fixed_findings'] = fixed_findings
        return fixed_findings
    
    def run_complete_analysis(self):
        """
        Run a complete analysis on all available data.
        """
        print("Starting complete analysis...")
        self.discover_runs()
        self.load_summaries()
        self.load_merged_data()
        
        # Run all comparisons
        self.compare_severity_counts()
        self.compare_status_counts()
        self.compare_project_counts()
        self.find_recurring_findings()
        self.find_new_findings()
        self.find_fixed_findings()
        
        print("Analysis complete.")
        return self.comparison_results
    
    def generate_reports(self, output_dir):
        """
        Generate reports from the comparison results.
        
        Parameters:
        output_dir (str): Directory to save reports
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Ensure we have results
        if not self.comparison_results:
            print("No comparison results. Please run analysis first.")
            return
        
        # Save summary reports
        for name, result in self.comparison_results.items():
            if isinstance(result, pd.DataFrame):
                output_file = os.path.join(output_dir, f"{name}.csv")
                result.to_csv(output_file, index=False, sep=';')
                print(f"Saved {name} to {output_file}")
                
            elif isinstance(result, dict) and name in ['new_findings', 'fixed_findings']:
                for run, df in result.items():
                    run_name = run.replace(':', '-')  # Sanitize for filenames
                    output_file = os.path.join(output_dir, f"{name}_{run_name}.csv")
                    df.to_csv(output_file, index=False, sep=';')
                    print(f"Saved {name} for {run} to {output_file}")
                    
        # Generate trend charts
        self.generate_trend_charts(output_dir)
        
        # Generate comparison summary
        self.generate_comparison_summary(output_dir)
    
    def generate_trend_charts(self, output_dir):
        """
        Generate trend charts from the comparison results.
        
        Parameters:
        output_dir (str): Directory to save charts
        """
        charts_dir = os.path.join(output_dir, "charts")
        os.makedirs(charts_dir, exist_ok=True)
        
        # Severity trend chart
        if 'severity_counts' in self.comparison_results:
            severity_df = self.comparison_results['severity_counts']
            if not severity_df.empty:
                plt.figure(figsize=(12, 6))
                
                # Plot each severity as a line
                for col in severity_df.columns:
                    if col not in ['run', 'date']:
                        plt.plot(severity_df['date'], severity_df[col], marker='o', label=col)
                
                plt.title('Severity Trends Over Time')
                plt.xlabel('Date')
                plt.ylabel('Number of Findings')
                plt.legend()
                plt.grid(True, linestyle='--', alpha=0.7)
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                chart_file = os.path.join(charts_dir, 'severity_trend.png')
                plt.savefig(chart_file)
                plt.close()
                print(f"Saved severity trend chart to {chart_file}")
        
        # Status trend chart
        if 'status_counts' in self.comparison_results:
            status_df = self.comparison_results['status_counts']
            if not status_df.empty:
                plt.figure(figsize=(12, 6))
                
                # Plot each status as a line
                for col in status_df.columns:
                    if col not in ['run', 'date']:
                        plt.plot(status_df['date'], status_df[col], marker='o', label=col)
                
                plt.title('Status Trends Over Time')
                plt.xlabel('Date')
                plt.ylabel('Number of Findings')
                plt.legend()
                plt.grid(True, linestyle='--', alpha=0.7)
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                chart_file = os.path.join(charts_dir, 'status_trend.png')
                plt.savefig(chart_file)
                plt.close()
                print(f"Saved status trend chart to {chart_file}")
                
        # New vs Fixed findings chart
        new_counts = {}
        fixed_counts = {}
        
        if 'new_findings' in self.comparison_results:
            for run, df in self.comparison_results['new_findings'].items():
                new_counts[run] = len(df)
                
        if 'fixed_findings' in self.comparison_results:
            for run, df in self.comparison_results['fixed_findings'].items():
                fixed_counts[run] = len(df)
                
        if new_counts and fixed_counts:
            all_runs = sorted(set(list(new_counts.keys()) + list(fixed_counts.keys())))
            
            # Create a DataFrame for plotting
            trends_df = pd.DataFrame({
                'run': all_runs,
                'new': [new_counts.get(run, 0) for run in all_runs],
                'fixed': [fixed_counts.get(run, 0) for run in all_runs]
            })
            
            # Add date column
            trends_df['date'] = trends_df['run'].apply(
                lambda x: datetime.strptime(x, '%Y-%m-%d_%H-%M-%S').strftime('%Y-%m-%d')
            )
            
            # Plot
            plt.figure(figsize=(12, 6))
            plt.bar(trends_df['date'], trends_df['new'], color='red', alpha=0.7, label='New Findings')
            plt.bar(trends_df['date'], trends_df['fixed'], color='green', alpha=0.7, label='Fixed Findings')
            
            plt.title('New vs Fixed Findings Over Time')
            plt.xlabel('Date')
            plt.ylabel('Number of Findings')
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            chart_file = os.path.join(charts_dir, 'new_vs_fixed.png')
            plt.savefig(chart_file)
            plt.close()
            print(f"Saved new vs fixed chart to {chart_file}")
    
    def generate_comparison_summary(self, output_dir):
        """
        Generate a comprehensive comparison summary in markdown format.
        
        Parameters:
        output_dir (str): Directory to save the summary
        """
        summary_file = os.path.join(output_dir, "comparison_summary.md")
        
        with open(summary_file, 'w') as f:
            f.write("# Findings Comparison Summary\n\n")
            f.write(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Overview of runs
            f.write("## Analysis Runs\n\n")
            if self.runs:
                for i, run in enumerate(sorted(self.runs)):
                    f.write(f"{i+1}. {run}\n")
            else:
                f.write("No runs discovered.\n")
            f.write("\n")
            
            # Summary of findings by severity
            f.write("## Severity Trends\n\n")
            if 'severity_counts' in self.comparison_results:
                severity_df = self.comparison_results['severity_counts']
                if not severity_df.empty:
                    f.write("| Date |")
                    for col in severity_df.columns:
                        if col not in ['run', 'date']:
                            f.write(f" {col} |")
                    f.write("\n")
                    
                    f.write("| --- |")
                    for col in severity_df.columns:
                        if col not in ['run', 'date']:
                            f.write(" --- |")
                    f.write("\n")
                    
                    for _, row in severity_df.iterrows():
                        f.write(f"| {row['date']} |")
                        for col in severity_df.columns:
                            if col not in ['run', 'date']:
                                f.write(f" {row[col]} |")
                        f.write("\n")
            else:
                f.write("No severity data available.\n")
            f.write("\n")
            
            # Summary of findings by status
            f.write("## Status Trends\n\n")
            if 'status_counts' in self.comparison_results:
                status_df = self.comparison_results['status_counts']
                if not status_df.empty:
                    f.write("| Date |")
                    for col in status_df.columns:
                        if col not in ['run', 'date']:
                            f.write(f" {col} |")
                    f.write("\n")
                    
                    f.write("| --- |")
                    for col in status_df.columns:
                        if col not in ['run', 'date']:
                            f.write(" --- |")
                    f.write("\n")
                    
                    for _, row in status_df.iterrows():
                        f.write(f"| {row['date']} |")
                        for col in status_df.columns:
                            if col not in ['run', 'date']:
                                f.write(f" {row[col]} |")
                        f.write("\n")
            else:
                f.write("No status data available.\n")
            f.write("\n")
            
            # New and fixed findings
            f.write("## New & Fixed Findings\n\n")
            f.write("| Run | New Findings | Fixed Findings |\n")
            f.write("| --- | --- | --- |\n")
            
            new_findings = self.comparison_results.get('new_findings', {})
            fixed_findings = self.comparison_results.get('fixed_findings', {})
            
            all_runs = sorted(set(list(new_findings.keys()) + list(fixed_findings.keys())))
            for run in all_runs:
                new_count = len(new_findings.get(run, pd.DataFrame())) if run in new_findings else 0
                fixed_count = len(fixed_findings.get(run, pd.DataFrame())) if run in fixed_findings else 0
                f.write(f"| {run} | {new_count} | {fixed_count} |\n")
            f.write("\n")
            
            # Most persistent findings
            f.write("## Top Recurring Findings\n\n")
            if 'recurring_findings' in self.comparison_results:
                recurring_df = self.comparison_results['recurring_findings']
                if not recurring_df.empty:
                    f.write("| Finding | Severity | Status | # of Runs |\n")
                    f.write("| --- | --- | --- | --- |\n")
                    
                    # Display top 10 or fewer if less than 10
                    top_n = min(10, len(recurring_df))
                    for _, row in recurring_df.head(top_n).iterrows():
                        finding_id = row['FINDING_SIGNATURE']
                        # Truncate if too long
                        if len(finding_id) > 50:
                            finding_id = finding_id[:47] + "..."
                            
                        f.write(f"| {finding_id} | {row['SEVERITY']} | {row['STATUS']} | {row['NUM_RUNS']} |\n")
            else:
                f.write("No recurring findings data available.\n")
            f.write("\n")
            
            # Images references
            f.write("## Trend Charts\n\n")
            f.write("![Severity Trends](charts/severity_trend.png)\n\n")
            f.write("![Status Trends](charts/status_trend.png)\n\n")
            f.write("![New vs Fixed Findings](charts/new_vs_fixed.png)\n\n")
            
        print(f"Generated comparison summary at {summary_file}")
    
def create_timestamped_directory(parent_dir):
    """
    Create a timestamped directory within the parent directory.
    
    Parameters:
    parent_dir (str): Parent directory
    
    Returns:
    str: Path to created directory
    """
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    new_dir = os.path.join(parent_dir, timestamp)
    os.makedirs(new_dir, exist_ok=True)
    return new_dir

def run_comparison_analysis(analysis_base_dir, output_dir=None):
    """
    Run a full comparison analysis on the analysis output directories.
    
    Parameters:
    analysis_base_dir (str): Directory containing analysis output subdirectories
    output_dir (str, optional): Directory where to save comparison results
    
    Returns:
    dict: Comparison results
    """
    analyzer = FindingsAnalyzer(analysis_base_dir)
    results = analyzer.run_complete_analysis()
    
    if output_dir:
        analyzer.generate_reports(output_dir)
    
    return results

# Example usage
if __name__ == "__main__":
    # Base directory where all analysis runs are stored
    analysis_base_dir = "./analysis_output"
    
    # Directory to save comparison results
    comparison_output_dir = "./comparison_results"
    
    # Run the comparison
    results = run_comparison_analysis(analysis_base_dir, comparison_output_dir)
