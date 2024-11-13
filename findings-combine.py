import pandas as pd
import glob
import os

def analyze_findings(df):
    """
    Analyze findings by severity and status.
    
    Parameters:
    df (pandas.DataFrame): DataFrame containing the findings
    
    Returns:
    dict: Dictionary containing DataFrames split by severity and status
    """
    severities = ["critical", "high", "medium", "low"]
    statuses = ["PASS", "FAIL"]
    
    # Dictionary to store our split dataframes
    analysis = {
        'by_severity': {},
        'by_status': {},
        'by_severity_and_status': {},
        'summary': {}
    }
    
    # Split by severity
    for severity in severities:
        analysis['by_severity'][severity] = df[df['SEVERITY'] == severity]
    
    # Split by status
    for status in statuses:
        analysis['by_status'][status] = df[df['STATUS'] == status]
    
    # Split by both severity and status
    for severity in severities:
        analysis['by_severity_and_status'][severity] = {}
        for status in statuses:
            mask = (df['SEVERITY'] == severity) & (df['STATUS'] == status)
            analysis['by_severity_and_status'][severity][status] = df[mask]
    
    # Create summary statistics
    summary = {
        'total_findings': len(df),
        'by_severity': {sev: len(analysis['by_severity'][sev]) for sev in severities},
        'by_status': {stat: len(analysis['by_status'][stat]) for stat in statuses},
        'by_severity_and_status': {
            sev: {
                stat: len(analysis['by_severity_and_status'][sev][stat])
                for stat in statuses
            }
            for sev in severities
        }
    }
    
    analysis['summary'] = summary
    
    return analysis

def merge_and_analyze_csv_files(input_path, output_dir):
    """
    Merge all CSV files and analyze the findings.
    Expects and maintains column names in UPPERCASE.
    
    Parameters:
    input_path (str): Path to directory containing CSV files
    output_dir (str): Directory where output files will be saved
    
    Returns:
    bool: True if successful, False otherwise
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Get all CSV files in the directory
        csv_files = glob.glob(os.path.join(input_path, "*.csv"))
        
        if not csv_files:
            print(f"No CSV files found in {input_path}")
            return False
            
        print(f"Found {len(csv_files)} CSV files to merge")
        
        # Read and combine all CSV files
        dfs = []
        for file in csv_files:
            try:
                df = pd.read_csv(file, sep=';')
                # Convert column names to uppercase
                df.columns = df.columns.str.upper()
                dfs.append(df)
                print(f"Successfully read: {file}")
            except Exception as e:
                print(f"Error reading {file}: {str(e)}")
                continue
        
        if not dfs:
            print("No valid CSV files were read")
            return False
        
        # Concatenate all dataframes
        merged_df = pd.concat(dfs, ignore_index=True)
        
        # Print column names to verify
        print("\nColumns in merged dataset:")
        for col in merged_df.columns:
            print(f"- {col}")
        
        # Save complete merged file
        merged_file = os.path.join(output_dir, "merged_complete.csv")
        merged_df.to_csv(merged_file, index=False, sep=';')
        print(f"Saved complete merged file to: {merged_file}")
        
        # Analyze the findings
        analysis = analyze_findings(merged_df)
        
        # Save split files
        for severity, df in analysis['by_severity'].items():
            filename = os.path.join(output_dir, f"severity_{severity.lower()}.csv")
            df.to_csv(filename, index=False, sep=';')
            
        for status, df in analysis['by_status'].items():
            filename = os.path.join(output_dir, f"status_{status.lower()}.csv")
            df.to_csv(filename, index=False, sep=';')
            
        for severity in analysis['by_severity_and_status']:
            for status, df in analysis['by_severity_and_status'][severity].items():
                filename = os.path.join(output_dir, f"{severity.lower()}_{status.lower()}.csv")
                df.to_csv(filename, index=False, sep=';')
        
        # Save summary as JSON
        summary_file = os.path.join(output_dir, "analysis_summary.json")
        pd.Series(analysis['summary']).to_json(summary_file, indent=4)
        
        # Print summary
        print("\nAnalysis Summary:")
        print(f"Total findings: {analysis['summary']['total_findings']}")
        print("\nFindings by Severity:")
        for severity, count in analysis['summary']['by_severity'].items():
            print(f"{severity}: {count}")
        print("\nFindings by Status:")
        for status, count in analysis['summary']['by_status'].items():
            print(f"{status}: {count}")
        print("\nFindings by Severity and Status:")
        for severity in analysis['summary']['by_severity_and_status']:
            for status, count in analysis['summary']['by_severity_and_status'][severity].items():
                print(f"{severity} - {status}: {count}")
        
        return True
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

# Example usage
if __name__ == "__main__":
    input_directory = "/Users/mikewis/CDW-OneDrive/OneDrive - CDW/Client Docs/Clients/FCB/output"
    output_directory = "/Users/mikewis/CDW-OneDrive/OneDrive - CDW/Client Docs/Clients/FCB/analysis"
    
    merge_and_analyze_csv_files(input_directory, output_directory)