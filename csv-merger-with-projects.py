import pandas as pd
import glob
import os
import re

def parse_accounts_list(accounts_file):
    """
    Parse the ACCOUNTS_LIST.txt file to get all account numbers.
    
    Parameters:
    accounts_file (str): Path to the ACCOUNTS_LIST.txt file
    
    Returns:
    list: List of account numbers
    """
    with open(accounts_file, 'r') as f:
        content = f.read()
        
    # Extract account numbers from the content
    match = re.search(r"ACCOUNTS_LIST='(.*)'", content)
    if match:
        accounts_str = match.group(1)
        accounts = accounts_str.split()
        return accounts
    
    return []

def merge_and_analyze_csv_files(input_path, output_dir, accounts_file, master_account_file):
    """
    Merge all CSV files and analyze the findings.
    Split by severity, status, and project.
    
    Parameters:
    input_path (str): Path to directory containing CSV files
    output_dir (str): Directory where output files will be saved
    accounts_file (str): Path to the ACCOUNTS_LIST.txt file
    master_account_file (str): Path to the master-account.csv file that maps accounts to projects
    
    Returns:
    bool: True if successful, False otherwise
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Parse accounts list
        print("Parsing accounts list...")
        accounts = parse_accounts_list(accounts_file)
        print(f"Found {len(accounts)} accounts")
        
        # Read master account mapping
        print("Reading master account mapping...")
        try:
            master_df = pd.read_csv(master_account_file, sep=';')
            # Convert column names to uppercase for consistency
            master_df.columns = master_df.columns.str.upper()
            
            # Check if master_df has the expected columns
            if 'ACCOUNT' not in master_df.columns or 'PROJECT' not in master_df.columns:
                print("Warning: master account file should have 'ACCOUNT' and 'PROJECT' columns")
                print(f"Found columns: {master_df.columns.tolist()}")
        except Exception as e:
            print(f"Error reading master account file: {str(e)}")
            print("Proceeding without project separation")
            master_df = None
        
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
        
        # Print column names and unique values
        print("\nColumns in merged dataset:")
        for col in merged_df.columns:
            print(f"- {col}")
            
        # Look for account column
        account_col = None
        for col in merged_df.columns:
            if 'ACCOUNT' in col:
                account_col = col
                break
        
        if account_col:
            print(f"\nFound account column: {account_col}")
            print(f"Sample accounts: {merged_df[account_col].head().tolist()}")
        else:
            print("\nWarning: No account column found in the data")
            print("Available columns:", merged_df.columns.tolist())
        
        # Save complete merged file
        merged_file = os.path.join(output_dir, "merged_complete.csv")
        merged_df.to_csv(merged_file, index=False, sep=';')
        print(f"Saved complete merged file to: {merged_file}")
        
        # Process by severity and status
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        statuses = ["PASS", "FAIL"]
        
        # Create directories for organizing the output
        severity_dir = os.path.join(output_dir, "by_severity")
        status_dir = os.path.join(output_dir, "by_status")
        combo_dir = os.path.join(output_dir, "by_severity_and_status")
        project_dir = os.path.join(output_dir, "by_project")
        
        os.makedirs(severity_dir, exist_ok=True)
        os.makedirs(status_dir, exist_ok=True)
        os.makedirs(combo_dir, exist_ok=True)
        os.makedirs(project_dir, exist_ok=True)
        
        # Split by severity
        for severity in severities:
            df_severity = merged_df[merged_df['SEVERITY'] == severity]
            if not df_severity.empty:
                filename = os.path.join(severity_dir, f"{severity.lower()}.csv")
                df_severity.to_csv(filename, index=False, sep=';')
                print(f"Created {severity} file with {len(df_severity)} records")
        
        # Split by status
        for status in statuses:
            df_status = merged_df[merged_df['STATUS'] == status]
            if not df_status.empty:
                filename = os.path.join(status_dir, f"{status.lower()}.csv")
                df_status.to_csv(filename, index=False, sep=';')
                print(f"Created {status} file with {len(df_status)} records")
        
        # Split by both severity and status
        for severity in severities:
            for status in statuses:
                mask = (merged_df['SEVERITY'] == severity) & (merged_df['STATUS'] == status)
                df_combo = merged_df[mask]
                if not df_combo.empty:
                    filename = os.path.join(combo_dir, f"{severity.lower()}_{status.lower()}.csv")
                    df_combo.to_csv(filename, index=False, sep=';')
                    print(f"Created {severity}_{status} file with {len(df_combo)} records")
        
        # Split by project if master_df is available and account_col is found
        if master_df is not None and account_col:
            print("\nSplitting by project...")
            
            # Create a mapping from account to project
            account_to_project = dict(zip(master_df['ACCOUNT'], master_df['PROJECT']))
            
            # Add project column to merged_df
            merged_df['PROJECT'] = merged_df[account_col].map(account_to_project)
            
            # Get unique projects
            projects = merged_df['PROJECT'].dropna().unique()
            print(f"Found {len(projects)} unique projects")
            
            # Create files for each project
            for project in projects:
                df_project = merged_df[merged_df['PROJECT'] == project]
                if not df_project.empty:
                    # Create project directory
                    project_specific_dir = os.path.join(project_dir, project)
                    os.makedirs(project_specific_dir, exist_ok=True)
                    
                    # Save overall project file
                    project_file = os.path.join(project_specific_dir, "all_findings.csv")
                    df_project.to_csv(project_file, index=False, sep=';')
                    
                    # Split by severity for this project
                    for severity in severities:
                        df_proj_sev = df_project[df_project['SEVERITY'] == severity]
                        if not df_proj_sev.empty:
                            filename = os.path.join(project_specific_dir, f"{severity.lower()}.csv")
                            df_proj_sev.to_csv(filename, index=False, sep=';')
                    
                    # Split by status for this project
                    for status in statuses:
                        df_proj_stat = df_project[df_project['STATUS'] == status]
                        if not df_proj_stat.empty:
                            filename = os.path.join(project_specific_dir, f"{status.lower()}.csv")
                            df_proj_stat.to_csv(filename, index=False, sep=';')
                    
                    # Split by severity and status for this project
                    for severity in severities:
                        for status in statuses:
                            mask = (df_project['SEVERITY'] == severity) & (df_project['STATUS'] == status)
                            df_proj_combo = df_project[mask]
                            if not df_proj_combo.empty:
                                filename = os.path.join(project_specific_dir, f"{severity.lower()}_{status.lower()}.csv")
                                df_proj_combo.to_csv(filename, index=False, sep=';')
                    
                    print(f"Created files for project '{project}' with {len(df_project)} records")
        
        # Create summary
        summary = {
            'total_findings': len(merged_df),
            'by_severity': {sev: len(merged_df[merged_df['SEVERITY'] == sev]) for sev in severities},
            'by_status': {stat: len(merged_df[merged_df['STATUS'] == stat]) for stat in statuses}
        }
        
        # Add project summary if available
        if master_df is not None and account_col and 'PROJECT' in merged_df.columns:
            project_counts = merged_df['PROJECT'].value_counts().to_dict()
            summary['by_project'] = project_counts
        
        # Save summary as JSON
        summary_file = os.path.join(output_dir, "analysis_summary.json")
        pd.Series(summary).to_json(summary_file, indent=4)
        
        # Print summary
        print("\nAnalysis Summary:")
        print(f"Total findings: {summary['total_findings']}")
        print("\nFindings by Severity:")
        for severity, count in summary['by_severity'].items():
            print(f"{severity}: {count}")
        print("\nFindings by Status:")
        for status, count in summary['by_status'].items():
            print(f"{status}: {count}")
        
        if 'by_project' in summary:
            print("\nFindings by Project:")
            for project, count in summary['by_project'].items():
                if pd.notna(project):  # Skip None/NaN projects
                    print(f"{project}: {count}")
        
        return True
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

# Example usage
if __name__ == "__main__":
    input_directory = "./prowler_analysis/scans/scan_20250501"
    output_directory = "./prowler_analysis/20250501_analysis_output"
    accounts_file = "./ACCOUNTS_LIST.txt"
    master_account_file = "./master-account.csv"
    
    merge_and_analyze_csv_files(input_directory, output_directory, accounts_file, master_account_file)
