#!/usr/bin/env python3
import os
import sys
import argparse
import shutil
from datetime import datetime

# Import our modules
# Note: You'll need to save the other scripts in the same directory or adjust these imports
from run_analysis_with_timestamp import merge_and_analyze_csv_files, create_timestamped_directory
from findings_comparison import run_comparison_analysis

def setup_directories(base_dir):
    """
    Set up the directory structure for our findings tracker.
    
    Parameters:
    base_dir (str): Base directory for all outputs
    
    Returns:
    tuple: (csv_dir, analysis_dir, comparison_dir)
    """
    # Create main directories if they don't exist
    csv_dir = os.path.join(base_dir, "csv_files")
    analysis_dir = os.path.join(base_dir, "analysis_runs")
    comparison_dir = os.path.join(base_dir, "comparison_results")
    
    os.makedirs(csv_dir, exist_ok=True)
    os.makedirs(analysis_dir, exist_ok=True)
    os.makedirs(comparison_dir, exist_ok=True)
    
    return csv_dir, analysis_dir, comparison_dir

def run_analysis(csv_dir, analysis_dir, accounts_file=None, master_file=None):
    """
    Run analysis on CSV files and store results in a timestamped directory.
    
    Parameters:
    csv_dir (str): Directory containing CSV files
    analysis_dir (str): Directory to store analysis results
    accounts_file (str, optional): Path to accounts list file
    master_file (str, optional): Path to master account mapping
    
    Returns:
    str: Path to the created output directory
    """
    output_dir = create_timestamped_directory(analysis_dir)
    
    # Copy reference files if provided
    if accounts_file and os.path.exists(accounts_file):
        shutil.copy2(accounts_file, output_dir)
    if master_file and os.path.exists(master_file):
        shutil.copy2(master_file, output_dir)
    
    # Run analysis
    success = merge_and_analyze_csv_files(
        csv_dir, 
        output_dir, 
        accounts_file, 
        master_file
    )
    
    if success:
        print(f"Analysis completed successfully. Results saved to {output_dir}")
        return output_dir
    else:
        print("Analysis failed.")
        return None

def run_comparison(analysis_dir, comparison_dir):
    """
    Run comparison analysis on all analysis runs.
    
    Parameters:
    analysis_dir (str): Directory containing analysis runs
    comparison_dir (str): Directory to store comparison results
    
    Returns:
    str: Path to the created comparison output directory
    """
    # Create timestamped comparison directory
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_dir = os.path.join(comparison_dir, f"comparison_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    
    # Run comparison
    results = run_comparison_analysis(analysis_dir, output_dir)
    
    if results:
        print(f"Comparison completed successfully. Results saved to {output_dir}")
        return output_dir
    else:
        print("Comparison failed.")
        return None

def main():
    parser = argparse.ArgumentParser(description='Track and compare security findings over time.')
    parser.add_argument('--base-dir', '-b', default='./findings_tracker', 
                        help='Base directory for all operations (default: ./findings_tracker)')
    parser.add_argument('--accounts', '-a', help='Path to ACCOUNTS_LIST.txt file')
    parser.add_argument('--master', '-m', help='Path to master-account.csv file mapping accounts to projects')
    parser.add_argument('--csv-dir', '-c', help='Directory containing CSV files (overrides base-dir/csv_files)')
    parser.add_argument('--analysis-only', action='store_true', 
                        help='Only run analysis, skip comparison')
    parser.add_argument('--comparison-only', action='store_true', 
                        help='Only run comparison on existing analysis runs, skip new analysis')
    
    args = parser.parse_args()
    
    # Set up directory structure
    csv_dir, analysis_dir, comparison_dir = setup_directories(args.base_dir)
    
    # Override CSV directory if specified
    if args.csv_dir:
        csv_dir = args.csv_dir
        if not os.path.exists(csv_dir):
            print(f"Error: CSV directory {csv_dir} does not exist.")
            return 1
    
    # Run analysis if not comparison-only
    if not args.comparison_only:
        print("\n=== RUNNING ANALYSIS ===")
        output_dir = run_analysis(csv_dir, analysis_dir, args.accounts, args.master)
        if not output_dir:
            print("Analysis failed. Exiting.")
            return 1
    
    # Run comparison if not analysis-only
    if not args.analysis_only:
        print("\n=== RUNNING COMPARISON ===")
        output_dir = run_comparison(analysis_dir, comparison_dir)
        if not output_dir:
            print("Comparison failed. Exiting.")
            return 1
    
    print("\nAll operations completed successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
