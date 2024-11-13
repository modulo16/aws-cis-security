import pandas as pd
import glob
import os

def merge_csv_files(input_path, output_file):
    """
    Merge all CSV files in the specified directory into a single CSV file.
    Uses semicolon (;) as the delimiter.
    
    Parameters:
    input_path (str): Path to directory containing CSV files
    output_file (str): Path for the output merged CSV file
    
    Returns:
    bool: True if successful, False otherwise
    """
    try:
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
                # Added sep=';' parameter to read_csv
                df = pd.read_csv(file, sep=';')
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
        
        # Save to output file with semicolon delimiter
        merged_df.to_csv(output_file, index=False, sep=';')
        print(f"Successfully merged {len(dfs)} files into {output_file}")
        print(f"Final dataset shape: {merged_df.shape}")
        
        return True
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

# Example usage
if __name__ == "__main__":
    # Replace these paths with your actual paths
    input_directory = "/Users/mikewis/CDW-OneDrive/OneDrive - CDW/Client Docs/Clients/FCB/output"
    output_file = "./merged_output.csv"
    
    merge_csv_files(input_directory, output_file)