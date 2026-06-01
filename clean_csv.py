import pandas as pd
import glob
import os

for folder in ['dataset/labeled', 'dataset/raw']:
    for f in glob.glob(f'{folder}/*.csv'):
        try:
            # Read line by line to handle potential malformed headers
            with open(f, 'r') as file:
                lines = file.readlines()
            
            if not lines:
                continue
                
            # Parse CSV correctly, skipping bad lines or cleaning spaces
            df = pd.read_csv(f, skipinitialspace=True, on_bad_lines='skip')
            
            # Strip spaces from column names
            df.columns = [str(c).strip() for c in df.columns]
            
            # Drop rows where 'decision' is null or invalid if it's a labeled dataset
            if folder == 'dataset/labeled':
                if 'decision' in df.columns:
                    df['decision'] = df['decision'].astype(str).str.strip()
                    df = df[df['decision'].isin(['PASS', 'BLOCK'])]
            
            # Save cleaned
            df.to_csv(f, index=False)
            print(f"Cleaned {f}, rows: {len(df)}")
            
        except Exception as e:
            print(f"Error on {f}: {e}")

