import json
import pandas as pd

# Replace with your actual JSON file name
input_file = 'nvdcve-2.0-2026.json'
output_file = 'vulnerabilities_data.xlsx'

print(f"Loading {input_file}...")

try:
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Target the specific list where your records are stored
    if 'vulnerabilities' in data:
        print("Flattening nested JSON data...")
        # json_normalize flattens the nested dictionaries into columns
        df = pd.json_normalize(data['vulnerabilities'])
        
        print(f"Saving {len(df)} rows to Excel. This may take a moment...")
        df.to_excel(output_file, index=False, engine='openpyxl')
        
        print(f"Success! Data saved to {output_file}")
    else:
        print("Error: Could not find the 'vulnerabilities' key in the JSON.")

except FileNotFoundError:
    print(f"Error: Could not find the file named {input_file}. Make sure it is in the same folder as this script.")
except Exception as e:
    print(f"An error occurred: {e}")