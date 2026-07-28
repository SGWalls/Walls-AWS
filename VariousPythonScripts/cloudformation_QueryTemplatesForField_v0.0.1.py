import os
import json
import yaml
from pathlib import Path

def check_files_for_mappings(directory_path):
    # List to store files that contain mappings
    files_with_mappings = []
    
    # Walk through the directory
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = Path(root) / file
            
            # Check only yaml/yml and json files
            if file_path.suffix.lower() not in ['.yaml', '.yml', '.json']:
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Parse based on file extension
                    if file_path.suffix.lower() in ['.yaml', '.yml']:
                        data = yaml.safe_load(content)
                    else:  # .json
                        data = json.loads(content)
                    
                    # Check if data is a dictionary and has 'Mappings' key
                    if isinstance(data, dict) and ('Mappings' in data or 'mappings' in data):
                        files_with_mappings.append(str(file_path))
                        
            except (yaml.YAMLError, json.JSONDecodeError) as e:
                # print(f"Error parsing {file_path}: {str(e)}")
                continue
            except Exception as e:
                # print(f"Error processing {file_path}: {str(e)}")
                continue
            
    return files_with_mappings

def main():
    # Replace with your directory path
    directory_path = r"C:\Users\sgwalls\Documents\AWS_Projects\CFT"
    
    files = check_files_for_mappings(directory_path)
    
    if files:
        print("\nFiles containing 'Mappings' section:")
        for file in files:
            print(f"- {file}")
    else:
        print("\nNo files found with 'Mappings' section.")

if __name__ == "__main__":
    main()
