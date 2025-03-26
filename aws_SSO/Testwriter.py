import pandas as pd
from datetime import datetime

def test_excel_writer():
    try:
        # Create sample data
        data = {
            'Group Name': ['Group1', 'Group1', 'Group2'],
            'Permission Set Name': ['Admin', 'ReadOnly', 'PowerUser'],
            'Account ID': ['111222333444', '555666777888', '999000111222']
        }

        # Create DataFrame
        df = pd.DataFrame(data)

        # Create timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f'test_excel_{timestamp}.xlsx'

        # Test Excel writing with formatting
        with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
            # Write DataFrame to Excel
            df.to_excel(writer, sheet_name='Test Sheet', index=False)
            
            # Get workbook and worksheet objects
            workbook = writer.book
            worksheet = writer.sheets['Test Sheet']
            
            # Add header formatting
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#D3D3D3',
                'border': 1
            })
            
            # Format headers
            for col_num, value in enumerate(df.columns.values):
                worksheet.write(0, col_num, value, header_format)
            
            # Adjust column widths
            for idx, col in enumerate(df.columns):
                max_length = max(
                    df[col].astype(str).apply(len).max(),
                    len(col)
                )
                worksheet.set_column(idx, idx, max_length + 2)

        print(f"Test successful! Excel file created: {output_file}")
        return True

    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return False

if __name__ == "__main__":
    test_excel_writer()
