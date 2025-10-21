import pandas as pd

class ExcelReader:
    """
    Utility class for reading specified cell ranges from Excel files.
    """

    @staticmethod
    def read_cells(file_path, column, row_start, row_end, sheet_name=None):
        """
        Reads values from a specific column and row range in an Excel file.

        :param file_path: Path to the Excel file.
        :param column: Column letter or index (0-based int or 'A', 'B', etc.).
        :param row_start: Starting row number (1-based, as in Excel).
        :param row_end: Ending row number (inclusive, as in Excel).
        :param sheet_name: Optional sheet name. If None, uses the first sheet.
        :return: List of values in the specified range.
        """
        # Convert column letter to index if needed
        if isinstance(column, str):
            col_idx = ord(column.upper()) - ord('A')
        else:
            col_idx = column

        df = pd.read_excel(file_path, header=None, sheet_name=sheet_name)
        # If sheet_name is None, df is a dict of DataFrames; select the first sheet
        if isinstance(df, dict):
            df = next(iter(df.values()))
        # Adjust for 0-based indexing in pandas
        values = df.iloc[row_start-1:row_end, col_idx].tolist()
        return values
