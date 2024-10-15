def generate_table(headers, rows, centered_columns=None):
    """
     Generate Markdown table
     :param headers: List of headers
     :param rows: Rows
     :param centered_columns: List with centered columns
     """
    COL_SEP = ' | '
    centered_column_set = set(centered_columns or [])
    def create_separator(header, index):
        if centered_columns is None:
            return '-'
        return ':-:' if index in centered_column_set else '-'

    row_separator = COL_SEP + COL_SEP.join(
        create_separator(header, index) for index, header in enumerate(headers)
    ) + COL_SEP

    table_rows = [COL_SEP + COL_SEP.join(headers) + COL_SEP]
    table_rows.append(row_separator)
    table_rows.extend(COL_SEP + COL_SEP.join(row) + COL_SEP for row in rows)

    return '\n'.join(table_rows)