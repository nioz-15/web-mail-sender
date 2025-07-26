import csv
from io import StringIO
from file_generators.base.base_file import BaseFile



class CSVFile(BaseFile):
    """CSV file generator with malware signature preservation support."""

    def get_file_extension(self) -> str:
        return ".csv"

    def generate(self, data: str, location: str = "1:1", encrypt: bool = False,
                 preserve_content: bool = False, **kwargs) -> bytes:
        """
        Generate CSV file with data at specific position.

        Args:
            data: Text content for cell
            location: Position as "row:column" (1-based)
            encrypt: Whether to encrypt (not supported for CSV)
            preserve_content: If True, preserves content exactly (critical for EICAR)
            **kwargs: Additional parameters (ignored)

        Returns:
            CSV file bytes
        """
        try:
            if preserve_content:
                print("CSVFile: Preserving content exactly (EICAR mode)")
                # CRITICAL: For EICAR, use exact content
                final_data = data
            else:
                print(f"CSVFile: Standard mode, location={location}")
                final_data = data

            # Parse location
            try:
                row, column = map(int, location.split(":"))
            except ValueError:
                raise ValueError("Invalid location format. Use 'row:column', e.g., '2:4'.")

            text_io = StringIO()
            writer = csv.writer(text_io)

            # Create grid and place data
            rows = [["" for _ in range(column)] for _ in range(row)]
            rows[row - 1][column - 1] = final_data

            writer.writerows(rows)

            byte_data = text_io.getvalue().encode("utf-8")
            text_io.close()

            if preserve_content:
                print(f"CSVFile: Generated preserved content ({len(byte_data)} bytes)")
            else:
                print(f"CSVFile: Generated standard content at {location} ({len(byte_data)} bytes)")

            return byte_data

        except Exception as e:
            print(f"Error generating CSV file: {e}")
            raise
