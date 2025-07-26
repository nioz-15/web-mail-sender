import io
from file_generators.base.base_file import BaseFile
from file_generators.utils.helpers import generate_random_id


class TextFile(BaseFile):
    """Text file generator with malware signature preservation support."""

    def get_file_extension(self) -> str:
        return ".txt"

    def generate(self, data: str, line_number: int = 1, encrypt: bool = False,
                 preserve_content: bool = False, **kwargs) -> bytes:
        """
        Generate a TXT file and place text at a specific line number.

        Args:
            data: Content to write
            line_number: Line number to place the content (1-based)
            encrypt: Whether to encrypt (not supported for TXT)
            preserve_content: If True, preserves content exactly (critical for EICAR)
            **kwargs: Additional parameters (ignored)

        Returns:
            File bytes
        """
        try:
            if preserve_content:
                print("TextFile: Preserving content exactly (EICAR mode)")
                # CRITICAL: For EICAR and other malware signatures, preserve content exactly
                final_content = data
            else:
                # Standard mode: add random ID and process normally
                print(f"TextFile: Standard mode, placing content at line {line_number}")

                # Validate line number
                if line_number is None:
                    line_number = 1
                try:
                    line_number = int(line_number) if line_number else 1
                    if line_number < 1:
                        raise ValueError("Line number must be 1 or greater.")
                except ValueError:
                    raise ValueError("Invalid line number. Must be a positive integer.")

                # Add random ID for tracking (only in standard mode)
                data_with_id = data + "\n" + generate_random_id()

                # Create content with empty lines before the data
                lines = [""] * (line_number - 1) + [data_with_id]
                final_content = "\n".join(lines)

            # Convert to bytes
            text_io = io.StringIO()
            text_io.write(final_content)
            byte_data = text_io.getvalue().encode("utf-8")
            text_io.close()

            if preserve_content:
                print(f"TextFile: Generated preserved content ({len(byte_data)} bytes)")
            else:
                print(
                    f"TextFile: Generated standard content at line {line_number} ({len(byte_data)} bytes)")

            return byte_data

        except Exception as e:
            print(f"Error generating text file: {e}")
            raise
