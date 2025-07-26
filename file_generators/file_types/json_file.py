import json
from io import BytesIO
from file_generators.base.base_file import BaseFile

from file_generators.utils.helpers import generate_random_id


class JSONFile(BaseFile):
    """JSON file generator with malware signature preservation support."""

    def get_file_extension(self) -> str:
        return ".json"

    def generate(self, data: str, message: str = "message", encrypt: bool = False,
                 preserve_content: bool = False, **kwargs) -> bytes:
        """
        Generate JSON file with data.

        Args:
            data: Content value
            message: JSON key name
            encrypt: Whether to encrypt (not supported for JSON)
            preserve_content: If True, preserves content exactly (critical for EICAR)
            **kwargs: Additional parameters (ignored)

        Returns:
            JSON file bytes
        """
        try:
            if preserve_content:
                print("JSONFile: Preserving content exactly (EICAR mode)")
                # CRITICAL: For EICAR, use exact content only
                json_data = {message: data}
            else:
                print(f"JSONFile: Standard mode, message key='{message}'")
                # Standard mode
                json_data = {
                    message: data,
                    "generated_by": "automation",
                    "tracking_id": generate_random_id()
                }

            # Convert to JSON string
            json_string = json.dumps(json_data, indent=4)

            # Convert to bytes
            byte_io = BytesIO()
            byte_io.write(json_string.encode("utf-8"))

            byte_data = byte_io.getvalue()
            byte_io.close()

            if preserve_content:
                print(f"JSONFile: Generated JSON with preserved content ({len(byte_data)} bytes)")
            else:
                print(f"JSONFile: Generated standard JSON with key '{message}' ({len(byte_data)} bytes)")

            return byte_data

        except Exception as e:
            print(f"Error generating JSON file: {e}")
            raise
