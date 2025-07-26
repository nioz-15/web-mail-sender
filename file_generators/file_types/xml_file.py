import xml.etree.ElementTree as ET
from io import BytesIO
from file_generators.base.base_file import BaseFile
from file_generators.utils.helpers import generate_random_id


class XMLFile(BaseFile):
    """XML file generator with malware signature preservation support."""

    def get_file_extension(self) -> str:
        return ".xml"

    def generate(self, data: str, location: str = "root:data", encrypt: bool = False,
                 preserve_content: bool = False, **kwargs) -> bytes:
        """
        Generate XML file with data.

        Args:
            data: Text content
            location: Structure as "parent:child"
            encrypt: Whether to encrypt (not supported for XML)
            preserve_content: If True, preserves content exactly (critical for EICAR)
            **kwargs: Additional parameters (ignored)

        Returns:
            XML file bytes
        """
        try:
            if preserve_content:
                print("XMLFile: Preserving content exactly (EICAR mode)")
                # CRITICAL: For EICAR, use exact content
                final_data = data
                add_metadata = False
            else:
                print(f"XMLFile: Standard mode, location={location}")
                # Standard mode: use content as-is
                final_data = data
                add_metadata = True

            # Parse location
            try:
                parent, child = location.split(":")
            except ValueError:
                raise ValueError("Invalid location format. Use 'parent:child', e.g., 'report:entry'.")

            # Create XML structure
            root = ET.Element(parent)

            # Add main content element
            child_element = ET.SubElement(root, child)
            child_element.text = final_data

            # Add metadata in standard mode
            if add_metadata:
                metadata = ET.SubElement(root, "metadata")
                ET.SubElement(metadata, "generated_by").text = "automation"
                ET.SubElement(metadata, "tracking_id").text = generate_random_id()

            # Convert to bytes
            byte_io = BytesIO()
            tree = ET.ElementTree(root)
            tree.write(byte_io, encoding="utf-8", xml_declaration=True)

            byte_data = byte_io.getvalue()
            byte_io.close()

            if preserve_content:
                print(f"XMLFile: Generated XML with preserved content ({len(byte_data)} bytes)")
            else:
                print(
                    f"XMLFile: Generated standard XML with structure '{location}' ({len(byte_data)} bytes)")

            return byte_data

        except Exception as e:
            print(f"Error generating XML file: {e}")
            raise
