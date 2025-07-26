import random
from io import BytesIO
import PyPDF2
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from file_generators.base.base_file import BaseFile
from file_generators.utils.helpers import generate_random_id


class PDFFile(BaseFile):
    """PDF file generator with malware signature preservation support."""

    def get_file_extension(self) -> str:
        return ".pdf"

    def generate(self, data: str, location: str = "top-left", encrypt: bool = False,
                 preserve_content: bool = False, **kwargs) -> bytes:
        """
        Generate a PDF document with the provided data.

        Args:
            data: Content to include in PDF
            location: Text placement ("top-left", "top-right", "bottom-left", "bottom-right", "center")
            encrypt: Whether to password-protect the PDF
            preserve_content: If True, preserves content exactly (critical for EICAR)
            **kwargs: Additional parameters (ignored)

        Returns:
            PDF file bytes
        """
        try:
            if preserve_content:
                print("PDFFile: Preserving content exactly (EICAR mode)")
                # CRITICAL: For EICAR, don't add random ID
                final_data = data
            else:
                print(f"PDFFile: Standard mode, location={location}")
                # Standard mode: append random ID
                final_data = data + "\n" + generate_random_id()

            # Create PDF bytes
            byte_io = BytesIO()
            c = canvas.Canvas(byte_io, pagesize=letter)

            # Generate random color
            if preserve_content:
                # Use black for preserved content
                c.setFillColorRGB(0, 0, 0)
            else:
                random_color = (random.random(), random.random(), random.random())
                c.setFillColorRGB(*random_color)

            # Set font
            c.setFont("Helvetica", 12)

            # Calculate position
            width, height = letter
            margin = 72

            location_map = {
                "top-left": (margin, height - margin),
                "top-right": (width - margin, height - margin),
                "bottom-left": (margin, margin),
                "bottom-right": (width - margin, margin),
                "center": (width / 2, height / 2),
            }
            x, y = location_map.get(location, location_map["top-left"])

            # Split text into lines and draw
            lines = final_data.splitlines()
            line_height = 14
            for i, line in enumerate(lines):
                current_y = y - i * line_height
                if location in ["top-right", "bottom-right"]:
                    text_width = c.stringWidth(line, "Helvetica", 12)
                    current_x = x - text_width
                else:
                    current_x = x
                c.drawString(current_x, current_y, line)

            c.showPage()
            c.save()

            pdf_bytes = byte_io.getvalue()
            byte_io.close()

            # Handle encryption
            if encrypt:
                print(f"PDFFile: Encrypting PDF with password")
                input_pdf = PyPDF2.PdfReader(BytesIO(pdf_bytes))
                output_pdf = PyPDF2.PdfWriter()

                for page in input_pdf.pages:
                    output_pdf.add_page(page)

                output_pdf.encrypt(self.password)

                output_buffer = BytesIO()
                output_pdf.write(output_buffer)
                output_buffer.seek(0)
                encrypted_pdf = output_buffer.getvalue()
                output_buffer.close()

                if preserve_content:
                    print(
                        f"PDFFile: Generated encrypted PDF with preserved content ({len(encrypted_pdf)} bytes)")

                return encrypted_pdf
            else:
                if preserve_content:
                    print(f"PDFFile: Generated PDF with preserved content ({len(pdf_bytes)} bytes)")

                return pdf_bytes

        except Exception as e:
            print(f"Error generating PDF file: {e}")
            raise
