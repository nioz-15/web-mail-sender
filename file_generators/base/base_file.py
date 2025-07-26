import os
import tempfile
import subprocess
import shutil
from abc import ABC, abstractmethod
from typing import Optional, Union
from io import BytesIO
from file_generators.constants import DEFAULT_PASSWORD



class BaseFile(ABC):
    """Base class for all file generators."""

    def __init__(self, password: str = DEFAULT_PASSWORD):
        self.password = password
        self._data = None
        self._file_bytes = None

    @abstractmethod
    def generate(self, data: str, **kwargs) -> bytes:
        """Generate file bytes from data."""
        pass

    @abstractmethod
    def get_file_extension(self) -> str:
        """Return the file extension for this file type."""
        pass

    def compress_zip(self, data: Union[str, bytes], filename: Optional[str] = None,
                     encrypt: bool = True) -> bytes:
        """
        Create ZIP archive using command line zip tool.

        Args:
            data: File data to compress
            filename: Optional filename for the archived file (e.g., "content.docx")
            encrypt: Whether to password-protect the archive

        Returns:
            ZIP archive bytes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        with tempfile.TemporaryDirectory() as temp_dir:
            # Use specified filename or create a default one
            if filename:
                source_filename = filename
            else:
                source_filename = f"content{self.get_file_extension()}"

            # Create source file with proper name
            source_path = os.path.join(temp_dir, source_filename)
            with open(source_path, 'wb') as f:
                f.write(data)

            # Create ZIP archive
            zip_path = os.path.join(temp_dir, "archive.zip")

            if encrypt and self.password:
                print(f"Creating password-protected ZIP archive with CLI (filename: {source_filename})")
                cmd = ["zip", "-P", self.password, "-j", zip_path, source_path]
            else:
                print(f"Creating unencrypted ZIP archive with CLI (filename: {source_filename})")
                cmd = ["zip", "-j", zip_path, source_path]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                print(f"ZIP command output: {result.stdout}")

                # Read the created ZIP file
                with open(zip_path, 'rb') as f:
                    zip_data = f.read()

                print(f"Successfully created ZIP archive ({len(zip_data)} bytes)")
                return zip_data

            except subprocess.CalledProcessError as e:
                print(f"ZIP creation failed: {e.stderr}")
                raise RuntimeError(f"Failed to create ZIP archive: {e.stderr}")

            finally:
                # Clean up files
                if os.path.exists(source_path):
                    os.remove(source_path)

    def compress_rar(self, data: Union[str, bytes], filename: Optional[str] = None,
                     encrypt: bool = True) -> bytes:
        """
        Create RAR archive using command line rar tool.

        Args:
            data: File data to compress
            filename: Optional filename for the archived file (e.g., "content.docx")
            encrypt: Whether to password-protect the archive

        Returns:
            RAR archive bytes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Check if RAR is available
        rar_exe = shutil.which("rar")
        if rar_exe is None:
            print("RAR CLI not found!")
            raise AssertionError("RAR CLI not found!")

        with tempfile.TemporaryDirectory() as temp_dir:
            # Use specified filename or create a default one
            if filename:
                source_filename = filename
            else:
                source_filename = f"content{self.get_file_extension()}"

            # Create source file with proper name
            source_path = os.path.join(temp_dir, source_filename)
            with open(source_path, 'wb') as f:
                f.write(data)

            # Create RAR archive
            rar_path = os.path.join(temp_dir, "archive.rar")

            if encrypt and self.password:
                print(f"Creating password-protected RAR archive with CLI (filename: {source_filename})")
                cmd = ["rar", "a", f"-p{self.password}", rar_path, source_path]
            else:
                print(f"Creating unencrypted RAR archive with CLI (filename: {source_filename})")
                cmd = ["rar", "a", rar_path, source_path]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                print(f"RAR command output: {result.stdout}")

                # Read the created RAR file
                with open(rar_path, 'rb') as f:
                    rar_data = f.read()

                print(f"Successfully created RAR archive ({len(rar_data)} bytes)")
                return rar_data

            except subprocess.CalledProcessError as e:
                print(f"RAR creation failed: {e.stderr}")
                raise RuntimeError(f"Failed to create RAR archive: {e.stderr}")

            finally:
                # Clean up files
                if os.path.exists(source_path):
                    os.remove(source_path)

    def compress(self, data: Union[str, bytes], archive_type: str = "zip",
                 filename: Optional[str] = None, encrypt: bool = True) -> bytes:
        """
        Compress file data into specified archive format using CLI tools.

        Args:
            data: File data to compress
            archive_type: Type of archive ('zip' or 'rar')
            filename: Filename for the archived file (e.g., "content.docx")
            encrypt: Whether to password-protect the archive

        Returns:
            Compressed archive bytes
        """
        archive_type = archive_type.lower()

        print(
            f"Compressing {len(data) if isinstance(data, bytes) else len(data.encode())} bytes using {archive_type}, encrypt={encrypt}, filename={filename}")

        if archive_type == "zip":
            return self.compress_zip(data, filename, encrypt)
        elif archive_type == "rar":
            return self.compress_rar(data, filename, encrypt)
        elif archive_type == "ace":
            # ACE format is rarely supported, fall back to ZIP
            print("ACE format not supported, using ZIP instead")
            return self.compress_zip(data, filename, encrypt)
        else:
            raise ValueError(f"Unsupported archive type: {archive_type}")

    def validate_compression_tools(self) -> dict:
        """
        Check which compression tools are available on the system.

        Returns:
            dict: Status of available compression tools
        """
        tools = {
            'zip': shutil.which('zip') is not None,
            'rar': shutil.which('rar') is not None
        }

        print(f"Compression tools availability: {tools}")
        return tools
