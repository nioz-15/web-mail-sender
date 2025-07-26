import os
import tempfile
import subprocess
import shutil
from typing import List, Tuple, Union
from file_generators.base.base_file import BaseFile



class ArchiveFile(BaseFile):
    """Enhanced archive file generator supporting both single and multiple files."""

    def __init__(self, archive_type: str = "zip", password: str = None):
        super().__init__(password)
        self.archive_type = archive_type.lower()
        if self.archive_type not in ["zip", "rar", "ace"]:
            raise ValueError(f"Unsupported archive type: {archive_type}")

    def get_file_extension(self) -> str:
        return f".{self.archive_type}"

    def generate(self, data: Union[str, List[Tuple[str, bytes]]], encrypt: bool = True, **kwargs) -> bytes:
        """
        Generate archive file containing single text data or multiple files.

        Args:
            data: Either string (single file) or list of tuples [(filename, file_bytes), ...]
            encrypt: Whether to password-protect the archive
            **kwargs: Additional parameters (ignored for archives)

        Returns:
            Archive file bytes
        """
        if isinstance(data, str):
            # Single file mode
            print(f"Creating {self.archive_type} archive with single file, encrypt={encrypt}")
            return self._generate_single_file_archive(data, encrypt)
        elif isinstance(data, list):
            # Multi-file mode
            print(f"Creating {self.archive_type} archive with {len(data)} files, encrypt={encrypt}")
            return self._generate_multi_file_archive(data, encrypt)
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")

    def _generate_single_file_archive(self, data: str, encrypt: bool = True) -> bytes:
        """Generate archive with single file (existing logic)."""
        if self.archive_type == "zip":
            return self._create_zip_single(data, encrypt)
        elif self.archive_type == "rar":
            return self._create_rar_single(data, encrypt)
        elif self.archive_type == "ace":
            return self._create_ace(data)

    def _generate_multi_file_archive(self, file_data_list: List[Tuple[str, bytes]], encrypt: bool = True) -> bytes:
        """Generate archive with multiple files."""
        if self.archive_type == "zip":
            return self._create_zip_multi(file_data_list, encrypt)
        elif self.archive_type == "rar":
            return self._create_rar_multi(file_data_list, encrypt)
        elif self.archive_type == "ace":
            return self._create_ace_multi(file_data_list)

    def _create_zip_single(self, data: str, encrypt: bool = True) -> bytes:
        """Create ZIP file with single text file using CLI (existing logic)."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp_file:
            tmp_file.write(data.encode('utf-8'))
            tmp_file_path = tmp_file.name

        try:
            zip_path = tempfile.mktemp(suffix=".zip")

            if encrypt and self.password:
                print(f"Creating encrypted ZIP archive with password")
                result = subprocess.run([
                    "zip", "-j", "-P", self.password, zip_path, tmp_file_path
                ], capture_output=True, text=True)
            else:
                print(f"Creating unencrypted ZIP archive")
                result = subprocess.run([
                    "zip", "-j", zip_path, tmp_file_path
                ], capture_output=True, text=True)

            if result.returncode != 0:
                print(f"ZIP creation failed: {result.stderr}")
                raise RuntimeError(f"ZIP creation failed: {result.stderr}")

            with open(zip_path, "rb") as zip_file:
                zip_bytes = zip_file.read()

            os.remove(zip_path)
            print(f"Successfully created ZIP archive ({len(zip_bytes)} bytes)")
            return zip_bytes

        except FileNotFoundError:
            print("zip command not found in PATH")
            raise RuntimeError("ZIP creation failed: 'zip' command not found. Please install zip.")
        except Exception as e:
            print(f"Unexpected error creating ZIP: {e}")
            raise
        finally:
            if os.path.exists(tmp_file_path):
                os.remove(tmp_file_path)

    def _create_zip_multi(self, file_data_list: List[Tuple[str, bytes]], encrypt: bool = True) -> bytes:
        """Create ZIP file with multiple files using CLI."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create all individual files
            file_paths = []
            for filename, file_data in file_data_list:
                file_path = os.path.join(temp_dir, filename)
                with open(file_path, 'wb') as f:
                    f.write(file_data if isinstance(file_data, bytes) else file_data.encode())
                file_paths.append(file_path)

            # Create ZIP archive with all files
            zip_path = os.path.join(temp_dir, "multi_file_archive.zip")

            try:
                if encrypt and self.password:
                    cmd = ["zip", "-P", self.password, "-j", zip_path] + file_paths
                    print(f"Creating password-protected ZIP with {len(file_paths)} files")
                else:
                    cmd = ["zip", "-j", zip_path] + file_paths
                    print(f"Creating unencrypted ZIP with {len(file_paths)} files")

                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                print(f"ZIP creation successful: {result.stdout}")

                with open(zip_path, 'rb') as f:
                    zip_data = f.read()

                print(f"Created multi-file ZIP ({len(zip_data)} bytes)")
                return zip_data

            except subprocess.CalledProcessError as e:
                print(f"Multi-file ZIP creation failed: {e.stderr}")
                raise RuntimeError(f"Failed to create multi-file ZIP: {e.stderr}")
            except FileNotFoundError:
                print("zip command not found in PATH")
                raise RuntimeError("ZIP creation failed: 'zip' command not found. Please install zip.")

    def _create_rar_single(self, data: str, encrypt: bool = True) -> bytes:
        """Create RAR file with single text file using CLI (existing logic)."""
        rar_exe = shutil.which("rar")
        if rar_exe is None:
            print("RAR CLI not found")
            raise RuntimeError("RAR creation failed: 'rar' command not found. Please install rar.")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp_file:
            tmp_file.write(data.encode('utf-8'))
            tmp_file_path = tmp_file.name

        try:
            rar_path = tempfile.mktemp(suffix=".rar")

            if encrypt and self.password:
                print(f"Creating encrypted RAR archive with password")
                result = subprocess.run([
                    rar_exe, "a", "-ep", f"-p{self.password}", rar_path, tmp_file_path
                ], capture_output=True, text=True)
            else:
                print(f"Creating unencrypted RAR archive")
                result = subprocess.run([
                    rar_exe, "a", "-ep", rar_path, tmp_file_path
                ], capture_output=True, text=True)

            if result.returncode != 0:
                print(f"RAR creation failed: {result.stderr}")
                raise RuntimeError(f"RAR creation failed: {result.stderr}")

            with open(rar_path, "rb") as rar_file:
                rar_bytes = rar_file.read()

            os.remove(rar_path)
            print(f"Successfully created RAR archive ({len(rar_bytes)} bytes)")
            return rar_bytes

        except Exception as e:
            print(f"Unexpected error creating RAR: {e}")
            raise
        finally:
            if os.path.exists(tmp_file_path):
                os.remove(tmp_file_path)

    def _create_rar_multi(self, file_data_list: List[Tuple[str, bytes]], encrypt: bool = True) -> bytes:
        """Create RAR file with multiple files using CLI."""
        rar_exe = shutil.which("rar")
        if rar_exe is None:
            print("RAR not available, falling back to ZIP")
            return self._create_zip_multi(file_data_list, encrypt)

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create all individual files
            file_paths = []
            for filename, file_data in file_data_list:
                file_path = os.path.join(temp_dir, filename)
                with open(file_path, 'wb') as f:
                    f.write(file_data if isinstance(file_data, bytes) else file_data.encode())
                file_paths.append(file_path)

            # Create RAR archive with all files
            rar_path = os.path.join(temp_dir, "multi_file_archive.rar")

            try:
                if encrypt and self.password:
                    cmd = ["rar", "a", f"-p{self.password}", "-ep"] + [rar_path] + file_paths
                    print(f"Creating password-protected RAR with {len(file_paths)} files")
                else:
                    cmd = ["rar", "a", "-ep", rar_path] + file_paths
                    print(f"Creating unencrypted RAR with {len(file_paths)} files")

                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                print(f"RAR creation successful: {result.stdout}")

                with open(rar_path, 'rb') as f:
                    rar_data = f.read()

                print(f"Created multi-file RAR ({len(rar_data)} bytes)")
                return rar_data

            except subprocess.CalledProcessError as e:
                print(f"Multi-file RAR creation failed: {e.stderr}")
                raise RuntimeError(f"Failed to create multi-file RAR: {e.stderr}")

    @staticmethod
    def _create_ace(data: str) -> bytes:
        """Create fake ACE file with single file (existing logic)."""
        print("Creating fake ACE file (ACE format not fully supported)")

        ace_file = tempfile.NamedTemporaryFile(delete=False, suffix=".ace")
        try:
            fake_ace_header = b"**ACE**"
            ace_file.write(fake_ace_header + data.encode('utf-8'))
            ace_file.close()

            with open(ace_file.name, "rb") as f:
                ace_bytes = f.read()

            print(f"Successfully created fake ACE file ({len(ace_bytes)} bytes)")
            return ace_bytes
        finally:
            if os.path.exists(ace_file.name):
                os.unlink(ace_file.name)

    @staticmethod
    def _create_ace_multi(file_data_list: List[Tuple[str, bytes]]) -> bytes:
        """Create fake ACE file with multiple files (simplified implementation)."""
        print(f"Creating fake ACE file with {len(file_data_list)} files (ACE format not fully supported)")

        ace_file = tempfile.NamedTemporaryFile(delete=False, suffix=".ace")
        try:
            fake_ace_header = b"**ACE**"
            ace_file.write(fake_ace_header)

            # Write all files with simple delimiter
            for filename, file_data in file_data_list:
                file_header = f"FILE:{filename}\n".encode('utf-8')
                ace_file.write(file_header)
                ace_file.write(file_data if isinstance(file_data, bytes) else file_data.encode())
                ace_file.write(b"\n---FILEEND---\n")

            ace_file.close()

            with open(ace_file.name, "rb") as f:
                ace_bytes = f.read()

            print(f"Successfully created fake multi-file ACE file ({len(ace_bytes)} bytes)")
            return ace_bytes
        finally:
            if os.path.exists(ace_file.name):
                os.unlink(ace_file.name)
