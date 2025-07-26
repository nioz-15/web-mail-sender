
import random
from typing import Optional, Union
from file_generators.data_factories import CleanFactory, MalwareFactory, PhishingFactory, DataLeakFactory, UnicodeFactory
from file_generators.file_types import PDFFile, WordFile, ExcelFile, TextFile, CSVFile, JSONFile, XMLFile, ArchiveFile
from file_generators.constants import DEFAULT_PASSWORD, FILE_TYPE_EXTENSIONS, LOCATION_MAPPINGS, DEFAULT_LOCATIONS, \
    ENCRYPTION_SUPPORT


class AttachmentDataGenerator:
    """Enhanced generator supporting both single files and multi-file archives."""

    def __init__(self, password: str = DEFAULT_PASSWORD):
        self.password = password
        self._file_generators = {
            'word': WordFile,
            'excel': ExcelFile,
            'pdf': PDFFile,
            'csv': CSVFile,
            'json': JSONFile,
            'txt': TextFile,
            'xml': XMLFile,
            'zip': lambda: ArchiveFile('zip', self.password),
            'rar': lambda: ArchiveFile('rar', self.password),
            'ace': lambda: ArchiveFile('ace', self.password)
        }

    def generate_content(self, tag: str, verdict: str) -> str:
        """
        Generate content based on tag and verdict.
        CRITICAL: For EICAR malware, preserve exact content without modification.

        Args:
            tag: Content type tag ('clean', 'malware', 'dlp', 'phishing')
            verdict: Specific content verdict within the tag

        Returns:
            Generated content string
        """
        if 'clean' in tag:
            return random.choice(CleanFactory().get_data())

        elif 'malware' in tag:
            malware_data = MalwareFactory().get_data()
            content = random.choice(malware_data[verdict])

            if verdict == "eicar":
                print(f"Generating EICAR content - preserving exact signature: {content[:20]}...")

            return content

        elif 'dlp' in tag:
            if 's3' in verdict:
                verdict = verdict.replace('s3;', '')
                data = DataLeakFactory.load_s3_data()
            else:
                data = DataLeakFactory().get_data()
            verdict_data = [random.choice(data[single_verdict]) for single_verdict in verdict.split(",")]
            return "\n".join(verdict_data)

        elif 'phishing' in tag:
            phishing_data = PhishingFactory().get_data()
            return random.choice(phishing_data[verdict])

        elif "unicode" in tag:
            unicode_data = UnicodeFactory().get_data()
            return random.choice(unicode_data[verdict])

        return ""

    def generate_attachment(self, tag: str, verdict: str, file_type: str,
                            file_location: Optional[str] = None,
                            encrypt: bool = False,
                            compression: Optional[str] = None) -> bytes:
        """
        Generate attachment file with specified content, format, and compression.
        CRITICAL: Preserves malware signatures (especially EICAR) without modification.

        Args:
            tag: Content type tag (malware, dlp, clean, phishing)
            verdict: Content verdict
            file_type: Type of file to generate
            file_location: Location parameter for file content placement
            encrypt: Whether to encrypt the file
            compression: Compression type ('zip', 'rar', or None for no compression)

        Returns:
            File bytes (compressed if compression is specified)
        """
        try:
            # Determine if content should be preserved (critical for malware)
            preserve_content = (tag == "malware")

            if preserve_content:
                print(f"Generating {tag}/{verdict} attachment with PRESERVED content")
            else:
                print(f"Generating {tag}/{verdict} attachment with standard content")

            data = self.generate_content(tag, verdict)

            file_bytes = self._file_generator(
                data=data,
                file_type=file_type,
                file_location=file_location,
                encrypt=encrypt,
                content_tag=tag,
                compression=compression,
                preserve_content=preserve_content
            )

            return file_bytes
        except Exception as e:
            print(f"Error generating attachment: {e}")
            raise

    def create_multi_file_archive(self, file_data_list: list, compression_type: str = "zip",
                                  encrypt: bool = True) -> bytes:
        """
        Create archive containing multiple files using existing ArchiveFile class.

        Args:
            file_data_list: List of tuples [(filename, file_bytes), ...]
            compression_type: Archive format ('zip', 'rar', or 'ace')
            encrypt: Whether to password-protect the archive

        Returns:
            Archive bytes containing all files
        """
        print(f"Creating multi-file {compression_type} archive with {len(file_data_list)} files")

        archive_generator = ArchiveFile(compression_type, self.password)
        return archive_generator.generate(file_data_list, encrypt=encrypt)

    def _file_generator(self, data: str, file_type: str,
                        file_location: Optional[str], encrypt: bool,
                        content_tag: str = None, compression: Optional[str] = None,
                        preserve_content: bool = False) -> bytes:
        """Generate file using appropriate file generator with preserved content support."""
        try:
            file_type = file_type.lower()

            if preserve_content:
                print(f"Generating {file_type} with PRESERVED content (malware signature)")
            else:
                print(f"Generating {file_type} with standard content processing")

            # Handle archive files using ArchiveFile
            if file_type in ['zip', 'rar', 'ace']:
                print(f"Creating {file_type} archive with encrypt={encrypt}")
                generator = ArchiveFile(file_type, self.password)
                return generator.generate(data, encrypt=encrypt)

            # Handle compression request for non-archive files
            if compression:
                print(f"Creating {file_type} file then compressing with {compression}")
                file_bytes = self._generate_regular_file(data, file_type, file_location, False, preserve_content)

                archive_generator = ArchiveFile(compression, self.password)
                extension = FILE_TYPE_EXTENSIONS.get(file_type.lower(), 'txt')
                filename = f"content.{extension}"
                return archive_generator.generate([(filename, file_bytes)], encrypt=encrypt)

            # Handle encryption for non-archive files
            if encrypt and not ENCRYPTION_SUPPORT.get(file_type, False):
                print(f"{file_type} doesn't support native encryption - will compress with password")
                file_bytes = self._generate_regular_file(data, file_type, file_location, False, preserve_content)

                archive_generator = ArchiveFile("zip", self.password)
                extension = FILE_TYPE_EXTENSIONS.get(file_type.lower(), 'txt')
                filename = f"content.{extension}"
                return archive_generator.generate([(filename, file_bytes)], encrypt=True)

            # Generate regular file (with or without native encryption)
            return self._generate_regular_file(data, file_type, file_location, encrypt, preserve_content)

        except Exception as e:
            raise AssertionError(f"Error in _file_generator for {file_type}: {e}")

    def _generate_regular_file(self, data: str, file_type: str, file_location: Optional[str],
                               encrypt: bool, preserve_content: bool) -> bytes:
        """Generate a regular (non-archive) file with content preservation support."""

        # File type mapping for non-archive files
        file_generator_mapping = {
            'word': WordFile,
            'excel': ExcelFile,
            'pdf': PDFFile,
            'csv': CSVFile,
            'json': JSONFile,
            'txt': TextFile,
            'xml': XMLFile
        }

        if file_type not in file_generator_mapping:
            print(f"File type '{file_type}' not implemented. Creating as text file.")
            generator = TextFile(password=self.password)
            return generator.generate(data, preserve_content=preserve_content)

        # Get the generator class
        generator_class = file_generator_mapping[file_type]
        generator = generator_class(password=self.password)

        # Prepare generation parameters
        kwargs = {
            'encrypt': encrypt,
            'preserve_content': preserve_content  # CRITICAL: Pass preserve_content to all generators
        }

        # Add file-type specific parameters with location handling
        if file_type == 'json':
            kwargs['message'] = file_location or DEFAULT_LOCATIONS['json']

        elif file_type == 'txt':
            if file_location:
                try:
                    kwargs['line_number'] = int(file_location)
                except (ValueError, TypeError):
                    # Map text locations to line numbers using constants
                    kwargs['line_number'] = LOCATION_MAPPINGS['txt'].get(
                        file_location.lower(),
                        DEFAULT_LOCATIONS['txt']
                    )
            else:
                kwargs['line_number'] = DEFAULT_LOCATIONS['txt']

        elif file_type in ['csv', 'xml', 'excel']:
            # Use location mappings from constants
            if file_location:
                mapping = LOCATION_MAPPINGS.get(file_type, {})
                kwargs['location'] = mapping.get(
                    file_location.lower(),
                    file_location  # Use original if no mapping found
                )
            else:
                kwargs['location'] = DEFAULT_LOCATIONS.get(file_type)

        elif file_type in ['word', 'pdf']:
            if file_location:
                mapping = LOCATION_MAPPINGS.get(file_type, {})
                kwargs['location'] = mapping.get(
                    file_location.lower(),
                    file_location  # Use original if no mapping found
                )
            else:
                kwargs['location'] = DEFAULT_LOCATIONS.get(file_type)

        # Generate the file
        if preserve_content:
            print(f"Generating {file_type} file with preserve_content=True")

        return generator.generate(data, **kwargs)
