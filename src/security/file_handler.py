"""
Secure File Handler - Manages file operations with security controls

This module provides secure file handling capabilities including:
- Temporary file management with automatic cleanup
- Path traversal protection
- Secure file deletion
- Input validation for file operations

Security Rationale:
- Prevents path traversal attacks
- Ensures temporary files are securely deleted
- Validates file types and sizes
- Implements secure memory handling for file data
"""

import os
import tempfile
import logging
import shutil
from pathlib import Path
from typing import Optional, List, Union, BinaryIO, TextIO
from contextlib import contextmanager
import hashlib
import mimetypes


class SecureFileHandler:
    """
    Handles file operations with security controls.

    Security: Prevents path traversal, manages temp files securely,
    validates input files, and ensures secure cleanup.
    """

    # Allowed file extensions for processing
    ALLOWED_EXTENSIONS = {".pdf", ".csv", ".xlsx", ".xls", ".txt"}

    # Maximum file size (50MB)
    MAX_FILE_SIZE = 50 * 1024 * 1024

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._temp_dir: Optional[Path] = None
        self._temp_files: List[Path] = []

    def setup_secure_temp_directory(self) -> None:
        """
        Create a secure temporary directory for file operations.

        Security: Creates temp directory with restricted permissions.
        """
        try:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="pf_secure_"))
            # Set restrictive permissions (owner only)
            os.chmod(self._temp_dir, 0o700)
            self.logger.info(f"Secure temp directory created: {self._temp_dir}")
        except Exception as e:
            self.logger.error(f"Failed to create secure temp directory: {e}")
            raise

    def validate_file_path(self, file_path: Union[str, Path]) -> Path:
        """
        Validate and normalize a file path for security.

        Args:
            file_path: The file path to validate

        Returns:
            Path: Validated and normalized path

        Raises:
            ValueError: If path is invalid or suspicious

        Security: Prevents path traversal and validates file existence.
        """
        path = Path(file_path).resolve()

        # Check if file exists
        if not path.exists():
            raise ValueError(f"File does not exist: {file_path}")

        # Check if it's actually a file
        if not path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        # Check file extension
        if path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            raise ValueError(f"File type not allowed: {path.suffix}")

        # Check file size
        if path.stat().st_size > self.MAX_FILE_SIZE:
            raise ValueError(f"File too large: {path.stat().st_size} bytes")

        # Prevent access to system directories
        system_dirs = ["/etc", "/sys", "/proc", "C:\\Windows", "C:\\System32"]
        for sys_dir in system_dirs:
            try:
                if path.is_relative_to(sys_dir):
                    raise ValueError(
                        f"Access to system directory not allowed: {sys_dir}"
                    )
            except (AttributeError, ValueError):
                # is_relative_to not available in older Python versions
                if str(path).startswith(sys_dir):
                    raise ValueError(
                        f"Access to system directory not allowed: {sys_dir}"
                    )

        return path

    @contextmanager
    def secure_temp_file(self, suffix: str = "", prefix: str = "pf_"):
        """
        Create a secure temporary file with automatic cleanup.

        Args:
            suffix: File suffix/extension
            prefix: File prefix

        Yields:
            Path: Path to temporary file

        Security: Creates temp file with restricted permissions and
        ensures automatic cleanup even if exceptions occur.
        """
        if not self._temp_dir:
            raise RuntimeError("Temp directory not initialized")

        temp_file = None
        try:
            # Create temporary file
            fd, temp_path = tempfile.mkstemp(
                suffix=suffix, prefix=prefix, dir=self._temp_dir
            )
            temp_file = Path(temp_path)

            # Set restrictive permissions
            os.chmod(temp_file, 0o600)
            os.close(fd)  # Close file descriptor

            self._temp_files.append(temp_file)
            self.logger.debug(f"Created temp file: {temp_file}")

            yield temp_file

        finally:
            # Secure cleanup
            if temp_file and temp_file.exists():
                self._secure_delete_file(temp_file)
                if temp_file in self._temp_files:
                    self._temp_files.remove(temp_file)

    def _secure_delete_file(self, file_path: Path) -> None:
        """
        Securely delete a file by overwriting it before removal.

        Args:
            file_path: Path to file to delete

        Security: Overwrites file content before deletion to prevent
        data recovery from unallocated disk space.
        """
        try:
            if not file_path.exists():
                return

            file_size = file_path.stat().st_size

            # Overwrite file with random data
            with open(file_path, "r+b") as f:
                for _ in range(3):  # Multiple passes
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())

            # Remove file
            file_path.unlink()
            self.logger.debug(f"Securely deleted file: {file_path}")

        except Exception as e:
            self.logger.error(f"Failed to securely delete file {file_path}: {e}")

    def calculate_file_hash(self, file_path: Path) -> str:
        """
        Calculate SHA-256 hash of a file for integrity verification.

        Args:
            file_path: Path to file

        Returns:
            str: SHA-256 hash in hexadecimal

        Security: Provides file integrity verification.
        """
        hash_sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)

            return hash_sha256.hexdigest()

        except Exception as e:
            self.logger.error(f"Failed to calculate hash for {file_path}: {e}")
            raise

    def get_file_mime_type(self, file_path: Path) -> Optional[str]:
        """
        Get the MIME type of a file.

        Args:
            file_path: Path to file

        Returns:
            Optional[str]: MIME type or None if unable to determine
        """
        try:
            mime_type, _ = mimetypes.guess_type(str(file_path))
            return mime_type
        except Exception as e:
            self.logger.error(f"Failed to get MIME type for {file_path}: {e}")
            return None

    def cleanup_temp_files(self) -> None:
        """
        Clean up all temporary files and directory.

        Security: Ensures all temporary files are securely deleted
        when the application shuts down.
        """
        try:
            # Delete all tracked temp files
            for temp_file in self._temp_files[:]:
                if temp_file.exists():
                    self._secure_delete_file(temp_file)
                self._temp_files.remove(temp_file)

            # Remove temp directory
            if self._temp_dir and self._temp_dir.exists():
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                self.logger.info("Temp directory cleaned up")

        except Exception as e:
            self.logger.error(f"Error during temp file cleanup: {e}")

    def __del__(self):
        """Destructor to ensure cleanup on object deletion."""
        self.cleanup_temp_files()
