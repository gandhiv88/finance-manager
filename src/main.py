#!/usr/bin/env python3
"""
Personal Finance Manager - Main Entry Point

A secure, local-first personal finance application that processes financial
statements and provides analytics without ever sending data to external services.

Security Design:
- All processing happens locally
- No network access allowed
- Encrypted local database storage
- Secure file handling with cleanup
"""

import sys
import os
import logging
from pathlib import Path
from typing import Optional

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt
from security.network_blocker import NetworkBlocker
from security.file_handler import SecureFileHandler
from gui.main_window import MainWindow
from database.db_manager import DatabaseManager


def setup_logging() -> None:
    """
    Configure secure logging that doesn't expose sensitive information.

    Security: Logs are kept local and don't include financial data.
    """
    log_dir = Path.home() / ".personalfinance" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "application.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    # Ensure no sensitive data is logged
    logging.getLogger().addFilter(
        lambda record: not any(
            sensitive in str(record.msg).lower()
            for sensitive in ["password", "key", "token", "account"]
        )
    )


def check_dependencies() -> bool:
    """
    Verify all required dependencies are available.

    Returns:
        bool: True if all dependencies are available, False otherwise
    """
    required_modules = [
        "pandas",
        "pdfplumber",
        "pytesseract",
        "sklearn",
        # "sqlcipher3",  # Optional - using sqlite3 with cryptography instead
        "PyQt5",
        "matplotlib",
        "cryptography",
    ]

    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)

    if missing_modules:
        logging.error(f"Missing required modules: {', '.join(missing_modules)}")
        return False

    return True


def initialize_security() -> bool:
    """
    Initialize security components and verify secure environment.

    Security: Blocks network access and sets up secure file handling.

    Returns:
        bool: True if security initialization successful, False otherwise
    """
    try:
        # Block all network access
        network_blocker = NetworkBlocker()
        network_blocker.block_network_access()
        logging.info("Network access blocked successfully")

        # Initialize secure file handler
        secure_handler = SecureFileHandler()
        secure_handler.setup_secure_temp_directory()
        logging.info("Secure file handling initialized")

        return True
    except Exception as e:
        logging.error(f"Security initialization failed: {e}")
        return False


def main() -> int:
    """
    Main application entry point.

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    # Set up logging first
    setup_logging()
    logging.info("Starting Personal Finance Manager")

    # Check dependencies
    if not check_dependencies():
        print(
            "ERROR: Missing required dependencies. Please run: pip install -r requirements.txt"
        )
        return 1

    # Initialize security
    if not initialize_security():
        print("ERROR: Failed to initialize security components")
        return 1

    # Create QApplication
    app = QApplication(sys.argv)
    app.setApplicationName("Personal Finance Manager")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("SecureFinance")

    # Set application properties for security
    app.setAttribute(Qt.AA_DisableWindowContextHelpButton)

    try:
        # Initialize database manager
        db_manager = DatabaseManager()

        # Create and show main window
        main_window = MainWindow(db_manager)
        main_window.show()

        logging.info("Application started successfully")

        # Run application
        exit_code = app.exec_()

        logging.info(f"Application exited with code: {exit_code}")
        return exit_code

    except Exception as e:
        logging.error(f"Application failed to start: {e}")

        # Show error dialog if possible
        try:
            error_dialog = QMessageBox()
            error_dialog.setIcon(QMessageBox.Critical)
            error_dialog.setWindowTitle("Application Error")
            error_dialog.setText(f"Failed to start application: {str(e)}")
            error_dialog.exec_()
        except:
            print(f"Failed to start application: {e}")

        return 1


if __name__ == "__main__":
    sys.exit(main())
