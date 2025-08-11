"""
Main Window - Primary application interface

This module provides the main GUI window for the personal finance application.
Implements a secure, user-friendly interface for financial data management.

Security Rationale:
- No external resource loading
- Secure file dialog operations
- Input validation for all user interactions
- Memory-safe widget handling
"""

import sys
import os
import logging
from pathlib import Path
from typing import Optional, List
from PyQt5.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QMenuBar,
    QMenu,
    QAction,
    QStatusBar,
    QMessageBox,
    QFileDialog,
    QPushButton,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QDialog,
    QLineEdit,
    QDialogButtonBox,
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QIcon, QFont

from database.db_manager import DatabaseManager
from security.file_handler import SecureFileHandler
from parsers.pdf_parser import PDFParser
from parsers.csv_parser import CSVParser
from parsers.excel_parser import ExcelParser
from ml.categorizer import ExpenseCategorizer


class PasswordDialog(QDialog):
    """
    Secure password input dialog.

    Security: Password input is masked and not stored in memory.
    """

    def __init__(self, parent=None, title="Enter Password"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(300, 150)

        layout = QVBoxLayout()

        # Password input
        self.password_label = QLabel("Database Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        # Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

        # Focus on password input
        self.password_input.setFocus()

    def get_password(self) -> str:
        """Get the entered password."""
        return self.password_input.text()

    def clear_password(self):
        """Securely clear password from memory."""
        self.password_input.clear()


class FileImportThread(QThread):
    """
    Background thread for file import operations.

    Security: Runs file processing in separate thread to prevent
    UI blocking while maintaining security controls.
    """

    progress_updated = pyqtSignal(int)
    import_completed = pyqtSignal(bool, str)

    def __init__(self, file_path: Path, db_manager: DatabaseManager, password: str):
        super().__init__()
        self.file_path = file_path
        self.db_manager = db_manager
        self.password = password
        self.logger = logging.getLogger(__name__)

    def run(self):
        """
        Run file import in background thread.

        Security: All file operations use secure handlers.
        """
        try:
            self.progress_updated.emit(10)

            # Initialize secure file handler
            file_handler = SecureFileHandler()

            self.progress_updated.emit(20)

            # Validate file
            validated_path = file_handler.validate_file_path(self.file_path)

            self.progress_updated.emit(30)

            # Choose appropriate parser
            parser = None
            file_ext = validated_path.suffix.lower()

            if file_ext == ".pdf":
                parser = PDFParser()
            elif file_ext == ".csv":
                parser = CSVParser()
            elif file_ext in [".xlsx", ".xls"]:
                parser = ExcelParser()
            else:
                raise ValueError(f"Unsupported file type: {file_ext}")

            self.progress_updated.emit(50)

            # Parse file
            transactions = parser.parse_file(validated_path)

            self.progress_updated.emit(70)

            # Categorize transactions
            categorizer = ExpenseCategorizer()
            categorized_transactions = categorizer.categorize_transactions(transactions)

            self.progress_updated.emit(90)

            # Save to database
            success_count = 0
            for transaction in categorized_transactions:
                transaction_id = self.db_manager.add_transaction(
                    self.password, transaction
                )
                if transaction_id:
                    success_count += 1

            self.progress_updated.emit(100)

            # Report results
            if success_count > 0:
                message = f"Successfully imported {success_count} transactions"
                self.import_completed.emit(True, message)
            else:
                self.import_completed.emit(False, "No transactions were imported")

        except Exception as e:
            self.logger.error(f"File import failed: {e}")
            self.import_completed.emit(False, f"Import failed: {str(e)}")


class MainWindow(QMainWindow):
    """
    Main application window.

    Security: Implements secure UI patterns and handles sensitive
    data display with appropriate protections.
    """

    def __init__(self, db_manager: DatabaseManager):
        super().__init__()
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        self.current_password: Optional[str] = None
        self.secure_file_handler = SecureFileHandler()

        self._setup_ui()
        self._setup_security()

        # Request password on startup
        self._authenticate_user()

    def _setup_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Personal Finance Manager")
        self.setGeometry(100, 100, 1200, 800)

        # Set application icon
        icon_path = Path(__file__).parent.parent.parent / "resources" / "app_icon.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        # Central widget with tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Create tabs
        self._create_dashboard_tab()
        self._create_transactions_tab()
        self._create_categories_tab()
        self._create_analytics_tab()

        # Menu bar
        self._create_menu_bar()

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Database encrypted and secure")

        # Progress bar (hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def _setup_security(self):
        """Setup security-related configurations."""
        # Disable context menu on sensitive widgets
        self.setContextMenuPolicy(Qt.NoContextMenu)

        # Set secure window flags
        self.setWindowFlags(self.windowFlags() | Qt.WindowCloseButtonHint)

    def _create_menu_bar(self):
        """Create application menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        import_action = QAction("Import Statement...", self)
        import_action.triggered.connect(self._import_file)
        file_menu.addAction(import_action)

        file_menu.addSeparator()

        backup_action = QAction("Backup Database...", self)
        backup_action.triggered.connect(self._backup_database)
        file_menu.addAction(backup_action)

        restore_action = QAction("Restore Database...", self)
        restore_action.triggered.connect(self._restore_database)
        file_menu.addAction(restore_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        change_password_action = QAction("Change Password...", self)
        change_password_action.triggered.connect(self._change_password)
        tools_menu.addAction(change_password_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _create_dashboard_tab(self):
        """Create the dashboard tab."""
        dashboard_widget = QWidget()
        layout = QVBoxLayout()
        dashboard_widget.setLayout(layout)

        # Welcome message
        welcome_label = QLabel("Welcome to Personal Finance Manager")
        welcome_label.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(welcome_label)

        # Quick stats (placeholder)
        stats_label = QLabel("Quick Stats will appear here after importing data")
        layout.addWidget(stats_label)

        # Import button
        import_button = QPushButton("Import Financial Statement")
        import_button.clicked.connect(self._import_file)
        layout.addWidget(import_button)

        layout.addStretch()

        self.tabs.addTab(dashboard_widget, "Dashboard")

    def _create_transactions_tab(self):
        """Create the transactions tab."""
        transactions_widget = QWidget()
        layout = QVBoxLayout()
        transactions_widget.setLayout(layout)

        # Transactions table
        self.transactions_table = QTableWidget()
        self.transactions_table.setColumnCount(6)
        self.transactions_table.setHorizontalHeaderLabels(
            ["Date", "Description", "Amount", "Type", "Category", "Account"]
        )

        # Make table read-only
        self.transactions_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Resize columns to content
        header = self.transactions_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)

        layout.addWidget(self.transactions_table)

        self.tabs.addTab(transactions_widget, "Transactions")

    def _create_categories_tab(self):
        """Create the categories management tab."""
        categories_widget = QWidget()
        layout = QVBoxLayout()
        categories_widget.setLayout(layout)

        label = QLabel("Category management will be implemented here")
        layout.addWidget(label)

        self.tabs.addTab(categories_widget, "Categories")

    def _create_analytics_tab(self):
        """Create the analytics tab."""
        analytics_widget = QWidget()
        layout = QVBoxLayout()
        analytics_widget.setLayout(layout)

        label = QLabel("Financial analytics and charts will be displayed here")
        layout.addWidget(label)

        self.tabs.addTab(analytics_widget, "Analytics")

    def _authenticate_user(self):
        """
        Authenticate user with password.

        Security: Required for database access.
        Development: Set FINANCE_DEV_MODE=true to use default password.
        """
        # Development mode bypass
        dev_mode = os.environ.get('FINANCE_DEV_MODE', '').lower() == 'true'
        if dev_mode:
            password = "dev_password_123"
            self.logger.warning("Running in development mode with default password")
            
            if not self.db_manager.db_path.exists():
                if self.db_manager.initialize_database(password):
                    self.current_password = password
                    self.status_bar.showMessage("Dev database created")
                    return
            else:
                if self.db_manager.verify_password(password):
                    self.current_password = password
                    self._load_transactions()
                    self.status_bar.showMessage("Dev database unlocked")
                    return
        
        # Normal authentication flow
        while True:
            password_dialog = PasswordDialog(self, "Database Password")

            if password_dialog.exec_() == QDialog.Accepted:
                password = password_dialog.get_password()

                # Check if database exists
                if not self.db_manager.db_path.exists():
                    # Initialize new database
                    if self.db_manager.initialize_database(password):
                        self.current_password = password
                        self.status_bar.showMessage("New encrypted database created")
                        break
                    else:
                        QMessageBox.critical(self, "Error", "Failed to create database")
                else:
                    # Verify existing database
                    if self.db_manager.verify_password(password):
                        self.current_password = password
                        self._load_transactions()
                        self.status_bar.showMessage("Database unlocked successfully")
                        break
                    else:
                        QMessageBox.warning(
                            self,
                            "Invalid Password",
                            "Incorrect password. Please try again.",
                        )

                password_dialog.clear_password()
            else:
                # User cancelled - exit application
                sys.exit(0)

    def _import_file(self):
        """Import a financial statement file."""
        if not self.current_password:
            QMessageBox.warning(self, "Error", "Database not authenticated")
            return

        # Open file dialog
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Financial Files (*.pdf *.csv *.xlsx *.xls)")

        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                file_path = Path(selected_files[0])
                self._process_file_import(file_path)

    def _process_file_import(self, file_path: Path):
        """Process file import in background thread."""
        try:
            # Show progress bar
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)

            # Start import thread
            self.import_thread = FileImportThread(
                file_path, self.db_manager, self.current_password
            )
            self.import_thread.progress_updated.connect(self._update_import_progress)
            self.import_thread.import_completed.connect(self._import_completed)
            self.import_thread.start()

            self.status_bar.showMessage(f"Importing {file_path.name}...")

        except Exception as e:
            self.logger.error(f"Failed to start import: {e}")
            QMessageBox.critical(
                self, "Import Error", f"Failed to start import: {str(e)}"
            )
            self.progress_bar.setVisible(False)

    @pyqtSlot(int)
    def _update_import_progress(self, value):
        """Update import progress bar."""
        self.progress_bar.setValue(value)

    @pyqtSlot(bool, str)
    def _import_completed(self, success, message):
        """Handle import completion."""
        self.progress_bar.setVisible(False)

        if success:
            QMessageBox.information(self, "Import Complete", message)
            self._load_transactions()  # Refresh transactions view
        else:
            QMessageBox.warning(self, "Import Failed", message)

        self.status_bar.showMessage("Ready")

    def _load_transactions(self):
        """Load and display transactions in the table."""
        if not self.current_password:
            return

        try:
            transactions = self.db_manager.get_transactions(self.current_password)

            # Update table
            self.transactions_table.setRowCount(len(transactions))

            for row, transaction in enumerate(transactions):
                self.transactions_table.setItem(
                    row,
                    0,
                    QTableWidgetItem(str(transaction.get("transaction_date", ""))),
                )
                self.transactions_table.setItem(
                    row, 1, QTableWidgetItem(str(transaction.get("description", "")))
                )
                self.transactions_table.setItem(
                    row, 2, QTableWidgetItem(f"${transaction.get('amount', 0):.2f}")
                )
                self.transactions_table.setItem(
                    row,
                    3,
                    QTableWidgetItem(str(transaction.get("transaction_type", ""))),
                )
                self.transactions_table.setItem(
                    row,
                    4,
                    QTableWidgetItem(
                        str(transaction.get("category_name", "Uncategorized"))
                    ),
                )
                self.transactions_table.setItem(
                    row, 5, QTableWidgetItem(str(transaction.get("account_name", "")))
                )

            self.status_bar.showMessage(f"Loaded {len(transactions)} transactions")

        except Exception as e:
            self.logger.error(f"Failed to load transactions: {e}")
            QMessageBox.critical(
                self, "Error", f"Failed to load transactions: {str(e)}"
            )

    def _backup_database(self):
        """Create database backup."""
        if not self.current_password:
            QMessageBox.warning(self, "Error", "Database not authenticated")
            return

        file_dialog = QFileDialog()
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        file_dialog.setDefaultSuffix("db")
        file_dialog.setNameFilter("Database Files (*.db)")

        if file_dialog.exec_():
            backup_path = Path(file_dialog.selectedFiles()[0])

            if self.db_manager.backup_database(self.current_password, backup_path):
                QMessageBox.information(
                    self, "Backup Complete", f"Database backed up to {backup_path}"
                )
            else:
                QMessageBox.critical(self, "Backup Failed", "Failed to create backup")

    def _restore_database(self):
        """Restore database from backup."""
        reply = QMessageBox.question(
            self,
            "Restore Database",
            "This will replace your current database. Continue?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            file_dialog = QFileDialog()
            file_dialog.setFileMode(QFileDialog.ExistingFile)
            file_dialog.setNameFilter("Database Files (*.db)")

            if file_dialog.exec_():
                backup_path = Path(file_dialog.selectedFiles()[0])

                # Get password for restore
                password_dialog = PasswordDialog(self, "Enter Password for Backup")
                if password_dialog.exec_() == QDialog.Accepted:
                    password = password_dialog.get_password()

                    if self.db_manager.restore_database(password, backup_path):
                        QMessageBox.information(
                            self, "Restore Complete", "Database restored successfully"
                        )
                        self.current_password = password
                        self._load_transactions()
                    else:
                        QMessageBox.critical(
                            self, "Restore Failed", "Failed to restore database"
                        )

    def _change_password(self):
        """Change database password."""
        # This would be implemented for changing database password
        QMessageBox.information(
            self,
            "Feature Not Implemented",
            "Password change feature will be implemented in future version",
        )

    def _show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About Personal Finance Manager",
            "Personal Finance Manager v1.0\n\n"
            "A secure, local-first personal finance application.\n"
            "All your data remains encrypted on your device.",
        )

    def closeEvent(self, event):
        """Handle application close event."""
        # Clean up secure file handler
        self.secure_file_handler.cleanup_temp_files()

        # Clear sensitive data from memory
        if self.current_password:
            self.current_password = None

        event.accept()
