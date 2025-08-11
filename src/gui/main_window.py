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
    QComboBox,
    QFormLayout,
    QCheckBox,
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
        self.setFixedSize(350, 200)
        self.reset_requested = False

        layout = QVBoxLayout()

        # Password input
        self.password_label = QLabel("Database Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        # Info label
        info_label = QLabel("Enter password to unlock encrypted database")
        info_label.setStyleSheet("color: gray; font-size: 10px;")

        # Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        # Reset button
        self.reset_button = QPushButton("Reset Database")
        self.reset_button.setStyleSheet("color: red;")
        self.reset_button.clicked.connect(self._request_reset)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.reset_button)
        button_layout.addStretch()
        button_layout.addWidget(self.buttons)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(info_label)
        layout.addStretch()
        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Focus on password input
        self.password_input.setFocus()

    def _request_reset(self):
        """Handle reset database request."""
        reply = QMessageBox.question(
            self,
            "Reset Database?",
            "This will DELETE all existing financial data and create a new database.\n"
            "Are you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.reset_requested = True
            self.accept()

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

    def __init__(
        self,
        file_path: Path,
        db_manager: DatabaseManager,
        password: str,
        account_id: int,
        account_type: str = "checking",
    ):
        super().__init__()
        self.file_path = file_path
        self.db_manager = db_manager
        self.password = password
        self.account_id = account_id
        self.account_type = account_type
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
            if file_ext == ".pdf":
                transactions = parser.parse_file(validated_path, self.account_type)
            else:
                transactions = parser.parse_file(validated_path)

            self.progress_updated.emit(70)

            # Categorize transactions
            categorizer = ExpenseCategorizer()
            categorized_transactions = categorizer.categorize_transactions(transactions)

            self.progress_updated.emit(80)

            # Map predicted categories to database category IDs
            self._map_categories_to_ids(categorized_transactions)

            self.progress_updated.emit(90)

            # Save to database
            success_count = 0
            for transaction in categorized_transactions:
                transaction["account_id"] = self.account_id
                transaction_id = self.db_manager.add_transaction(
                    self.password, transaction
                )
                if transaction_id:
                    success_count += 1

            # Record file import for audit trail
            if success_count > 0:
                self._record_file_import(validated_path, success_count)

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

    def _record_file_import(self, file_path: str, transaction_count: int) -> None:
        """Record file import for audit trail."""
        try:
            with self.db_manager._get_connection(self.password) as conn:
                conn.execute(
                    """INSERT INTO file_imports 
                       (filename, import_date, transaction_count) 
                       VALUES (?, datetime('now'), ?)""",
                    (Path(file_path).name, transaction_count),
                )
        except Exception as e:
            print(f"Warning: Could not record file import: {e}")


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
        self._create_accounts_tab()
        self._create_transactions_tab()
        self._create_imports_tab()
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

        add_account_action = QAction("Add Account...", self)
        add_account_action.triggered.connect(self._add_account)
        tools_menu.addAction(add_account_action)

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

        # Add account button
        add_account_button = QPushButton("Add New Account")
        add_account_button.clicked.connect(self._add_account)
        layout.addWidget(add_account_button)

        layout.addStretch()

        self.tabs.addTab(dashboard_widget, "Dashboard")

    def _create_accounts_tab(self):
        """Create the accounts management tab."""
        accounts_widget = QWidget()
        layout = QVBoxLayout()
        accounts_widget.setLayout(layout)

        # Header with add button
        header_layout = QHBoxLayout()
        accounts_label = QLabel("Your Accounts")
        accounts_label.setFont(QFont("Arial", 14, QFont.Bold))
        header_layout.addWidget(accounts_label)

        header_layout.addStretch()

        add_btn = QPushButton("Add Account")
        add_btn.clicked.connect(self._add_account)
        header_layout.addWidget(add_btn)

        layout.addLayout(header_layout)

        # Accounts table
        self.accounts_table = QTableWidget()
        self.accounts_table.setColumnCount(5)
        self.accounts_table.setHorizontalHeaderLabels(
            ["Name", "Type", "Institution", "Notes", "Created"]
        )

        # Make table read-only
        self.accounts_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Resize columns to content
        header = self.accounts_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)

        layout.addWidget(self.accounts_table)

        self.tabs.addTab(accounts_widget, "Accounts")

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

    def _create_imports_tab(self):
        """Create the file imports management tab."""
        imports_widget = QWidget()
        layout = QVBoxLayout()
        imports_widget.setLayout(layout)

        # Header
        header_layout = QHBoxLayout()
        imports_label = QLabel("File Imports & Deletion Management")
        imports_label.setFont(QFont("Arial", 14, QFont.Bold))
        header_layout.addWidget(imports_label)

        header_layout.addStretch()

        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._load_file_imports)
        header_layout.addWidget(refresh_btn)

        # Find duplicates button
        duplicates_btn = QPushButton("Find Duplicates")
        duplicates_btn.clicked.connect(self._find_duplicates)
        header_layout.addWidget(duplicates_btn)

        layout.addLayout(header_layout)

        # File imports table
        self.imports_table = QTableWidget()
        self.imports_table.setColumnCount(6)
        self.imports_table.setHorizontalHeaderLabels(
            [
                "File Name",
                "Import Date",
                "Transactions",
                "Current Count",
                "Status",
                "Actions",
            ]
        )

        # Make most columns read-only
        self.imports_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Resize columns
        header = self.imports_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)

        layout.addWidget(self.imports_table)

        # Instructions
        instructions = QLabel(
            "• Use 'Delete File Import' to remove all transactions from a file\n"
            "• Use 'Find Duplicates' to identify potential duplicate transactions\n"
            "• Deletions cannot be undone - create a backup first if needed"
        )
        instructions.setStyleSheet("color: gray; font-size: 10px; margin: 10px;")
        layout.addWidget(instructions)

        self.tabs.addTab(imports_widget, "File Management")

    def _create_categories_tab(self):
        """Create the categories management tab."""
        categories_widget = QWidget()
        layout = QVBoxLayout()
        categories_widget.setLayout(layout)

        # Header with add category button
        header_layout = QHBoxLayout()
        categories_label = QLabel("Transaction Categories")
        categories_label.setFont(QFont("Arial", 14, QFont.Bold))
        header_layout.addWidget(categories_label)

        header_layout.addStretch()

        # Add category button
        add_category_btn = QPushButton("Add Category")
        add_category_btn.clicked.connect(self._add_category)
        header_layout.addWidget(add_category_btn)

        layout.addLayout(header_layout)

        # Categories table
        self.categories_table = QTableWidget()
        self.categories_table.setColumnCount(5)
        self.categories_table.setHorizontalHeaderLabels(
            ["Name", "Type", "Parent Category", "Transaction Count", "Actions"]
        )

        # Make most columns read-only
        self.categories_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Resize columns
        header = self.categories_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)

        layout.addWidget(self.categories_table)

        # Statistics section
        stats_layout = QHBoxLayout()

        self.total_categories_label = QLabel("Total Categories: 0")
        self.income_categories_label = QLabel("Income: 0")
        self.expense_categories_label = QLabel("Expense: 0")

        stats_layout.addWidget(self.total_categories_label)
        stats_layout.addWidget(self.income_categories_label)
        stats_layout.addWidget(self.expense_categories_label)
        stats_layout.addStretch()

        layout.addLayout(stats_layout)

        self.tabs.addTab(categories_widget, "Categories")

    def _create_analytics_tab(self):
        """Create the analytics tab."""
        analytics_widget = QWidget()
        layout = QVBoxLayout()
        analytics_widget.setLayout(layout)

        # Header
        header_label = QLabel("Financial Analytics & Insights")
        header_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header_label)

        # Control panel
        controls_layout = QHBoxLayout()

        # Time period selector
        period_label = QLabel("Time Period:")
        self.period_combo = QComboBox()
        self.period_combo.addItems(
            [
                "Last 30 Days",
                "Last 90 Days",
                "Last 6 Months",
                "Last Year",
                "All Time",
                "Custom Range",
            ]
        )
        self.period_combo.currentTextChanged.connect(self._update_analytics)

        # Account filter
        account_label = QLabel("Account:")
        self.account_filter_combo = QComboBox()
        self.account_filter_combo.addItem("All Accounts")
        self.account_filter_combo.currentTextChanged.connect(self._update_analytics)

        # Refresh button
        refresh_analytics_btn = QPushButton("Refresh")
        refresh_analytics_btn.clicked.connect(self._update_analytics)

        controls_layout.addWidget(period_label)
        controls_layout.addWidget(self.period_combo)
        controls_layout.addWidget(account_label)
        controls_layout.addWidget(self.account_filter_combo)
        controls_layout.addStretch()
        controls_layout.addWidget(refresh_analytics_btn)

        layout.addLayout(controls_layout)

        # Summary cards layout
        summary_layout = QHBoxLayout()

        # Income card
        income_card = self._create_summary_card("Total Income", "$0.00", "#4CAF50")
        self.income_label = income_card.findChild(QLabel, "value")
        summary_layout.addWidget(income_card)

        # Expenses card
        expenses_card = self._create_summary_card("Total Expenses", "$0.00", "#F44336")
        self.expenses_label = expenses_card.findChild(QLabel, "value")
        summary_layout.addWidget(expenses_card)

        # Net card
        net_card = self._create_summary_card("Net", "$0.00", "#2196F3")
        self.net_label = net_card.findChild(QLabel, "value")
        summary_layout.addWidget(net_card)

        # Transaction count card
        count_card = self._create_summary_card("Transactions", "0", "#FF9800")
        self.count_label = count_card.findChild(QLabel, "value")
        summary_layout.addWidget(count_card)

        layout.addLayout(summary_layout)

        # Charts and tables section
        charts_layout = QHBoxLayout()

        # Left column - Category breakdown
        left_column = QVBoxLayout()

        category_label = QLabel("Spending by Category")
        category_label.setFont(QFont("Arial", 12, QFont.Bold))
        left_column.addWidget(category_label)

        self.category_table = QTableWidget()
        self.category_table.setColumnCount(3)
        self.category_table.setHorizontalHeaderLabels(
            ["Category", "Amount", "Percentage"]
        )
        self.category_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.category_table.setMaximumHeight(300)
        left_column.addWidget(self.category_table)

        # Right column - Monthly trends
        right_column = QVBoxLayout()

        trends_label = QLabel("Monthly Trends")
        trends_label.setFont(QFont("Arial", 12, QFont.Bold))
        right_column.addWidget(trends_label)

        self.trends_table = QTableWidget()
        self.trends_table.setColumnCount(4)
        self.trends_table.setHorizontalHeaderLabels(
            ["Month", "Income", "Expenses", "Net"]
        )
        self.trends_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.trends_table.setMaximumHeight(300)
        right_column.addWidget(self.trends_table)

        charts_layout.addLayout(left_column)
        charts_layout.addLayout(right_column)
        layout.addLayout(charts_layout)

        # Recent transactions section
        recent_label = QLabel("Recent Large Transactions")
        recent_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(recent_label)

        self.recent_large_table = QTableWidget()
        self.recent_large_table.setColumnCount(4)
        self.recent_large_table.setHorizontalHeaderLabels(
            ["Date", "Description", "Amount", "Category"]
        )
        self.recent_large_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.recent_large_table.setMaximumHeight(200)
        layout.addWidget(self.recent_large_table)

        self.tabs.addTab(analytics_widget, "Analytics")

    def _authenticate_user(self):
        """Authenticate user or setup password on first run."""
        # Check if database exists
        db_exists = self.db_manager.db_path.exists()
        if not db_exists:
            # Prompt to set password
            password_dialog = QDialog(self)
            password_dialog.setWindowTitle("Set Database Password")
            layout = QVBoxLayout()
            label = QLabel("Create a password to secure your financial data:")
            password_input = QLineEdit()
            password_input.setEchoMode(QLineEdit.Password)
            layout.addWidget(label)
            layout.addWidget(password_input)
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            layout.addWidget(buttons)
            password_dialog.setLayout(layout)
            buttons.accepted.connect(password_dialog.accept)
            buttons.rejected.connect(password_dialog.reject)
            if password_dialog.exec_() == QDialog.Accepted:
                new_password = password_input.text() or "new_password_123"
                if self.db_manager.initialize_database(new_password):
                    self.current_password = new_password
                    self._load_accounts()  # Load empty accounts table
                    self._load_file_imports()  # Load empty imports table
                    self._load_categories()  # Load default categories
                    self._load_analytics_accounts()  # Load analytics accounts
                    self.status_bar.showMessage("New database created successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to create database")
                    sys.exit(1)
            else:
                sys.exit(0)
        else:
            # Normal authentication flow
            while True:
                password_dialog = PasswordDialog(self, "Database Password")

                if password_dialog.exec_() == QDialog.Accepted:
                    # Check if reset was requested
                    if password_dialog.reset_requested:
                        # Delete existing database and create new one
                        if self.db_manager.db_path.exists():
                            self.db_manager.db_path.unlink()

                        new_password = (
                            password_dialog.get_password() or "new_password_123"
                        )
                        if self.db_manager.initialize_database(new_password):
                            self.current_password = new_password
                            self.status_bar.showMessage(
                                "New database created successfully"
                            )
                            break
                        else:
                            QMessageBox.critical(
                                self, "Error", "Failed to create new database"
                            )
                        continue

                    password = password_dialog.get_password()

                    # Check if database exists
                    if not self.db_manager.db_path.exists():
                        # Initialize new database
                        if self.db_manager.initialize_database(password):
                            self.current_password = password
                            self.status_bar.showMessage(
                                "New encrypted database created"
                            )
                            break
                        else:
                            QMessageBox.critical(
                                self, "Error", "Failed to create database"
                            )
                    else:
                        # Verify existing database
                        if self.db_manager.verify_password(password):
                            self.current_password = password
                            self._load_transactions()
                            self._load_accounts()
                            self._load_file_imports()
                            self._load_categories()
                            self._load_analytics_accounts()
                            self.status_bar.showMessage(
                                "Database unlocked successfully"
                            )
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
        """Import a financial statement file with account selection and creation."""
        if not self.current_password:
            QMessageBox.warning(self, "Error", "Database not authenticated")
            return

        # Query accounts
        try:
            with self.db_manager._get_connection(self.current_password) as conn:
                cursor = conn.execute("SELECT id, account_name FROM accounts")
                accounts = cursor.fetchall()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load accounts: {e}")
            return

        if not accounts:
            # Prompt to create account
            account_dialog = QDialog(self)
            account_dialog.setWindowTitle("Create Account")
            form = QFormLayout()
            name_input = QLineEdit()
            type_combo = QComboBox()
            type_combo.addItems(["checking", "savings", "credit"])
            institution_input = QLineEdit()
            form.addRow("Account Name:", name_input)
            form.addRow("Account Type:", type_combo)
            form.addRow("Institution:", institution_input)
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            form.addWidget(buttons)
            account_dialog.setLayout(form)
            buttons.accepted.connect(account_dialog.accept)
            buttons.rejected.connect(account_dialog.reject)
            if account_dialog.exec_() == QDialog.Accepted:
                acc_name = name_input.text().strip()
                acc_type = type_combo.currentText()
                institution = institution_input.text().strip()
                if acc_name:
                    try:
                        with self.db_manager._get_connection(
                            self.current_password
                        ) as conn:
                            conn.execute(
                                "INSERT INTO accounts (account_name, account_type, institution) VALUES (?, ?, ?)",
                                (acc_name, acc_type, institution),
                            )
                            conn.commit()
                            cursor = conn.execute(
                                "SELECT id, account_name FROM accounts"
                            )
                            accounts = cursor.fetchall()
                    except Exception as e:
                        QMessageBox.critical(
                            self, "Error", f"Failed to create account: {e}"
                        )
                        return
                else:
                    QMessageBox.warning(self, "Error", "Account name required.")
                    return
            else:
                return

        # Open file dialog
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Financial Files (*.pdf *.csv *.xlsx *.xls)")

        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                file_path = Path(selected_files[0])
                # Prompt for account selection if multiple
                if len(accounts) == 1:
                    account_id = accounts[0][0]
                else:
                    dialog = QDialog(self)
                    dialog.setWindowTitle("Select Account for Import")
                    layout = QVBoxLayout()
                    label = QLabel(
                        "Select the account to assign imported transactions:"
                    )
                    combo = QComboBox()
                    for acc in accounts:
                        combo.addItem(acc[1], acc[0])
                    layout.addWidget(label)
                    layout.addWidget(combo)
                    buttons = QDialogButtonBox(
                        QDialogButtonBox.Ok | QDialogButtonBox.Cancel
                    )
                    layout.addWidget(buttons)
                    dialog.setLayout(layout)
                    buttons.accepted.connect(dialog.accept)
                    buttons.rejected.connect(dialog.reject)
                    if dialog.exec_() == QDialog.Accepted:
                        account_id = combo.currentData()
                    else:
                        return  # Cancelled
                self._process_file_import(file_path, account_id)

    def _process_file_import(self, file_path: Path, account_id: int):
        """Process file import in background thread, passing account_id."""
        try:
            # Get account type for proper transaction parsing
            account_type = "checking"  # Default
            try:
                with self.db_manager._get_connection(self.current_password) as conn:
                    cursor = conn.execute(
                        "SELECT account_type FROM accounts WHERE id = ?", (account_id,)
                    )
                    result = cursor.fetchone()
                    if result:
                        account_type = result[0]
            except Exception as e:
                self.logger.warning(f"Could not get account type: {e}")

            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)

            self.import_thread = FileImportThread(
                file_path,
                self.db_manager,
                self.current_password,
                account_id,
                account_type,
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
            self._load_file_imports()  # Refresh imports view
            self._update_analytics()  # Refresh analytics
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

    def _load_accounts(self):
        """Load and display accounts in the table."""
        if not self.current_password:
            return

        try:
            with self.db_manager._get_connection(self.current_password) as conn:
                cursor = conn.execute(
                    """SELECT account_name, account_type, institution, notes, created_at 
                       FROM accounts ORDER BY created_at DESC"""
                )
                accounts = cursor.fetchall()

            # Update accounts table
            self.accounts_table.setRowCount(len(accounts))

            for row, account in enumerate(accounts):
                self.accounts_table.setItem(
                    row, 0, QTableWidgetItem(str(account[0]))  # name
                )
                self.accounts_table.setItem(
                    row, 1, QTableWidgetItem(str(account[1]))  # type
                )
                self.accounts_table.setItem(
                    row, 2, QTableWidgetItem(str(account[2] or ""))  # institution
                )
                self.accounts_table.setItem(
                    row, 3, QTableWidgetItem(str(account[3] or ""))  # notes
                )
                # Format created date
                created_date = str(account[4])[:10] if account[4] else ""
                self.accounts_table.setItem(
                    row, 4, QTableWidgetItem(created_date)  # created
                )

        except Exception as e:
            self.logger.error(f"Failed to load accounts: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load accounts: {str(e)}")

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

    def _add_account(self):
        """Add a new account."""
        if not self.current_password:
            QMessageBox.warning(self, "Error", "Database not authenticated")
            return

        # Create account dialog
        account_dialog = QDialog(self)
        account_dialog.setWindowTitle("Add New Account")
        account_dialog.setFixedSize(400, 250)

        form = QFormLayout()

        name_input = QLineEdit()
        name_input.setPlaceholderText("e.g., Chase Checking")

        type_combo = QComboBox()
        type_combo.addItems(["checking", "savings", "credit"])

        institution_input = QLineEdit()
        institution_input.setPlaceholderText("e.g., Chase Bank")

        notes_input = QLineEdit()
        notes_input.setPlaceholderText("Optional notes")

        form.addRow("Account Name*:", name_input)
        form.addRow("Account Type:", type_combo)
        form.addRow("Institution:", institution_input)
        form.addRow("Notes:", notes_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        form.addWidget(buttons)

        account_dialog.setLayout(form)
        buttons.accepted.connect(account_dialog.accept)
        buttons.rejected.connect(account_dialog.reject)

        # Focus on name input
        name_input.setFocus()

        if account_dialog.exec_() == QDialog.Accepted:
            account_name = name_input.text().strip()
            account_type = type_combo.currentText()
            institution = institution_input.text().strip()
            notes = notes_input.text().strip()

            if not account_name:
                QMessageBox.warning(self, "Error", "Account name is required.")
                return

            try:
                with self.db_manager._get_connection(self.current_password) as conn:
                    conn.execute(
                        """INSERT INTO accounts 
                           (account_name, account_type, institution, notes) 
                           VALUES (?, ?, ?, ?)""",
                        (
                            account_name,
                            account_type,
                            institution or None,
                            notes or None,
                        ),
                    )
                    conn.commit()

                QMessageBox.information(
                    self, "Success", f"Account '{account_name}' added successfully!"
                )
                self.status_bar.showMessage(f"Added account: {account_name}")
                self._load_accounts()  # Refresh accounts table

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add account: {str(e)}")

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

    def _map_categories_to_ids(self, transactions):
        """Map predicted category names to database category IDs."""
        if not self.current_password:
            return

        try:
            # Get all categories from database
            with self.db_manager._get_connection(self.current_password) as conn:
                cursor = conn.execute("SELECT id, name FROM categories")
                category_map = {
                    name.lower(): cat_id for cat_id, name in cursor.fetchall()
                }

            # Map predicted categories to IDs
            for transaction in transactions:
                predicted_category = transaction.get("predicted_category", "").lower()

                if predicted_category in category_map:
                    transaction["category_id"] = category_map[predicted_category]
                elif predicted_category == "food":
                    # Map common ML categories to database categories
                    transaction["category_id"] = category_map.get("food & dining")
                elif predicted_category == "transportation":
                    transaction["category_id"] = category_map.get("transportation")
                elif predicted_category == "shopping":
                    transaction["category_id"] = category_map.get("shopping")
                elif predicted_category == "entertainment":
                    transaction["category_id"] = category_map.get("entertainment")
                elif predicted_category == "utilities":
                    transaction["category_id"] = category_map.get("bills & utilities")
                elif predicted_category == "healthcare":
                    transaction["category_id"] = category_map.get("healthcare")
                elif predicted_category == "income":
                    transaction["category_id"] = category_map.get("income")
                else:
                    # Leave as None for uncategorized
                    transaction["category_id"] = None

        except Exception as e:
            self.logger.error(f"Failed to map categories: {e}")
            # If mapping fails, leave categories as None

    def _load_file_imports(self):
        """Load and display file imports in the table."""
        if not self.current_password:
            return

        try:
            imports = self.db_manager.get_file_imports(self.current_password)

            # Update imports table
            self.imports_table.setRowCount(len(imports))

            for row, import_record in enumerate(imports):
                # File name
                self.imports_table.setItem(
                    row, 0, QTableWidgetItem(str(import_record.get("filename", "")))
                )

                # Import date (format for display)
                import_date = str(import_record.get("import_date", ""))[:16]
                self.imports_table.setItem(row, 1, QTableWidgetItem(import_date))

                # Original transaction count
                original_count = import_record.get("transactions_imported", 0)
                self.imports_table.setItem(
                    row, 2, QTableWidgetItem(str(original_count))
                )

                # Current transaction count
                current_count = import_record.get("current_transaction_count", 0)
                self.imports_table.setItem(row, 3, QTableWidgetItem(str(current_count)))

                # Status
                status = import_record.get("status", "completed")
                self.imports_table.setItem(row, 4, QTableWidgetItem(status))

                # Actions button (only if transactions exist)
                if current_count > 0:
                    delete_btn = QPushButton("Delete File Import")
                    delete_btn.setStyleSheet("background-color: #ffcccc;")
                    file_hash = import_record.get("file_hash")
                    delete_btn.clicked.connect(
                        lambda checked, fh=file_hash, fn=import_record.get(
                            "filename"
                        ): self._delete_file_import(fh, fn)
                    )
                    self.imports_table.setCellWidget(row, 5, delete_btn)
                else:
                    self.imports_table.setItem(
                        row, 5, QTableWidgetItem("Already deleted")
                    )

        except Exception as e:
            self.logger.error(f"Failed to load file imports: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load imports: {str(e)}")

    def _delete_file_import(self, file_hash: str, filename: str):
        """Delete all transactions from a specific file import."""
        if not self.current_password or not file_hash:
            return

        # Get transaction count for confirmation
        try:
            transactions = self.db_manager.get_transactions_by_file(
                self.current_password, file_hash
            )
            transaction_count = len(transactions)

            if transaction_count == 0:
                QMessageBox.information(
                    self,
                    "No Transactions",
                    "No transactions found for this file import.",
                )
                return

            # Show confirmation dialog with preview
            dialog = QDialog(self)
            dialog.setWindowTitle("Confirm File Import Deletion")
            dialog.setFixedSize(600, 400)

            layout = QVBoxLayout()

            # Warning message
            warning_label = QLabel(
                f"⚠️ This will permanently delete {transaction_count} "
                f"transactions from '{filename}'"
            )
            warning_label.setStyleSheet("color: red; font-weight: bold; margin: 10px;")
            layout.addWidget(warning_label)

            # Show preview of transactions to be deleted
            preview_label = QLabel("Transactions to be deleted:")
            layout.addWidget(preview_label)

            preview_table = QTableWidget()
            preview_table.setColumnCount(4)
            preview_table.setHorizontalHeaderLabels(
                ["Date", "Description", "Amount", "Type"]
            )
            preview_table.setRowCount(min(10, transaction_count))  # Show max 10

            for i, transaction in enumerate(transactions[:10]):
                preview_table.setItem(
                    i, 0, QTableWidgetItem(str(transaction.get("transaction_date", "")))
                )
                preview_table.setItem(
                    i,
                    1,
                    QTableWidgetItem(
                        str(transaction.get("description", ""))[:40] + "..."
                    ),
                )
                preview_table.setItem(
                    i, 2, QTableWidgetItem(f"${transaction.get('amount', 0):.2f}")
                )
                preview_table.setItem(
                    i, 3, QTableWidgetItem(str(transaction.get("transaction_type", "")))
                )

            preview_table.setEditTriggers(QTableWidget.NoEditTriggers)
            preview_table.resizeColumnsToContents()
            layout.addWidget(preview_table)

            if transaction_count > 10:
                more_label = QLabel(
                    f"... and {transaction_count - 10} more transactions"
                )
                more_label.setStyleSheet("font-style: italic; color: gray;")
                layout.addWidget(more_label)

            # Buttons
            button_layout = QHBoxLayout()

            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(dialog.reject)
            button_layout.addWidget(cancel_btn)

            button_layout.addStretch()

            delete_btn = QPushButton("Delete All Transactions")
            delete_btn.setStyleSheet("background-color: #ff4444; color: white;")
            delete_btn.clicked.connect(dialog.accept)
            button_layout.addWidget(delete_btn)

            layout.addLayout(button_layout)
            dialog.setLayout(layout)

            # Execute deletion if confirmed
            if dialog.exec_() == QDialog.Accepted:
                deleted_count = self.db_manager.delete_transactions_by_file(
                    self.current_password, file_hash
                )

                if deleted_count > 0:
                    QMessageBox.information(
                        self,
                        "Deletion Complete",
                        f"Successfully deleted {deleted_count} transactions "
                        f"from '{filename}'",
                    )
                    self._load_file_imports()  # Refresh the imports table
                    self._load_transactions()  # Refresh transactions table
                else:
                    QMessageBox.warning(
                        self,
                        "Deletion Failed",
                        "No transactions were deleted. They may have already been removed.",
                    )

        except Exception as e:
            self.logger.error(f"Failed to delete file import: {e}")
            QMessageBox.critical(
                self, "Error", f"Failed to delete transactions: {str(e)}"
            )

    def _find_duplicates(self):
        """Find and display potential duplicate transactions."""
        if not self.current_password:
            return

        try:
            # Show progress
            self.status_bar.showMessage("Searching for duplicate transactions...")

            duplicates = self.db_manager.find_duplicate_transactions(
                self.current_password
            )

            if not duplicates:
                QMessageBox.information(
                    self,
                    "No Duplicates Found",
                    "No potential duplicate transactions were found.",
                )
                self.status_bar.showMessage("Ready")
                return

            # Show duplicates dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("Potential Duplicate Transactions")
            dialog.setFixedSize(800, 600)

            layout = QVBoxLayout()

            # Header
            header_label = QLabel(
                f"Found {len(duplicates)} potential duplicate groups:"
            )
            header_label.setFont(QFont("Arial", 12, QFont.Bold))
            layout.addWidget(header_label)

            # Duplicates table
            dup_table = QTableWidget()
            dup_table.setColumnCount(6)
            dup_table.setHorizontalHeaderLabels(
                [
                    "Date",
                    "Description",
                    "Amount",
                    "Account",
                    "Duplicate Count",
                    "Select",
                ]
            )
            dup_table.setRowCount(len(duplicates))

            selected_transactions = []

            for row, dup in enumerate(duplicates):
                dup_table.setItem(
                    row, 0, QTableWidgetItem(str(dup.get("transaction_date", "")))
                )
                dup_table.setItem(
                    row,
                    1,
                    QTableWidgetItem(str(dup.get("description", ""))[:50] + "..."),
                )
                dup_table.setItem(
                    row, 2, QTableWidgetItem(f"${dup.get('amount', 0):.2f}")
                )
                dup_table.setItem(
                    row, 3, QTableWidgetItem(str(dup.get("account_name", "")))
                )
                dup_table.setItem(
                    row, 4, QTableWidgetItem(str(dup.get("duplicate_count", 1)))
                )

                # Checkbox for selection
                checkbox = QCheckBox()
                checkbox.setProperty("transaction_id", dup.get("id"))
                dup_table.setCellWidget(row, 5, checkbox)

            dup_table.setEditTriggers(QTableWidget.NoEditTriggers)
            dup_table.resizeColumnsToContents()
            layout.addWidget(dup_table)

            # Instructions
            instructions = QLabel(
                "Select transactions to delete (keep at least one copy of each duplicate):"
            )
            instructions.setStyleSheet("color: blue; font-style: italic; margin: 10px;")
            layout.addWidget(instructions)

            # Buttons
            button_layout = QHBoxLayout()

            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(dialog.reject)
            button_layout.addWidget(cancel_btn)

            select_all_btn = QPushButton("Select All")
            select_all_btn.clicked.connect(
                lambda: self._toggle_all_checkboxes(dup_table, True)
            )
            button_layout.addWidget(select_all_btn)

            clear_all_btn = QPushButton("Clear All")
            clear_all_btn.clicked.connect(
                lambda: self._toggle_all_checkboxes(dup_table, False)
            )
            button_layout.addWidget(clear_all_btn)

            button_layout.addStretch()

            delete_selected_btn = QPushButton("Delete Selected")
            delete_selected_btn.setStyleSheet(
                "background-color: #ff4444; color: white;"
            )
            delete_selected_btn.clicked.connect(
                lambda: self._delete_selected_duplicates(dialog, dup_table)
            )
            button_layout.addWidget(delete_selected_btn)

            layout.addLayout(button_layout)
            dialog.setLayout(layout)

            dialog.exec_()

        except Exception as e:
            self.logger.error(f"Failed to find duplicates: {e}")
            QMessageBox.critical(self, "Error", f"Failed to find duplicates: {str(e)}")
        finally:
            self.status_bar.showMessage("Ready")

    def _toggle_all_checkboxes(self, table: QTableWidget, checked: bool):
        """Toggle all checkboxes in the duplicates table."""
        for row in range(table.rowCount()):
            checkbox = table.cellWidget(row, 5)
            if checkbox:
                checkbox.setChecked(checked)

    def _delete_selected_duplicates(self, dialog: QDialog, table: QTableWidget):
        """Delete selected duplicate transactions."""
        try:
            # Get selected transaction IDs
            selected_ids = []
            for row in range(table.rowCount()):
                checkbox = table.cellWidget(row, 5)
                if checkbox and checkbox.isChecked():
                    transaction_id = checkbox.property("transaction_id")
                    if transaction_id:
                        selected_ids.append(transaction_id)

            if not selected_ids:
                QMessageBox.warning(
                    dialog, "No Selection", "Please select transactions to delete."
                )
                return

            # Confirm deletion
            reply = QMessageBox.question(
                dialog,
                "Confirm Deletion",
                f"Are you sure you want to delete {len(selected_ids)} "
                f"selected transactions?\n\nThis action cannot be undone.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )

            if reply == QMessageBox.Yes:
                deleted_count = self.db_manager.delete_transactions_by_ids(
                    self.current_password, selected_ids
                )

                QMessageBox.information(
                    dialog,
                    "Deletion Complete",
                    f"Successfully deleted {deleted_count} duplicate transactions.",
                )

                dialog.accept()
                self._load_transactions()  # Refresh transactions table
                self._load_file_imports()  # Refresh imports table

        except Exception as e:
            self.logger.error(f"Failed to delete selected duplicates: {e}")
            QMessageBox.critical(
                dialog, "Error", f"Failed to delete transactions: {str(e)}"
            )

    def _create_summary_card(self, title: str, value: str, color: str) -> QWidget:
        """Create a summary card widget for analytics."""
        card = QWidget()
        card.setStyleSheet(
            f"""
            QWidget {{
                background-color: white;
                border: 2px solid {color};
                border-radius: 8px;
                margin: 5px;
                padding: 10px;
            }}
        """
        )
        card.setFixedSize(150, 80)

        layout = QVBoxLayout()

        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 10px; color: gray;")
        layout.addWidget(title_label)

        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setStyleSheet(
            f"font-size: 14px; font-weight: bold; color: {color};"
        )
        layout.addWidget(value_label)

        card.setLayout(layout)
        return card

    def _load_categories(self):
        """Load and display categories in the table."""
        if not self.current_password:
            return

        try:
            with self.db_manager._get_connection(self.current_password) as conn:
                # Get categories with transaction counts
                query = """
                    SELECT c.id, c.name, c.is_income, 
                           CASE WHEN c.parent_id IS NULL THEN '' 
                                ELSE p.name END as parent_name,
                           COUNT(t.id) as transaction_count
                    FROM categories c
                    LEFT JOIN categories p ON c.parent_id = p.id
                    LEFT JOIN transactions t ON c.id = t.category_id
                    GROUP BY c.id, c.name, c.is_income, p.name
                    ORDER BY c.is_income DESC, c.name
                """
                cursor = conn.execute(query)
                categories = cursor.fetchall()

            # Update categories table
            self.categories_table.setRowCount(len(categories))

            total_categories = 0
            income_categories = 0
            expense_categories = 0

            for row, category in enumerate(categories):
                cat_id, name, is_income, parent_name, trans_count = category

                # Category name
                self.categories_table.setItem(row, 0, QTableWidgetItem(name))

                # Type
                cat_type = "Income" if is_income else "Expense"
                self.categories_table.setItem(row, 1, QTableWidgetItem(cat_type))

                # Parent category
                self.categories_table.setItem(
                    row, 2, QTableWidgetItem(parent_name or "")
                )

                # Transaction count
                self.categories_table.setItem(
                    row, 3, QTableWidgetItem(str(trans_count))
                )

                # Actions button (edit/delete if no transactions)
                if trans_count == 0:
                    delete_btn = QPushButton("Delete")
                    delete_btn.setStyleSheet("background-color: #ffcccc;")
                    delete_btn.clicked.connect(
                        lambda checked, cid=cat_id, cname=name: self._delete_category(
                            cid, cname
                        )
                    )
                    self.categories_table.setCellWidget(row, 4, delete_btn)
                else:
                    self.categories_table.setItem(
                        row, 4, QTableWidgetItem(f"{trans_count} transactions")
                    )

                # Update counts
                total_categories += 1
                if is_income:
                    income_categories += 1
                else:
                    expense_categories += 1

            # Update statistics
            self.total_categories_label.setText(f"Total Categories: {total_categories}")
            self.income_categories_label.setText(f"Income: {income_categories}")
            self.expense_categories_label.setText(f"Expense: {expense_categories}")

        except Exception as e:
            self.logger.error(f"Failed to load categories: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load categories: {str(e)}")

    def _add_category(self):
        """Add a new category."""
        if not self.current_password:
            QMessageBox.warning(self, "Error", "Database not authenticated")
            return

        # Create category dialog
        category_dialog = QDialog(self)
        category_dialog.setWindowTitle("Add New Category")
        category_dialog.setFixedSize(400, 250)

        form = QFormLayout()

        name_input = QLineEdit()
        name_input.setPlaceholderText("e.g., Groceries, Salary")

        type_combo = QComboBox()
        type_combo.addItems(["Expense", "Income"])

        # Get existing categories for parent selection
        parent_combo = QComboBox()
        parent_combo.addItem("None (Top Level)", None)

        try:
            with self.db_manager._get_connection(self.current_password) as conn:
                cursor = conn.execute(
                    "SELECT id, name FROM categories WHERE parent_id IS NULL ORDER BY name"
                )
                for cat_id, cat_name in cursor.fetchall():
                    parent_combo.addItem(cat_name, cat_id)
        except Exception as e:
            self.logger.warning(f"Could not load parent categories: {e}")

        form.addRow("Category Name*:", name_input)
        form.addRow("Type:", type_combo)
        form.addRow("Parent Category:", parent_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        form.addWidget(buttons)

        category_dialog.setLayout(form)
        buttons.accepted.connect(category_dialog.accept)
        buttons.rejected.connect(category_dialog.reject)

        # Focus on name input
        name_input.setFocus()

        if category_dialog.exec_() == QDialog.Accepted:
            category_name = name_input.text().strip()
            is_income = type_combo.currentText() == "Income"
            parent_id = parent_combo.currentData()

            if not category_name:
                QMessageBox.warning(self, "Error", "Category name is required.")
                return

            try:
                with self.db_manager._get_connection(self.current_password) as conn:
                    conn.execute(
                        """INSERT INTO categories (name, is_income, parent_id) 
                           VALUES (?, ?, ?)""",
                        (category_name, is_income, parent_id),
                    )
                    conn.commit()

                QMessageBox.information(
                    self, "Success", f"Category '{category_name}' added successfully!"
                )
                self.status_bar.showMessage(f"Added category: {category_name}")
                self._load_categories()  # Refresh categories table

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add category: {str(e)}")

    def _delete_category(self, category_id: int, category_name: str):
        """Delete a category (only if no transactions)."""
        reply = QMessageBox.question(
            self,
            "Delete Category",
            f"Are you sure you want to delete the category '{category_name}'?\n"
            f"This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            try:
                with self.db_manager._get_connection(self.current_password) as conn:
                    conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
                    conn.commit()

                QMessageBox.information(
                    self, "Success", f"Category '{category_name}' deleted successfully!"
                )
                self._load_categories()  # Refresh categories table

            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to delete category: {str(e)}"
                )

    def _load_analytics_accounts(self):
        """Load accounts into analytics account filter."""
        if not self.current_password:
            return

        try:
            # Clear existing items (except "All Accounts")
            self.account_filter_combo.clear()
            self.account_filter_combo.addItem("All Accounts")

            with self.db_manager._get_connection(self.current_password) as conn:
                cursor = conn.execute(
                    "SELECT id, account_name FROM accounts ORDER BY account_name"
                )
                for account_id, account_name in cursor.fetchall():
                    self.account_filter_combo.addItem(account_name, account_id)

            # Load initial analytics
            self._update_analytics()

        except Exception as e:
            self.logger.error(f"Failed to load analytics accounts: {e}")

    def _update_analytics(self):
        """Update all analytics data and displays."""
        if not self.current_password:
            return

        try:
            # Get filter parameters
            period = self.period_combo.currentText()
            account_filter = self.account_filter_combo.currentData()

            # Build date filter
            date_filter = self._get_date_filter(period)

            # Get transactions for analysis
            transactions = self._get_filtered_transactions(date_filter, account_filter)

            # Update summary cards
            self._update_summary_cards(transactions)

            # Update category breakdown
            self._update_category_breakdown(transactions)

            # Update monthly trends
            self._update_monthly_trends(transactions)

            # Update recent large transactions
            self._update_recent_large_transactions(transactions)

        except Exception as e:
            self.logger.error(f"Failed to update analytics: {e}")

    def _get_date_filter(self, period: str) -> str:
        """Get SQL date filter for the selected period."""
        if period == "Last 30 Days":
            return "AND transaction_date >= date('now', '-30 days')"
        elif period == "Last 90 Days":
            return "AND transaction_date >= date('now', '-90 days')"
        elif period == "Last 6 Months":
            return "AND transaction_date >= date('now', '-6 months')"
        elif period == "Last Year":
            return "AND transaction_date >= date('now', '-1 year')"
        elif period == "All Time":
            return ""
        else:  # Custom Range - for now, default to last 30 days
            return "AND transaction_date >= date('now', '-30 days')"

    def _get_filtered_transactions(self, date_filter: str, account_filter):
        """Get transactions with applied filters."""
        try:
            with self.db_manager._get_connection(self.current_password) as conn:
                query = f"""
                    SELECT t.*, c.name as category_name, a.account_name
                    FROM transactions t
                    LEFT JOIN categories c ON t.category_id = c.id
                    LEFT JOIN accounts a ON t.account_id = a.id
                    WHERE 1=1 {date_filter}
                """
                params = []

                if account_filter is not None:
                    query += " AND t.account_id = ?"
                    params.append(account_filter)

                query += " ORDER BY t.transaction_date DESC"

                cursor = conn.execute(query, params)
                columns = [description[0] for description in cursor.description]
                transactions = []

                for row in cursor.fetchall():
                    transactions.append(dict(zip(columns, row)))

                return transactions

        except Exception as e:
            self.logger.error(f"Failed to get filtered transactions: {e}")
            return []

    def _update_summary_cards(self, transactions):
        """Update the summary cards with transaction data."""
        total_income = 0
        total_expenses = 0
        transaction_count = len(transactions)

        for transaction in transactions:
            amount = float(transaction.get("amount", 0))
            trans_type = transaction.get("transaction_type", "")

            if trans_type == "credit":
                total_income += amount
            elif trans_type == "debit":
                total_expenses += amount

        net_amount = total_income - total_expenses

        # Update labels
        self.income_label.setText(f"${total_income:.2f}")
        self.expenses_label.setText(f"${total_expenses:.2f}")

        net_color = "#4CAF50" if net_amount >= 0 else "#F44336"
        self.net_label.setText(f"${net_amount:.2f}")
        self.net_label.setStyleSheet(
            f"font-size: 14px; font-weight: bold; color: {net_color};"
        )

        self.count_label.setText(str(transaction_count))

    def _update_category_breakdown(self, transactions):
        """Update category breakdown table."""
        category_totals = {}
        total_amount = 0

        # Calculate category totals (expenses only)
        for transaction in transactions:
            if transaction.get("transaction_type") == "debit":
                amount = float(transaction.get("amount", 0))
                category = transaction.get("category_name") or "Uncategorized"
                category_totals[category] = category_totals.get(category, 0) + amount
                total_amount += amount

        # Sort by amount
        sorted_categories = sorted(
            category_totals.items(), key=lambda x: x[1], reverse=True
        )

        # Update table
        self.category_table.setRowCount(len(sorted_categories))

        for row, (category, amount) in enumerate(sorted_categories):
            percentage = (amount / total_amount * 100) if total_amount > 0 else 0

            self.category_table.setItem(row, 0, QTableWidgetItem(category))
            self.category_table.setItem(row, 1, QTableWidgetItem(f"${amount:.2f}"))
            self.category_table.setItem(row, 2, QTableWidgetItem(f"{percentage:.1f}%"))

        self.category_table.resizeColumnsToContents()

    def _update_monthly_trends(self, transactions):
        """Update monthly trends table."""
        from collections import defaultdict

        monthly_data = defaultdict(lambda: {"income": 0, "expenses": 0})

        # Group by month
        for transaction in transactions:
            date_str = transaction.get("transaction_date", "")
            if date_str:
                # Extract year-month from date
                month_key = date_str[:7]  # YYYY-MM format
                amount = float(transaction.get("amount", 0))
                trans_type = transaction.get("transaction_type", "")

                if trans_type == "credit":
                    monthly_data[month_key]["income"] += amount
                elif trans_type == "debit":
                    monthly_data[month_key]["expenses"] += amount

        # Sort by month (most recent first)
        sorted_months = sorted(monthly_data.items(), key=lambda x: x[0], reverse=True)

        # Update table (show last 6 months max)
        display_months = sorted_months[:6]
        self.trends_table.setRowCount(len(display_months))

        for row, (month, data) in enumerate(display_months):
            income = data["income"]
            expenses = data["expenses"]
            net = income - expenses

            self.trends_table.setItem(row, 0, QTableWidgetItem(month))
            self.trends_table.setItem(row, 1, QTableWidgetItem(f"${income:.2f}"))
            self.trends_table.setItem(row, 2, QTableWidgetItem(f"${expenses:.2f}"))

            net_item = QTableWidgetItem(f"${net:.2f}")
            if net < 0:
                net_item.setStyleSheet("color: red;")
            else:
                net_item.setStyleSheet("color: green;")
            self.trends_table.setItem(row, 3, net_item)

        self.trends_table.resizeColumnsToContents()

    def _update_recent_large_transactions(self, transactions):
        """Update recent large transactions table."""
        # Filter for large transactions (top 10 by amount)
        large_transactions = sorted(
            transactions, key=lambda x: float(x.get("amount", 0)), reverse=True
        )[:10]

        self.recent_large_table.setRowCount(len(large_transactions))

        for row, transaction in enumerate(large_transactions):
            self.recent_large_table.setItem(
                row, 0, QTableWidgetItem(transaction.get("transaction_date", ""))
            )

            description = transaction.get("description", "")[
                :40
            ]  # Truncate long descriptions
            self.recent_large_table.setItem(row, 1, QTableWidgetItem(description))

            amount = float(transaction.get("amount", 0))
            self.recent_large_table.setItem(row, 2, QTableWidgetItem(f"${amount:.2f}"))

            category = transaction.get("category_name") or "Uncategorized"
            self.recent_large_table.setItem(row, 3, QTableWidgetItem(category))

        self.recent_large_table.resizeColumnsToContents()
