"""
Test Database Manager functionality and security
"""

import unittest
import tempfile
from pathlib import Path
import os
import sys

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from database.db_manager import DatabaseManager


class TestDatabaseManager(unittest.TestCase):
    """Test DatabaseManager class functionality and security."""

    def setUp(self):
        """Set up test database."""
        self.test_db = Path(tempfile.mkdtemp()) / "test_db.db"
        self.password = "test_password_123"
        self.db_manager = DatabaseManager(self.test_db)

    def tearDown(self):
        """Clean up test database."""
        if self.test_db.exists():
            self.test_db.unlink()
        if self.test_db.parent.exists():
            self.test_db.parent.rmdir()

    def test_database_initialization(self):
        """Test database initialization with password."""
        result = self.db_manager.initialize_database(self.password)
        self.assertTrue(result)
        self.assertTrue(self.test_db.exists())

    def test_password_verification(self):
        """Test password verification."""
        self.db_manager.initialize_database(self.password)

        # Correct password
        self.assertTrue(self.db_manager.verify_password(self.password))

        # Incorrect password
        self.assertFalse(self.db_manager.verify_password("wrong_password"))

    def test_add_transaction(self):
        """Test adding transactions to database."""
        self.db_manager.initialize_database(self.password)

        transaction_data = {
            "account_id": 1,
            "transaction_date": "2023-01-15",
            "description": "Test Transaction",
            "amount": 100.50,
            "transaction_type": "debit",
            "category_id": 1,
            "subcategory": "Food",
            "notes": "Test notes",
            "file_hash": "test_hash",
        }

        transaction_id = self.db_manager.add_transaction(
            self.password, transaction_data
        )
        self.assertIsNotNone(transaction_id)
        self.assertIsInstance(transaction_id, int)

    def test_get_transactions(self):
        """Test retrieving transactions."""
        self.db_manager.initialize_database(self.password)

        # Add test transaction
        transaction_data = {
            "account_id": 1,
            "transaction_date": "2023-01-15",
            "description": "Test Transaction",
            "amount": 100.50,
            "transaction_type": "debit",
            "category_id": 1,
        }

        self.db_manager.add_transaction(self.password, transaction_data)

        # Retrieve transactions
        transactions = self.db_manager.get_transactions(self.password)
        self.assertIsInstance(transactions, list)
        self.assertEqual(len(transactions), 1)
        self.assertEqual(transactions[0]["description"], "Test Transaction")


if __name__ == "__main__":
    unittest.main()
