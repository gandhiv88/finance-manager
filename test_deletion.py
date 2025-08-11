#!/usr/bin/env python3
"""
Quick test script for deletion functionality
"""

from src.database.db_manager import DatabaseManager
from pathlib import Path
import tempfile
import os


def test_deletion_functions():
    """Test the deletion functions."""
    # Use a temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        db_manager = DatabaseManager(db_path)
        password = "test_password_123"

        # Initialize database
        print("✓ Initializing test database...")
        if not db_manager.initialize_database(password):
            print("❌ Failed to initialize database")
            return False

        # Add a test account
        print("✓ Adding test account...")
        with db_manager._get_connection(password) as conn:
            conn.execute(
                "INSERT INTO accounts (account_name, account_type, institution) VALUES (?, ?, ?)",
                ("Test Account", "checking", "Test Bank"),
            )
            conn.commit()

            # Get the account ID
            cursor = conn.execute(
                "SELECT id FROM accounts WHERE account_name = 'Test Account'"
            )
            account_id = cursor.fetchone()[0]

        # Add test transactions with different file hashes
        print("✓ Adding test transactions...")
        test_transactions = [
            {
                "account_id": account_id,
                "transaction_date": "2024-01-01",
                "description": "Test Transaction 1",
                "amount": 100.00,
                "transaction_type": "debit",
                "category_id": None,
                "subcategory": None,
                "notes": None,
                "file_hash": "file_hash_1",
            },
            {
                "account_id": account_id,
                "transaction_date": "2024-01-02",
                "description": "Test Transaction 2",
                "amount": 50.00,
                "transaction_type": "debit",
                "category_id": None,
                "subcategory": None,
                "notes": None,
                "file_hash": "file_hash_1",
            },
            {
                "account_id": account_id,
                "transaction_date": "2024-01-03",
                "description": "Test Transaction 3",
                "amount": 75.00,
                "transaction_type": "credit",
                "category_id": None,
                "subcategory": None,
                "notes": None,
                "file_hash": "file_hash_2",
            },
        ]

        transaction_ids = []
        for transaction in test_transactions:
            trans_id = db_manager.add_transaction(password, transaction)
            if trans_id:
                transaction_ids.append(trans_id)

        print(f"✓ Added {len(transaction_ids)} transactions")

        # Add file import records
        with db_manager._get_connection(password) as conn:
            conn.execute(
                "INSERT INTO file_imports (filename, file_hash, file_size, transactions_imported) VALUES (?, ?, ?, ?)",
                ("test_file_1.pdf", "file_hash_1", 1024, 2),
            )
            conn.execute(
                "INSERT INTO file_imports (filename, file_hash, file_size, transactions_imported) VALUES (?, ?, ?, ?)",
                ("test_file_2.pdf", "file_hash_2", 2048, 1),
            )
            conn.commit()

        # Test getting file imports
        print("✓ Testing get_file_imports...")
        imports = db_manager.get_file_imports(password)
        print(f"  Found {len(imports)} file imports")
        for imp in imports:
            print(
                f"  - {imp['filename']}: {imp['current_transaction_count']} transactions"
            )

        # Test getting transactions by file
        print("✓ Testing get_transactions_by_file...")
        file_transactions = db_manager.get_transactions_by_file(password, "file_hash_1")
        print(f"  Found {len(file_transactions)} transactions for file_hash_1")

        # Test duplicate detection
        print("✓ Testing find_duplicate_transactions...")
        duplicates = db_manager.find_duplicate_transactions(password)
        print(f"  Found {len(duplicates)} potential duplicate groups")

        # Test deleting transactions by file
        print("✓ Testing delete_transactions_by_file...")
        deleted_count = db_manager.delete_transactions_by_file(password, "file_hash_1")
        print(f"  Deleted {deleted_count} transactions from file_hash_1")

        # Test deleting specific transactions by ID
        print("✓ Testing delete_transactions_by_ids...")
        remaining_transactions = db_manager.get_transactions(password)
        if remaining_transactions:
            remaining_id = remaining_transactions[0]["id"]
            deleted_count = db_manager.delete_transactions_by_ids(
                password, [remaining_id]
            )
            print(f"  Deleted {deleted_count} specific transaction")

        # Final check
        final_transactions = db_manager.get_transactions(password)
        print(f"✓ Final transaction count: {len(final_transactions)}")

        print("\n🎉 All deletion functionality tests passed!")
        return True

    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        # Clean up
        if os.path.exists(db_path):
            os.unlink(db_path)


if __name__ == "__main__":
    print("Testing deletion functionality...")
    success = test_deletion_functions()
    exit(0 if success else 1)
