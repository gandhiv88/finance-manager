#!/usr/bin/env python3
"""
Reset Database Script

This script will delete the existing database and let you start fresh.
Use this if you've forgotten your password.
"""

import os
import sys
from pathlib import Path

def reset_database():
    """Reset the personal finance database."""
    
    # Database location
    db_dir = Path.home() / ".personalfinance"
    db_path = db_dir / "finance.db"
    
    print("Personal Finance Manager - Database Reset")
    print("=" * 50)
    
    if not db_path.exists():
        print("✅ No existing database found. You can start fresh!")
        return
    
    print(f"📍 Database found at: {db_path}")
    print("⚠️  WARNING: This will DELETE all your financial data!")
    print()
    
    response = input("Are you sure you want to reset the database? (type 'yes' to confirm): ")
    
    if response.lower() == 'yes':
        try:
            db_path.unlink()
            print("✅ Database reset successfully!")
            print("   You can now run the application and set a new password.")
            print()
            print("To run the application:")
            print("   Normal mode: python src/main.py")
            print("   Dev mode:    FINANCE_DEV_MODE=true python src/main.py")
        except Exception as e:
            print(f"❌ Error resetting database: {e}")
    else:
        print("❌ Database reset cancelled.")

if __name__ == "__main__":
    reset_database()
