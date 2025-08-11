"""
Test suite for Personal Finance Manager

This module contains unit tests for the application components.
Tests ensure security, functionality, and data integrity.
"""

import unittest
import tempfile
import os
from pathlib import Path

# Test configuration
TEST_DB_PATH = Path(tempfile.gettempdir()) / "test_finance.db"
TEST_PASSWORD = "test_password_123"
