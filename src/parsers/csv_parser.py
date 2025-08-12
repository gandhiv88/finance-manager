"""
CSV Parser - Extract financial data from CSV files

This module handles parsing of CSV financial statements with automatic
column detection and data validation.

Security Rationale:
- Processes files locally only
- Input validation for malicious CSV content
- Memory-safe parsing with size limits
- No external dependencies for basic CSV parsing
"""

import csv
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import re
from datetime import datetime
import pandas as pd

from security.file_handler import SecureFileHandler


class CSVParser:
    """
    Parse financial data from CSV statements.

    Security: All processing happens locally using pandas and csv module.
    Input validation prevents CSV injection attacks.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.secure_handler = SecureFileHandler()

        # Common column name patterns
        self.date_columns = [
            "date",
            "transaction_date",
            "trans_date",
            "posted_date",
            "effective_date",
        ]
        self.description_columns = [
            "description",
            "memo",
            "payee",
            "merchant",
            "reference",
            "details",
        ]
        self.amount_columns = [
            "amount",
            "transaction_amount",
            "debit_amount",
            "credit_amount",
        ]
        # Debit terms typically represent outflows (charges/purchases/fees)
        self.debit_columns = [
            "debit",
            "debit_amount",
            "withdrawal",
            "charge",
            "purchase",
            "fee",
        ]
        # Credit terms typically represent inflows to the account (payments/refunds)
        self.credit_columns = [
            "credit",
            "credit_amount",
            "deposit",
            "income",
            "payment",
            "pmt",
            "refund",
            "reversal",
            "adjustment",
        ]
        # Optional transaction type columns (values like 'Sale', 'Payment', etc.)
        self.type_hint_columns = [
            "type",
            "transaction_type",
            "trans_type",
            "transaction",
            "dr/cr",
            "debit/credit",
            "activity",
        ]

        # Date parsing patterns
        self.date_formats = [
            "%m/%d/%Y",  # 12/31/2023
            "%m/%d/%y",  # 12/31/23
            "%Y-%m-%d",  # 2023-12-31
            "%d/%m/%Y",  # 31/12/2023
            "%Y/%m/%d",  # 2023/12/31
            "%m-%d-%Y",  # 12-31-2023
            "%d-%m-%Y",  # 31-12-2023
            "%d %b %Y",  # 31 Jan 2025
            "%d %B %Y",  # 31 January 2025
        ]

    def parse_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a CSV financial statement.

        Args:
            file_path: Path to CSV file

        Returns:
            List[Dict[str, Any]]: Extracted transaction data

        Security: Uses secure file validation and local processing only.
        """
        try:
            # Validate file first
            validated_path = self.secure_handler.validate_file_path(file_path)
            self.logger.info(f"Parsing CSV file: {validated_path}")

            # Detect encoding and delimiter
            encoding, delimiter = self._detect_csv_format(validated_path)

            # Read and parse CSV data
            df = pd.read_csv(
                validated_path,
                encoding=encoding,
                delimiter=delimiter,
                low_memory=False,
                nrows=10000,  # Limit rows for security
            )

            # Validate CSV content for security
            if not self._validate_csv_content(df):
                raise ValueError("CSV content validation failed")

            # Detect column mapping
            column_mapping = self._detect_columns(df)
            if not column_mapping:
                raise ValueError("Unable to detect required columns")

            # Parse transactions
            transactions = self._parse_transactions(df, column_mapping)

            self.logger.info(f"Parsed {len(transactions)} transactions from CSV")
            return transactions

        except Exception as e:
            self.logger.error(f"CSV parsing failed: {e}")
            return []

    def _detect_csv_format(self, file_path: Path) -> Tuple[str, str]:
        """
        Detect CSV encoding and delimiter.

        Args:
            file_path: Path to CSV file

        Returns:
            Tuple[str, str]: (encoding, delimiter)

        Security: Limits sample size to prevent resource exhaustion.
        """
        encoding = "utf-8"
        delimiter = ","

        try:
            # Try to detect encoding
            import chardet

            with open(file_path, "rb") as f:
                sample = f.read(8192)  # Read small sample for detection
                detected = chardet.detect(sample)
                if detected["encoding"] and detected["confidence"] > 0.7:
                    encoding = detected["encoding"]
        except ImportError:
            # chardet not available, use default
            pass
        except Exception as e:
            self.logger.warning(f"Encoding detection failed: {e}")

        try:
            # Detect delimiter by testing common options
            with open(file_path, "r", encoding=encoding) as f:
                sample_lines = [f.readline() for _ in range(5)]
                sample = "\n".join(sample_lines)

                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample, delimiters=",;\t|").delimiter

        except Exception as e:
            self.logger.warning(f"Delimiter detection failed: {e}")

        return encoding, delimiter

    def _validate_csv_content(self, df: pd.DataFrame) -> bool:
        """
        Validate CSV content for security issues.

        Args:
            df: Pandas DataFrame

        Returns:
            bool: True if content is safe

        Security: Checks for CSV injection patterns and malicious content.
        """
        try:
            # Check DataFrame size
            if len(df) > 50000 or len(df.columns) > 100:
                self.logger.warning("CSV file too large")
                return False

            # Check for CSV injection patterns
            dangerous_patterns = [
                r"^\s*[=@+\-]",  # Formula injection patterns
                r"<script.*?>",  # Script injection
                r"javascript:",  # JavaScript URLs
                r"data:.*base64",  # Data URLs
            ]

            for column in df.columns:
                if df[column].dtype == "object":  # String columns
                    for pattern in dangerous_patterns:
                        if (
                            df[column]
                            .astype(str)
                            .str.contains(pattern, regex=True, na=False)
                            .any()
                        ):
                            self.logger.warning(
                                f"Potentially dangerous content in column {column}"
                            )
                            return False

            return True

        except Exception as e:
            self.logger.error(f"CSV validation failed: {e}")
            return False

    def _detect_columns(self, df: pd.DataFrame) -> Optional[Dict[str, str]]:
        """
        Detect column mapping for financial data.

        Args:
            df: Pandas DataFrame

        Returns:
            Optional[Dict[str, str]]: Column mapping or None
        """
        columns = [col.lower().strip() for col in df.columns]
        mapping: Dict[str, str] = {}

        # Find date column
        date_col = None
        for col_name in columns:
            if any(date_pattern in col_name for date_pattern in self.date_columns):
                date_col = df.columns[columns.index(col_name)]
                break

        if not date_col:
            # Try to find by data pattern
            for col in df.columns:
                if self._looks_like_date_column(df[col]):
                    date_col = col
                    break

        if not date_col:
            self.logger.error("Could not find date column")
            return None

        mapping["date"] = date_col

        # Find description column
        desc_col = None
        for col_name in columns:
            if any(
                desc_pattern in col_name for desc_pattern in self.description_columns
            ):
                desc_col = df.columns[columns.index(col_name)]
                break

        if not desc_col:
            # Use the first string column that's not the date
            for col in df.columns:
                if col != date_col and df[col].dtype == "object":
                    desc_col = col
                    break

        if not desc_col:
            self.logger.error("Could not find description column")
            return None

        mapping["description"] = desc_col

        # Optional: transaction type hint column
        type_col = None
        for col_name in columns:
            if any(t in col_name for t in self.type_hint_columns):
                type_col = df.columns[columns.index(col_name)]
                break
        if type_col:
            mapping["type_col"] = type_col

        # Find amount columns
        amount_col = None
        debit_col = None
        credit_col = None

        # Look for combined amount column first
        for col_name in columns:
            if any(
                amount_pattern in col_name for amount_pattern in self.amount_columns
            ):
                amount_col = df.columns[columns.index(col_name)]
                break

        # Look for separate debit/credit columns
        for col_name in columns:
            if any(debit_pattern in col_name for debit_pattern in self.debit_columns):
                debit_col = df.columns[columns.index(col_name)]
            if any(
                credit_pattern in col_name for credit_pattern in self.credit_columns
            ):
                credit_col = df.columns[columns.index(col_name)]

        # Use combined amount or separate debit/credit
        if amount_col:
            mapping["amount"] = amount_col
        elif debit_col and credit_col:
            mapping["debit"] = debit_col
            mapping["credit"] = credit_col
        else:
            # Try to find by data pattern
            for col in df.columns:
                if col not in [date_col, desc_col] and self._looks_like_amount_column(
                    df[col]
                ):
                    mapping["amount"] = col
                    break

        if "amount" not in mapping and (
            "debit" not in mapping or "credit" not in mapping
        ):
            self.logger.error("Could not find amount column(s)")
            return None

        self.logger.info(f"Detected column mapping: {mapping}")
        return mapping

    def _looks_like_date_column(self, series: pd.Series) -> bool:
        """Check if a series contains date-like data."""
        try:
            sample = series.dropna().head(10)
            if len(sample) == 0:
                return False

            date_count = 0
            for value in sample:
                if self._parse_date_value(str(value)):
                    date_count += 1

            return date_count >= len(sample) * 0.8  # 80% look like dates

        except Exception:
            return False

    def _looks_like_amount_column(self, series: pd.Series) -> bool:
        """Check if a series contains amount-like data."""
        try:
            sample = series.dropna().head(10)
            if len(sample) == 0:
                return False

            numeric_count = 0
            for value in sample:
                if self._parse_amount_value(str(value)) is not None:
                    numeric_count += 1

            return numeric_count >= len(sample) * 0.8  # 80% look like amounts

        except Exception:
            return False

    def _parse_transactions(
        self, df: pd.DataFrame, column_mapping: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        Parse transactions from DataFrame using column mapping.

        Args:
            df: Pandas DataFrame
            column_mapping: Column mapping dictionary

        Returns:
            List[Dict[str, Any]]: Parsed transactions
        """
        transactions = []

        for index, row in df.iterrows():
            try:
                transaction = self._parse_transaction_row(row, column_mapping)
                if transaction:
                    transactions.append(transaction)
            except Exception as e:
                self.logger.debug(f"Failed to parse row {index}: {e}")
                continue

        return transactions

    def _parse_transaction_row(
        self, row: pd.Series, mapping: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a single transaction row.

        Args:
            row: Pandas Series (DataFrame row)
            mapping: Column mapping

        Returns:
            Optional[Dict[str, Any]]: Transaction data or None
        """
        try:
            # Parse date
            date_value = row[mapping["date"]]
            transaction_date = self._parse_date_value(date_value)
            if not transaction_date:
                return None

            # Parse description
            description = str(row[mapping["description"]]).strip()
            if not description or description.lower() in ["nan", "none", ""]:
                description = "Unknown Transaction"

            # Optional type hint value
            type_hint_val = None
            if "type_col" in mapping:
                try:
                    type_hint_val = (
                        str(row.get(mapping["type_col"], "")).strip().lower()
                    )
                except Exception:
                    type_hint_val = None

            # Parse amount
            if "amount" in mapping:
                # Single amount column
                amount_value = row[mapping["amount"]]
                amount = self._parse_amount_value(amount_value)
                if amount is None:
                    return None

                # Determine transaction type: first by explicit type hint,
                # otherwise fall back to sign convention
                trans_type = None
                if type_hint_val:
                    if type_hint_val in [
                        "credit",
                        "payment",
                        "pmt",
                        "refund",
                        "reversal",
                        "adjustment",
                    ]:
                        trans_type = "credit"
                    elif type_hint_val in [
                        "debit",
                        "sale",
                        "purchase",
                        "charge",
                        "fee",
                        "cash advance",
                    ]:
                        trans_type = "debit"

                if not trans_type:
                    trans_type = "debit" if amount < 0 else "credit"

                amount = abs(amount)

            else:
                # Separate debit/credit columns
                debit_value = row.get(mapping.get("debit", ""), 0) or 0
                credit_value = row.get(mapping.get("credit", ""), 0) or 0

                debit_amount = self._parse_amount_value(debit_value) or 0
                credit_amount = self._parse_amount_value(credit_value) or 0

                if debit_amount > 0 and debit_amount >= credit_amount:
                    amount = debit_amount
                    trans_type = "debit"
                elif credit_amount > 0:
                    amount = credit_amount
                    trans_type = "credit"
                else:
                    # As a fallback, use type hint with a generic amount if present
                    if type_hint_val in [
                        "credit",
                        "payment",
                        "pmt",
                        "refund",
                        "reversal",
                        "adjustment",
                    ]:
                        amt_guess = debit_amount or credit_amount
                        if amt_guess <= 0:
                            return None
                        amount = amt_guess
                        trans_type = "credit"
                    elif type_hint_val in [
                        "debit",
                        "sale",
                        "purchase",
                        "charge",
                        "fee",
                        "cash advance",
                    ]:
                        amt_guess = debit_amount or credit_amount
                        if amt_guess <= 0:
                            return None
                        amount = amt_guess
                        trans_type = "debit"
                    else:
                        return None  # No valid amount/type found

            return {
                "transaction_date": transaction_date,
                "description": description,
                "amount": amount,
                "transaction_type": trans_type,
                "category_id": None,  # Will be set by categorizer
                "subcategory": None,
                "notes": None,
                "file_hash": None,  # Will be set by caller
            }

        except Exception as e:
            self.logger.debug(f"Failed to parse transaction row: {e}")
            return None

    def _parse_date_value(self, date_value: Any) -> Optional[datetime]:
        """
        Parse date value into datetime object.

        Args:
            date_value: Date value to parse

        Returns:
            Optional[datetime]: Parsed datetime or None
        """
        if pd.isna(date_value):
            return None

        date_str = str(date_value).strip()

        # Try pandas date parsing first
        try:
            parsed_date = pd.to_datetime(date_str, infer_datetime_format=True)
            return parsed_date.to_pydatetime()
        except Exception:
            pass

        # Try manual format parsing
        for fmt in self.date_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        return None

    def _parse_amount_value(self, amount_value: Any) -> Optional[float]:
        """
        Parse amount value into float.

        Args:
            amount_value: Amount value to parse

        Returns:
            Optional[float]: Parsed amount or None
        """
        if pd.isna(amount_value):
            return None

        try:
            # Convert to string and clean
            amount_str = str(amount_value).strip()

            # Detect parentheses indicating negative amounts, e.g., ($123.45)
            is_paren_negative = False
            if amount_str.startswith("(") and amount_str.endswith(")"):
                is_paren_negative = True
                amount_str = amount_str[1:-1]

            # Remove currency symbols and commas
            clean_amount = re.sub(r"[^\d\.\-\+]", "", amount_str)

            if clean_amount:
                val = float(clean_amount)
                if is_paren_negative and val > 0:
                    val = -val
                return val

        except (ValueError, TypeError):
            pass

        return None
