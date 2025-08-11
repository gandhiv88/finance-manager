"""
PDF Parser - Extract financial data from PDF statements

This module handles parsing of PDF financial statements using pdfplumber
and OCR capabilities for scanned documents.

Security Rationale:
- Processes files locally only
- No external API calls
- Secure temporary file handling
- Input validation for malicious PDFs
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import re
from datetime import datetime
import pdfplumber
import pytesseract
from PIL import Image
import os

from security.file_handler import SecureFileHandler


class PDFParser:
    """
    Parse financial data from PDF statements.

    Security: All processing happens locally using pdfplumber and Tesseract OCR.
    No data is transmitted to external services.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.secure_handler = SecureFileHandler()

        # Common patterns for financial data extraction
        self.amount_pattern = re.compile(
            r"[\$\-]?((?:\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{2})?)"
        )
        self.parentheses_amount_pattern = re.compile(r"\((\d{1,3}(?:,\d{3})*\.\d{2})\)")
        self.date_patterns = [
            re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b"),  # MM/DD/YYYY
            re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{2})\b"),  # MM/DD/YY
            re.compile(r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b"),  # YYYY-MM-DD
            re.compile(
                r"\b([A-Z][a-z]{2,9})\s+(\d{1,2}),?\s+(\d{4})\b"
            ),  # Month DD YYYY
            re.compile(
                r"\b(\d{1,2})\s+([A-Z][a-z]{2,9}),?\s+(\d{4})\b"
            ),  # DD Month YYYY
            re.compile(
                r"\b(\d{1,2})-([A-Za-z]{3})-(\d{2,4})\b"
            ),  # DD-Mon-YY or DD-Mon-YYYY (new)
        ]
        self.hyphen_month_pattern = re.compile(r"\b(\d{1,2})-([A-Za-z]{3})-(\d{2,4})\b")
        self.month_map = {
            "jan": 1,
            "january": 1,
            "feb": 2,
            "february": 2,
            "mar": 3,
            "march": 3,
            "apr": 4,
            "april": 4,
            "may": 5,
            "jun": 6,
            "june": 6,
            "jul": 7,
            "july": 7,
            "aug": 8,
            "august": 8,
            "sep": 9,
            "sept": 9,
            "september": 9,
            "oct": 10,
            "october": 10,
            "nov": 11,
            "november": 11,
            "dec": 12,
            "december": 12,
        }
        self.debug = os.environ.get("FINANCE_DEBUG", "").lower() == "true"

    def parse_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a PDF financial statement.

        Args:
            file_path: Path to PDF file

        Returns:
            List[Dict[str, Any]]: Extracted transaction data

        Security: Uses secure file validation and local processing only.
        """
        try:
            # Validate file first
            validated_path = self.secure_handler.validate_file_path(file_path)
            self.logger.info(f"Parsing PDF file: {validated_path}")

            transactions = []
            file_hash = self.secure_handler.calculate_file_hash(validated_path)

            # Try text extraction first
            text_transactions = self._extract_text_data(validated_path)
            if text_transactions:
                # Attach file hash
                for t in text_transactions:
                    t["file_hash"] = file_hash
                transactions.extend(text_transactions)
                self.logger.info(
                    f"Extracted {len(text_transactions)} transactions from text"
                )
            else:
                if self.debug:
                    self.logger.debug(
                        "No text-based transactions found. Dumping sample text excerpt."
                    )

            # If no text data or insufficient data, try OCR
            if len(transactions) == 0:
                ocr_transactions = self._extract_ocr_data(validated_path)
                if ocr_transactions:
                    for t in ocr_transactions:
                        t["file_hash"] = file_hash
                    transactions.extend(ocr_transactions)
                    self.logger.info(
                        f"Extracted {len(ocr_transactions)} transactions from OCR"
                    )
                elif self.debug:
                    self.logger.debug("No OCR transactions found either.")

            return transactions

        except Exception as e:
            self.logger.error(f"PDF parsing failed: {e}")
            return []

    def _extract_text_data(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Extract text data from PDF using pdfplumber.

        Args:
            file_path: Path to PDF file

        Returns:
            List[Dict[str, Any]]: Extracted transactions

        Security: Uses pdfplumber for local text extraction only.
        """
        transactions = []

        try:
            with pdfplumber.open(file_path) as pdf:
                all_text = ""

                # Extract text from all pages
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        all_text += page_text + "\n"

                # Parse transactions from text
                transactions = self._parse_transaction_text(all_text)

                # Try table extraction as well
                table_transactions = self._extract_table_data(pdf)
                if table_transactions:
                    transactions.extend(table_transactions)

                # After collecting all text, optionally log excerpt in debug
                if self.debug:
                    sample = all_text[:500].replace("\n", " | ")
                    self.logger.debug(f"Sample extracted text: {sample}")

        except Exception as e:
            self.logger.error(f"Text extraction failed: {e}")
            return []

        return transactions

    def _extract_table_data(self, pdf) -> List[Dict[str, Any]]:
        """
        Extract tabular data from PDF.

        Args:
            pdf: pdfplumber PDF object

        Returns:
            List[Dict[str, Any]]: Extracted transactions from tables
        """
        transactions = []

        try:
            for page in pdf.pages:
                tables = page.extract_tables()

                for table in tables:
                    if not table or len(table) < 2:  # Need header + data rows
                        continue

                    # Identify columns by header patterns
                    header = table[0] if table[0] else []
                    date_col = self._find_column_index(
                        header, ["date", "transaction date", "posted"]
                    )
                    desc_col = self._find_column_index(
                        header, ["description", "merchant", "payee"]
                    )
                    amount_col = self._find_column_index(
                        header, ["amount", "total", "debit", "credit"]
                    )

                    # Process data rows
                    for row in table[1:]:
                        if not row or len(row) < max(
                            date_col or 0, desc_col or 0, amount_col or 0
                        ):
                            continue

                        transaction = self._create_transaction_from_row(
                            row, date_col, desc_col, amount_col
                        )

                        if transaction:
                            transactions.append(transaction)

        except Exception as e:
            self.logger.error(f"Table extraction failed: {e}")

        return transactions

    def _extract_ocr_data(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Extract data using OCR for scanned PDFs.

        Args:
            file_path: Path to PDF file

        Returns:
            List[Dict[str, Any]]: Extracted transactions

        Security: Uses local Tesseract OCR, no cloud services.
        """
        transactions = []

        try:
            with pdfplumber.open(file_path) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    # Convert page to image
                    img = page.to_image(
                        resolution=300
                    )  # High resolution for better OCR
                    pil_image = img.original

                    # Use secure temp file for image processing
                    with self.secure_handler.secure_temp_file(
                        suffix=".png"
                    ) as temp_path:
                        pil_image.save(temp_path)

                        # Perform OCR
                        ocr_text = pytesseract.image_to_string(
                            Image.open(temp_path),
                            config="--psm 6",  # Uniform block of text
                        )

                        # Parse OCR text for transactions
                        page_transactions = self._parse_transaction_text(ocr_text)
                        transactions.extend(page_transactions)

        except Exception as e:
            self.logger.error(f"OCR extraction failed: {e}")

        return transactions

    def _parse_transaction_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Parse transaction data from extracted text.

        Args:
            text: Extracted text content

        Returns:
            List[Dict[str, Any]]: Parsed transactions
        """
        transactions = []
        lines = text.split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for transaction patterns
            transaction = self._extract_transaction_from_line(line)
            if transaction:
                transactions.append(transaction)

        if self.debug and not transactions:
            self.logger.debug("No transactions extracted from line-based parsing.")

        return transactions

    def _extract_transaction_from_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Extract transaction data from a single line of text.

        Args:
            line: Single line of text

        Returns:
            Optional[Dict[str, Any]]: Transaction data or None
        """
        try:
            transaction_date = None
            matched_date_text = None
            for pattern in self.date_patterns:
                match = pattern.search(line)
                if match:
                    try:
                        groups = match.groups()
                        matched_date_text = match.group(0)
                        if pattern.pattern.startswith(
                            "\\b(\\d{1,2})/(\\d{1,2})/(\\d{4})"
                        ):
                            transaction_date = datetime(
                                int(groups[2]), int(groups[0]), int(groups[1])
                            )
                        elif pattern.pattern.startswith(
                            "\\b(\\d{1,2})/(\\d{1,2})/(\\d{2})"
                        ):
                            year = 2000 + int(groups[2])
                            transaction_date = datetime(
                                year, int(groups[0]), int(groups[1])
                            )
                        elif pattern.pattern.startswith(
                            "\\b(\\d{4})-(\\d{1,2})-(\\d{1,2})"
                        ):
                            transaction_date = datetime(
                                int(groups[0]), int(groups[1]), int(groups[2])
                            )
                        else:
                            # Month name patterns or DD-Mon-YY
                            if pattern is self.date_patterns[
                                -1
                            ] or self.hyphen_month_pattern.match(
                                matched_date_text or ""
                            ):
                                # Hyphen format DD-Mon-YY/ YYYY
                                day = int(groups[0])
                                month = self.month_map.get(groups[1].lower(), None)
                                if month:
                                    year_val = int(groups[2])
                                    if year_val < 100:  # two-digit year
                                        year_val += 2000
                                    transaction_date = datetime(year_val, month, day)
                            elif groups[0].isalpha():  # Month DD YYYY
                                month = self.month_map.get(groups[0].lower(), None)
                                if month:
                                    transaction_date = datetime(
                                        int(groups[2]), month, int(groups[1])
                                    )
                            else:  # DD Month YYYY
                                month = self.month_map.get(groups[1].lower(), None)
                                if month:
                                    year_val = int(groups[2])
                                    if year_val < 100:
                                        year_val += 2000
                                    transaction_date = datetime(
                                        year_val, month, int(groups[0])
                                    )
                        if transaction_date:
                            break
                    except ValueError:
                        continue

            if not transaction_date:
                return None

            paren_match = self.parentheses_amount_pattern.search(line)
            negative_by_parentheses = False
            if paren_match:
                amount_str = paren_match.group(1).replace(",", "")
                negative_by_parentheses = True
            else:
                amount_matches = self.amount_pattern.findall(line)
                if not amount_matches:
                    return None
                amount_str = amount_matches[-1].replace(",", "")
            try:
                amount = float(amount_str)
            except ValueError:
                return None
            if negative_by_parentheses:
                amount = -amount

            transaction_type = (
                "debit"
                if negative_by_parentheses or "-" in line or "debit" in line.lower()
                else "credit"
            )

            description = self._extract_description(line, matched_date_text, amount_str)

            return {
                "transaction_date": transaction_date.date(),
                "description": description,
                "amount": abs(amount),
                "transaction_type": transaction_type,
                "category_id": None,
                "subcategory": None,
                "notes": None,
                "file_hash": None,
            }

        except Exception as e:
            self.logger.debug(f"Failed to parse line '{line}': {e}")
            return None

    def _extract_description(
        self, line: str, original_date_token: Optional[str], amount_str: str
    ) -> str:
        """Extract transaction description from line removing date & amount tokens."""
        working = line
        if original_date_token:
            working = working.replace(original_date_token, " ")
        # Remove amount occurrences (last amount already captured)
        working = working.replace(amount_str, " ")
        # Remove currency symbols and stray hyphens at ends
        working = re.sub(r"[$]", " ", working)
        working = re.sub(r"\s+", " ", working).strip()
        # Remove leading/trailing punctuation or separators
        working = re.sub(r"^[\-*\s]+|[\-*\s]+$", "", working)
        return working or "Unknown Transaction"

    def _find_column_index(
        self, headers: List[str], keywords: List[str]
    ) -> Optional[int]:
        """
        Find column index by matching keywords in headers.

        Args:
            headers: Table headers
            keywords: Keywords to match

        Returns:
            Optional[int]: Column index or None
        """
        for i, header in enumerate(headers):
            if header and any(
                keyword.lower() in header.lower() for keyword in keywords
            ):
                return i
        return None

    def _create_transaction_from_row(
        self,
        row: List[str],
        date_col: Optional[int],
        desc_col: Optional[int],
        amount_col: Optional[int],
    ) -> Optional[Dict[str, Any]]:
        """
        Create transaction dictionary from table row.

        Args:
            row: Table row data
            date_col: Date column index
            desc_col: Description column index
            amount_col: Amount column index

        Returns:
            Optional[Dict[str, Any]]: Transaction data or None
        """
        try:
            if date_col is None or desc_col is None or amount_col is None:
                return None

            # Parse date
            date_str = row[date_col] if date_col < len(row) else ""
            transaction_date = self._parse_date_string(date_str)
            if not transaction_date:
                return None

            # Parse amount
            amount_str = row[amount_col] if amount_col < len(row) else ""
            amount = self._parse_amount_string(amount_str)
            if amount is None:
                return None

            # Get description
            description = row[desc_col] if desc_col < len(row) else "Unknown"

            # Determine transaction type
            transaction_type = "debit" if amount < 0 else "credit"

            return {
                "transaction_date": transaction_date,
                "description": description.strip(),
                "amount": abs(amount),
                "transaction_type": transaction_type,
                "category_id": None,
                "subcategory": None,
                "notes": None,
                "file_hash": None,  # Will be set by caller
            }

        except Exception as e:
            self.logger.debug(f"Failed to create transaction from row: {e}")
            return None

    def _parse_date_string(self, date_str: str) -> Optional[datetime]:
        """Parse date string into datetime object (extended for DD-Mon-YY)."""
        # Direct hyphen check first
        hyphen = self.hyphen_month_pattern.match(date_str.strip())
        if hyphen:
            day = int(hyphen.group(1))
            mon_txt = hyphen.group(2).lower()
            year_val = int(hyphen.group(3))
            if year_val < 100:
                year_val += 2000
            month = self.month_map.get(mon_txt, None)
            if month:
                try:
                    return datetime(year_val, month, day)
                except ValueError:
                    return None
        # Fallback to existing patterns
        for pattern in self.date_patterns:
            match = pattern.search(date_str)
            if match:
                try:
                    groups = match.groups()
                    if pattern is self.date_patterns[0]:  # MM/DD/YYYY
                        return datetime(int(groups[2]), int(groups[0]), int(groups[1]))
                    if pattern is self.date_patterns[1]:  # MM/DD/YY
                        return datetime(
                            2000 + int(groups[2]), int(groups[0]), int(groups[1])
                        )
                    if pattern is self.date_patterns[2]:  # YYYY-MM-DD
                        return datetime(int(groups[0]), int(groups[1]), int(groups[2]))
                    if pattern is self.date_patterns[3]:  # Month DD YYYY
                        month = self.month_map.get(groups[0].lower(), None)
                        if month:
                            return datetime(int(groups[2]), month, int(groups[1]))
                    if pattern is self.date_patterns[4]:  # DD Month YYYY
                        month = self.month_map.get(groups[1].lower(), None)
                        if month:
                            return datetime(int(groups[2]), month, int(groups[0]))
                    if (
                        pattern is self.date_patterns[5]
                    ):  # DD-Mon-YY/ YYYY (handled above but kept for completeness)
                        day = int(groups[0])
                        month = self.month_map.get(groups[1].lower(), None)
                        if month:
                            year_val = int(groups[2])
                            if year_val < 100:
                                year_val += 2000
                            return datetime(year_val, month, day)
                except ValueError:
                    continue
        return None

    def _parse_amount_string(self, amount_str: str) -> Optional[float]:
        """Parse amount string into float."""
        try:
            # Clean amount string
            clean_amount = re.sub(r"[^\d\.\-]", "", amount_str)
            if clean_amount:
                return float(clean_amount)
        except ValueError:
            pass
        return None
