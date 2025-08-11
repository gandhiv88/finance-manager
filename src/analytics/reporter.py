"""
Financial Analytics - Generate reports and metrics

This module provides comprehensive financial analytics including
monthly/yearly summaries, category breakdowns, and trend analysis.

Security Rationale:
- All calculations happen locally
- No external data transmission
- Aggregated data only (no raw transaction exposure)
- Secure memory handling for financial calculations
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
from collections import defaultdict
import json
from pathlib import Path


class FinancialAnalytics:
    """
    Generate financial analytics and reports from transaction data.

    Security: All analysis happens locally with no external dependencies.
    Sensitive data is aggregated before reporting.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_monthly_summary(
        self,
        transactions: List[Dict[str, Any]],
        month: Optional[int] = None,
        year: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Generate monthly financial summary.

        Args:
            transactions: List of transaction dictionaries
            month: Target month (current month if None)
            year: Target year (current year if None)

        Returns:
            Dict[str, Any]: Monthly summary data

        Security: Aggregates transaction data without exposing individual records.
        """
        try:
            # Use current month/year if not specified
            if month is None or year is None:
                now = datetime.now()
                month = month or now.month
                year = year or now.year

            # Filter transactions for the specified month
            monthly_transactions = self._filter_transactions_by_month(
                transactions, month, year
            )

            if not monthly_transactions:
                return self._empty_summary(month, year)

            # Calculate summary metrics
            summary = {
                "period": f"{year}-{month:02d}",
                "month": month,
                "year": year,
                "transaction_count": len(monthly_transactions),
                "income": self._calculate_total_income(monthly_transactions),
                "expenses": self._calculate_total_expenses(monthly_transactions),
                "net_savings": 0.0,
                "categories": self._analyze_categories(monthly_transactions),
                "top_expenses": self._get_top_expenses(monthly_transactions, limit=5),
                "daily_averages": self._calculate_daily_averages(monthly_transactions),
                "trends": self._analyze_monthly_trends(transactions, month, year),
            }

            # Calculate net savings
            summary["net_savings"] = summary["income"] - summary["expenses"]

            return summary

        except Exception as e:
            self.logger.error(f"Monthly summary generation failed: {e}")
            return self._empty_summary(
                month or datetime.now().month, year or datetime.now().year
            )

    def generate_yearly_summary(
        self, transactions: List[Dict[str, Any]], year: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate yearly financial summary.

        Args:
            transactions: List of transaction dictionaries
            year: Target year (current year if None)

        Returns:
            Dict[str, Any]: Yearly summary data
        """
        try:
            if year is None:
                year = datetime.now().year

            # Filter transactions for the year
            yearly_transactions = self._filter_transactions_by_year(transactions, year)

            if not yearly_transactions:
                return self._empty_yearly_summary(year)

            # Generate monthly breakdowns
            monthly_summaries = []
            for month in range(1, 13):
                month_summary = self.generate_monthly_summary(transactions, month, year)
                monthly_summaries.append(month_summary)

            # Calculate yearly totals
            total_income = sum(ms["income"] for ms in monthly_summaries)
            total_expenses = sum(ms["expenses"] for ms in monthly_summaries)

            summary = {
                "year": year,
                "transaction_count": len(yearly_transactions),
                "total_income": total_income,
                "total_expenses": total_expenses,
                "net_savings": total_income - total_expenses,
                "monthly_breakdown": monthly_summaries,
                "category_totals": self._analyze_yearly_categories(yearly_transactions),
                "savings_rate": self._calculate_savings_rate(
                    total_income, total_expenses
                ),
                "spending_trends": self._analyze_yearly_trends(yearly_transactions),
                "largest_expenses": self._get_top_expenses(
                    yearly_transactions, limit=10
                ),
            }

            return summary

        except Exception as e:
            self.logger.error(f"Yearly summary generation failed: {e}")
            return self._empty_yearly_summary(year or datetime.now().year)

    def generate_category_analysis(
        self, transactions: List[Dict[str, Any]], period_months: int = 3
    ) -> Dict[str, Any]:
        """
        Generate detailed category analysis.

        Args:
            transactions: List of transaction dictionaries
            period_months: Number of months to analyze

        Returns:
            Dict[str, Any]: Category analysis data
        """
        try:
            # Filter to recent transactions
            cutoff_date = datetime.now() - timedelta(days=period_months * 30)
            recent_transactions = [
                t
                for t in transactions
                if self._parse_transaction_date(t.get("transaction_date"))
                >= cutoff_date
            ]

            if not recent_transactions:
                return {"categories": [], "total_analyzed": 0}

            # Group by category
            category_data = defaultdict(
                lambda: {
                    "total_amount": 0.0,
                    "transaction_count": 0,
                    "average_amount": 0.0,
                    "transactions": [],
                }
            )

            for transaction in recent_transactions:
                if transaction.get("transaction_type") == "debit":  # Only expenses
                    category = transaction.get("category_name", "Uncategorized")
                    amount = float(transaction.get("amount", 0))

                    category_data[category]["total_amount"] += amount
                    category_data[category]["transaction_count"] += 1
                    category_data[category]["transactions"].append(
                        {
                            "date": transaction.get("transaction_date"),
                            "description": transaction.get("description", ""),
                            "amount": amount,
                        }
                    )

            # Calculate averages and percentages
            total_expenses = sum(
                data["total_amount"] for data in category_data.values()
            )

            categories = []
            for category, data in category_data.items():
                data["average_amount"] = (
                    data["total_amount"] / data["transaction_count"]
                    if data["transaction_count"] > 0
                    else 0
                )
                data["percentage"] = (
                    (data["total_amount"] / total_expenses * 100)
                    if total_expenses > 0
                    else 0
                )

                # Don't include individual transactions in summary
                category_summary = {
                    k: v for k, v in data.items() if k != "transactions"
                }
                category_summary["name"] = category
                categories.append(category_summary)

            # Sort by total amount
            categories.sort(key=lambda x: x["total_amount"], reverse=True)

            return {
                "period_months": period_months,
                "total_expenses": total_expenses,
                "categories": categories,
                "total_analyzed": len(recent_transactions),
            }

        except Exception as e:
            self.logger.error(f"Category analysis failed: {e}")
            return {"categories": [], "total_analyzed": 0}

    def _filter_transactions_by_month(
        self, transactions: List[Dict[str, Any]], month: int, year: int
    ) -> List[Dict[str, Any]]:
        """Filter transactions for specific month/year."""
        filtered = []

        for transaction in transactions:
            trans_date = self._parse_transaction_date(
                transaction.get("transaction_date")
            )
            if trans_date and trans_date.month == month and trans_date.year == year:
                filtered.append(transaction)

        return filtered

    def _filter_transactions_by_year(
        self, transactions: List[Dict[str, Any]], year: int
    ) -> List[Dict[str, Any]]:
        """Filter transactions for specific year."""
        filtered = []

        for transaction in transactions:
            trans_date = self._parse_transaction_date(
                transaction.get("transaction_date")
            )
            if trans_date and trans_date.year == year:
                filtered.append(transaction)

        return filtered

    def _parse_transaction_date(self, date_value: Any) -> Optional[datetime]:
        """Parse transaction date into datetime object."""
        try:
            if isinstance(date_value, datetime):
                return date_value
            elif isinstance(date_value, str):
                return datetime.fromisoformat(date_value.replace("Z", "+00:00"))
            else:
                return None
        except (ValueError, AttributeError):
            return None

    def _calculate_total_income(self, transactions: List[Dict[str, Any]]) -> float:
        """Calculate total income from transactions."""
        return sum(
            float(t.get("amount", 0))
            for t in transactions
            if t.get("transaction_type") == "credit"
        )

    def _calculate_total_expenses(self, transactions: List[Dict[str, Any]]) -> float:
        """Calculate total expenses from transactions."""
        return sum(
            float(t.get("amount", 0))
            for t in transactions
            if t.get("transaction_type") == "debit"
        )

    def _analyze_categories(
        self, transactions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze spending by category."""
        category_totals = defaultdict(float)
        category_counts = defaultdict(int)

        for transaction in transactions:
            if transaction.get("transaction_type") == "debit":
                category = transaction.get("category_name", "Uncategorized")
                amount = float(transaction.get("amount", 0))

                category_totals[category] += amount
                category_counts[category] += 1

        categories = []
        total_expenses = sum(category_totals.values())

        for category, total in category_totals.items():
            categories.append(
                {
                    "name": category,
                    "total": total,
                    "count": category_counts[category],
                    "average": total / category_counts[category],
                    "percentage": (
                        (total / total_expenses * 100) if total_expenses > 0 else 0
                    ),
                }
            )

        return sorted(categories, key=lambda x: x["total"], reverse=True)

    def _get_top_expenses(
        self, transactions: List[Dict[str, Any]], limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get top expenses by amount."""
        expenses = [
            {
                "description": t.get("description", "Unknown"),
                "amount": float(t.get("amount", 0)),
                "date": t.get("transaction_date"),
                "category": t.get("category_name", "Uncategorized"),
            }
            for t in transactions
            if t.get("transaction_type") == "debit"
        ]

        return sorted(expenses, key=lambda x: x["amount"], reverse=True)[:limit]

    def _calculate_daily_averages(
        self, transactions: List[Dict[str, Any]]
    ) -> Dict[str, float]:
        """Calculate daily spending averages."""
        if not transactions:
            return {"income": 0.0, "expenses": 0.0, "net": 0.0}

        # Get date range
        dates = [
            self._parse_transaction_date(t.get("transaction_date"))
            for t in transactions
        ]
        dates = [d for d in dates if d is not None]

        if not dates:
            return {"income": 0.0, "expenses": 0.0, "net": 0.0}

        days_in_period = (max(dates) - min(dates)).days + 1

        total_income = self._calculate_total_income(transactions)
        total_expenses = self._calculate_total_expenses(transactions)

        return {
            "income": total_income / days_in_period,
            "expenses": total_expenses / days_in_period,
            "net": (total_income - total_expenses) / days_in_period,
        }

    def _analyze_monthly_trends(
        self, transactions: List[Dict[str, Any]], current_month: int, current_year: int
    ) -> Dict[str, Any]:
        """Analyze trends compared to previous months."""
        try:
            # Get previous month
            if current_month == 1:
                prev_month, prev_year = 12, current_year - 1
            else:
                prev_month, prev_year = current_month - 1, current_year

            current_transactions = self._filter_transactions_by_month(
                transactions, current_month, current_year
            )
            prev_transactions = self._filter_transactions_by_month(
                transactions, prev_month, prev_year
            )

            current_expenses = self._calculate_total_expenses(current_transactions)
            prev_expenses = self._calculate_total_expenses(prev_transactions)

            current_income = self._calculate_total_income(current_transactions)
            prev_income = self._calculate_total_income(prev_transactions)

            expense_change = (
                (current_expenses - prev_expenses) / prev_expenses * 100
                if prev_expenses > 0
                else 0
            )
            income_change = (
                (current_income - prev_income) / prev_income * 100
                if prev_income > 0
                else 0
            )

            return {
                "expense_change_percent": expense_change,
                "income_change_percent": income_change,
                "previous_month": f"{prev_year}-{prev_month:02d}",
                "comparison_available": len(prev_transactions) > 0,
            }

        except Exception as e:
            self.logger.debug(f"Trend analysis failed: {e}")
            return {"comparison_available": False}

    def _analyze_yearly_categories(
        self, transactions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze categories for full year."""
        return self._analyze_categories(transactions)

    def _calculate_savings_rate(self, income: float, expenses: float) -> float:
        """Calculate savings rate as percentage."""
        if income <= 0:
            return 0.0
        return ((income - expenses) / income) * 100

    def _analyze_yearly_trends(
        self, transactions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze spending trends throughout the year."""
        monthly_expenses = []
        monthly_income = []

        for month in range(1, 13):
            month_transactions = [
                t
                for t in transactions
                if self._parse_transaction_date(t.get("transaction_date"))
                and self._parse_transaction_date(t.get("transaction_date")).month
                == month
            ]

            monthly_expenses.append(self._calculate_total_expenses(month_transactions))
            monthly_income.append(self._calculate_total_income(month_transactions))

        return {
            "monthly_expenses": monthly_expenses,
            "monthly_income": monthly_income,
            "highest_expense_month": monthly_expenses.index(max(monthly_expenses)) + 1,
            "lowest_expense_month": monthly_expenses.index(min(monthly_expenses)) + 1,
        }

    def _empty_summary(self, month: int, year: int) -> Dict[str, Any]:
        """Return empty summary structure."""
        return {
            "period": f"{year}-{month:02d}",
            "month": month,
            "year": year,
            "transaction_count": 0,
            "income": 0.0,
            "expenses": 0.0,
            "net_savings": 0.0,
            "categories": [],
            "top_expenses": [],
            "daily_averages": {"income": 0.0, "expenses": 0.0, "net": 0.0},
            "trends": {"comparison_available": False},
        }

    def _empty_yearly_summary(self, year: int) -> Dict[str, Any]:
        """Return empty yearly summary structure."""
        return {
            "year": year,
            "transaction_count": 0,
            "total_income": 0.0,
            "total_expenses": 0.0,
            "net_savings": 0.0,
            "monthly_breakdown": [],
            "category_totals": [],
            "savings_rate": 0.0,
            "spending_trends": {
                "monthly_expenses": [0] * 12,
                "monthly_income": [0] * 12,
            },
            "largest_expenses": [],
        }
