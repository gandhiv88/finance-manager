"""
Expense Categorizer - Machine Learning for transaction categorization

This module provides offline machine learning capabilities for automatically
categorizing financial transactions based on description patterns.

Security Rationale:
- All ML processing happens locally
- No external API calls or cloud services
- Models trained and stored locally
- User corrections improve categorization accuracy
"""

import logging
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import re
from collections import defaultdict
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


class ExpenseCategorizer:
    """
    Offline machine learning categorizer for financial transactions.

    Security: All processing and model storage happens locally.
    No external dependencies or network calls.
    """

    def __init__(self, model_dir: Optional[Path] = None):
        self.logger = logging.getLogger(__name__)

        # Default model directory
        if model_dir is None:
            model_dir = Path.home() / ".personalfinance" / "models"
            model_dir.mkdir(parents=True, exist_ok=True)

        self.model_dir = model_dir
        self.model_path = model_dir / "categorizer_model.pkl"
        self.vectorizer_path = model_dir / "vectorizer.pkl"
        self.label_encoder_path = model_dir / "label_encoder.pkl"

        # ML components
        self.model: Optional[Pipeline] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.is_trained = False

        # Default category mapping
        self.default_categories = {
            "food": [
                "restaurant",
                "grocery",
                "food",
                "cafe",
                "pizza",
                "burger",
                "starbucks",
                "mcdonalds",
                "subway",
                "dining",
                "lunch",
                "dinner",
                "breakfast",
            ],
            "transportation": [
                "gas",
                "fuel",
                "uber",
                "lyft",
                "taxi",
                "parking",
                "metro",
                "bus",
                "train",
                "airline",
                "flight",
                "car",
                "auto",
            ],
            "shopping": [
                "amazon",
                "walmart",
                "target",
                "ebay",
                "store",
                "retail",
                "mall",
                "purchase",
                "buy",
                "shop",
                "clothing",
                "electronics",
            ],
            "entertainment": [
                "movie",
                "theater",
                "netflix",
                "spotify",
                "game",
                "concert",
                "entertainment",
                "fun",
                "leisure",
                "hobby",
            ],
            "utilities": [
                "electric",
                "water",
                "gas",
                "internet",
                "phone",
                "cable",
                "utility",
                "bill",
                "service",
                "subscription",
            ],
            "healthcare": [
                "doctor",
                "hospital",
                "pharmacy",
                "medical",
                "dental",
                "health",
                "medicine",
                "clinic",
                "insurance",
                "copay",
            ],
            "income": [
                "salary",
                "payroll",
                "deposit",
                "income",
                "payment",
                "refund",
                "bonus",
                "interest",
                "dividend",
                "transfer",
            ],
        }

        # Load existing model if available
        self._load_model()

    def categorize_transactions(
        self, transactions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Categorize a list of transactions.

        Args:
            transactions: List of transaction dictionaries

        Returns:
            List[Dict[str, Any]]: Transactions with category predictions

        Security: All categorization happens locally using offline models.
        """
        categorized_transactions = []

        for transaction in transactions:
            try:
                category = self._categorize_single_transaction(transaction)
                transaction["predicted_category"] = category
                transaction["category_confidence"] = self._get_prediction_confidence(
                    transaction
                )

                categorized_transactions.append(transaction)

            except Exception as e:
                self.logger.debug(f"Failed to categorize transaction: {e}")
                transaction["predicted_category"] = "unknown"
                transaction["category_confidence"] = 0.0
                categorized_transactions.append(transaction)

        return categorized_transactions

    def _categorize_single_transaction(self, transaction: Dict[str, Any]) -> str:
        """
        Categorize a single transaction.

        Args:
            transaction: Transaction dictionary

        Returns:
            str: Predicted category
        """
        description = transaction.get("description", "").lower().strip()
        amount = transaction.get("amount", 0)
        transaction_type = transaction.get("transaction_type", "debit")

        # Quick rule-based categorization for income
        if transaction_type == "credit" and amount > 500:
            if any(
                keyword in description for keyword in self.default_categories["income"]
            ):
                return "income"

        # Use ML model if trained
        if self.is_trained and self.model and self.label_encoder:
            try:
                features = self._extract_features(transaction)
                prediction = self.model.predict([features])[0]
                category = self.label_encoder.inverse_transform([prediction])[0]
                return category
            except Exception as e:
                self.logger.debug(f"ML prediction failed: {e}")

        # Fallback to rule-based categorization
        return self._rule_based_categorization(description)

    def _rule_based_categorization(self, description: str) -> str:
        """
        Rule-based categorization using keyword matching.

        Args:
            description: Transaction description

        Returns:
            str: Predicted category
        """
        description = description.lower()

        # Score each category based on keyword matches
        category_scores = defaultdict(int)

        for category, keywords in self.default_categories.items():
            for keyword in keywords:
                if keyword in description:
                    # Exact match gets higher score
                    if keyword == description:
                        category_scores[category] += 10
                    else:
                        category_scores[category] += 1

        # Return category with highest score
        if category_scores:
            best_category = max(category_scores, key=category_scores.get)
            return best_category

        return "unknown"

    def _extract_features(self, transaction: Dict[str, Any]) -> str:
        """
        Extract features from transaction for ML model.

        Args:
            transaction: Transaction dictionary

        Returns:
            str: Feature string for TF-IDF vectorization
        """
        description = transaction.get("description", "").lower()
        amount = transaction.get("amount", 0)
        transaction_type = transaction.get("transaction_type", "debit")

        # Clean and normalize description
        clean_desc = re.sub(r"[^\w\s]", " ", description)
        clean_desc = " ".join(clean_desc.split())

        # Add amount-based features
        if amount < 10:
            amount_feature = "small_amount"
        elif amount < 100:
            amount_feature = "medium_amount"
        else:
            amount_feature = "large_amount"

        # Combine features
        features = f"{clean_desc} {transaction_type} {amount_feature}"
        return features

    def train_model(self, training_data: List[Dict[str, Any]]) -> bool:
        """
        Train the ML model with transaction data.

        Args:
            training_data: List of transactions with categories

        Returns:
            bool: True if training successful

        Security: All training happens locally, no external data.
        """
        try:
            if len(training_data) < 10:
                self.logger.warning("Insufficient training data")
                return False

            # Prepare training data
            features = []
            labels = []

            for transaction in training_data:
                if "category" in transaction or "predicted_category" in transaction:
                    feature_text = self._extract_features(transaction)
                    category = transaction.get("category") or transaction.get(
                        "predicted_category"
                    )

                    if feature_text and category and category != "unknown":
                        features.append(feature_text)
                        labels.append(category)

            if len(features) < 5:
                self.logger.warning("Insufficient valid training samples")
                return False

            # Encode labels
            self.label_encoder = LabelEncoder()
            encoded_labels = self.label_encoder.fit_transform(labels)

            # Create and train pipeline
            self.model = Pipeline(
                [
                    (
                        "tfidf",
                        TfidfVectorizer(
                            max_features=1000,
                            stop_words="english",
                            ngram_range=(1, 2),
                            min_df=2,
                        ),
                    ),
                    ("classifier", MultinomialNB(alpha=0.1)),
                ]
            )

            # Train model
            self.model.fit(features, encoded_labels)
            self.is_trained = True

            # Save model
            self._save_model()

            # Log training results
            if len(features) > 10:
                X_train, X_test, y_train, y_test = train_test_split(
                    features, encoded_labels, test_size=0.2, random_state=42
                )

                self.model.fit(X_train, y_train)
                predictions = self.model.predict(X_test)
                accuracy = accuracy_score(y_test, predictions)

                self.logger.info(
                    f"Model trained with {len(features)} samples, accuracy: {accuracy:.2f}"
                )

            return True

        except Exception as e:
            self.logger.error(f"Model training failed: {e}")
            return False

    def add_user_correction(
        self, transaction: Dict[str, Any], correct_category: str
    ) -> bool:
        """
        Add user correction to improve model accuracy.

        Args:
            transaction: Transaction that was corrected
            correct_category: Correct category provided by user

        Returns:
            bool: True if correction was processed

        Security: Corrections are stored locally and used for retraining.
        """
        try:
            # Update transaction with correct category
            transaction["category"] = correct_category
            transaction["user_corrected"] = True

            # Load existing corrections
            corrections_file = self.model_dir / "user_corrections.pkl"
            corrections = []

            if corrections_file.exists():
                with open(corrections_file, "rb") as f:
                    corrections = pickle.load(f)

            # Add new correction
            corrections.append(
                {
                    "transaction": transaction,
                    "correct_category": correct_category,
                    "timestamp": np.datetime64("now"),
                }
            )

            # Save corrections
            with open(corrections_file, "wb") as f:
                pickle.dump(corrections, f)

            # Retrain model if we have enough corrections
            if len(corrections) >= 10:
                training_data = [c["transaction"] for c in corrections]
                self.train_model(training_data)

            self.logger.info(f"User correction added for category: {correct_category}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add user correction: {e}")
            return False

    def _get_prediction_confidence(self, transaction: Dict[str, Any]) -> float:
        """
        Get confidence score for prediction.

        Args:
            transaction: Transaction dictionary

        Returns:
            float: Confidence score between 0 and 1
        """
        if not self.is_trained or not self.model:
            return 0.5  # Default confidence for rule-based

        try:
            features = self._extract_features(transaction)
            probabilities = self.model.predict_proba([features])[0]
            return float(np.max(probabilities))
        except Exception:
            return 0.5

    def _save_model(self) -> None:
        """
        Save trained model to disk.

        Security: Models are saved locally with restricted permissions.
        """
        try:
            # Save with restricted permissions
            with open(self.model_path, "wb") as f:
                pickle.dump(self.model, f)

            with open(self.label_encoder_path, "wb") as f:
                pickle.dump(self.label_encoder, f)

            # Set restrictive permissions
            self.model_path.chmod(0o600)
            self.label_encoder_path.chmod(0o600)

            self.logger.info("Model saved successfully")

        except Exception as e:
            self.logger.error(f"Failed to save model: {e}")

    def _load_model(self) -> None:
        """
        Load trained model from disk.

        Security: Only loads from local trusted directory.
        """
        try:
            if self.model_path.exists() and self.label_encoder_path.exists():
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)

                with open(self.label_encoder_path, "rb") as f:
                    self.label_encoder = pickle.load(f)

                self.is_trained = True
                self.logger.info("Model loaded successfully")

        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            self.model = None
            self.label_encoder = None
            self.is_trained = False

    def get_model_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the trained model.

        Returns:
            Dict[str, Any]: Model statistics
        """
        stats = {
            "is_trained": self.is_trained,
            "model_exists": self.model_path.exists(),
            "categories": [],
        }

        if self.label_encoder:
            stats["categories"] = list(self.label_encoder.classes_)

        return stats
