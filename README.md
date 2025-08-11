# Personal Finance Manager

A cross-platform, local-first personal finance application built with Python that prioritizes privacy and security.

## Features

### Core Functionality
- **Document Processing**: Parse PDF, CSV, and Excel pay statements and credit card statements
- **Smart Categorization**: Automatically categorize expenses using offline machine learning models
- **Secure Storage**: All data stored in locally encrypted SQLite database (SQLCipher with AES-256)
- **Financial Analytics**: Monthly and yearly metrics for income, expenses, and savings
- **Manual Corrections**: User can correct categorizations to improve ML model accuracy
- **Backup & Restore**: Encrypted local file backup/restore functionality

### Security Features
- **Local-First**: No personal data ever leaves your device
- **No Network Access**: Application blocks all network requests
- **Encryption**: AES-256 encryption for database storage
- **Secure File Handling**: Temporary files automatically deleted after processing
- **Privacy by Design**: Zero telemetry or data collection

## Architecture

```
┌──────────────────────────────────────────┐
│               User Interface              │
│   (PyQt5 for cross-platform GUI)         │
└──────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────┐
│       Data Processing & Categorization    │
│  - PDF/CSV/Excel parsers                  │
│  - OCR (Tesseract) for scanned statements │
│  - Expense categorization (scikit-learn)  │
│  - User rule-based overrides              │
└──────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────┐
│       Local Encrypted Data Storage        │
│  - SQLite + SQLCipher (AES-256)           │
│  - All data stored offline                │
└──────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────┐
│       Reporting & Analytics Engine        │
│  - Monthly/yearly summaries               │
│  - Category breakdowns                    │
│  - Savings projections                    │
│  - Chart visualizations                   │
└──────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────┐
│         Backup & Restore Module           │
│  - Local encrypted file export/import     │
└──────────────────────────────────────────┘
```

## Technology Stack

- **Language**: Python 3.9+
- **GUI**: PyQt5 (cross-platform)
- **Database**: SQLite with SQLCipher encryption
- **Data Processing**: pandas, pdfplumber
- **OCR**: pytesseract (Tesseract)
- **Machine Learning**: scikit-learn (offline only)
- **Visualization**: matplotlib/plotly
- **Packaging**: PyInstaller/Briefcase

## Installation

### Prerequisites
- Python 3.9 or higher
- Tesseract OCR engine

### Setup
1. Clone the repository
2. Create a virtual environment:
   ```bash
   python3 -m venv f_venv
   source f_venv/bin/activate  # On Windows: f_venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application
```bash
python3 src/main.py
```

## Development

### Project Structure
```
src/
├── main.py                 # Application entry point
├── parsers/                # Document parsing modules
│   ├── pdf_parser.py       # PDF statement parsing
│   ├── csv_parser.py       # CSV file parsing
│   ├── excel_parser.py     # Excel file parsing
│   └── ocr_processor.py    # OCR for scanned documents
├── ml/                     # Machine learning modules
│   ├── categorizer.py      # Expense categorization
│   ├── model_trainer.py    # ML model training
│   └── feature_extractor.py # Feature extraction
├── database/               # Database modules
│   ├── db_manager.py       # Database operations
│   ├── models.py           # Data models
│   └── migrations.py       # Schema migrations
├── gui/                    # GUI modules
│   ├── main_window.py      # Main application window
│   ├── import_dialog.py    # File import interface
│   ├── categorization_view.py # Category management
│   └── analytics_view.py   # Reports and charts
├── security/               # Security modules
│   ├── encryption.py       # Encryption utilities
│   ├── file_handler.py     # Secure file operations
│   └── network_blocker.py  # Network access prevention
└── analytics/              # Analytics modules
    ├── reporter.py         # Report generation
    ├── metrics.py          # Financial metrics calculation
    └── visualizations.py   # Chart generation
```

## Building for Distribution

### Create Standalone Executable
```bash
# Install build dependencies
pip install pyinstaller

# Build for current platform
pyinstaller --onefile --windowed src/main.py
```

## Security Notes

This application is designed with security and privacy as primary concerns:

- All processing happens locally on your device
- No network connections are made
- Database is encrypted with AES-256
- Temporary files are securely deleted
- No telemetry or usage tracking

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes following the security guidelines
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions, please use the GitHub issue tracker.
