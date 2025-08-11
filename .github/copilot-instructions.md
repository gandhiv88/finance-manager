# Copilot Instructions

<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

## Project Context
This is a cross-platform personal finance application built in Python with a focus on privacy and security.

## Key Principles
- **Security First**: All data must remain local, no network requests allowed
- **Privacy**: Personal financial data never leaves the device
- **Encryption**: Use SQLCipher/AES-256 for all data storage
- **Cross-platform**: Must work on both macOS and Windows
- **Offline-only**: No cloud APIs or internet dependencies

## Architecture Guidelines
- Use modular design with separate modules for parsing, ML, database, GUI, and security
- Follow the principle of least privilege for file access
- Implement secure file handling with automatic cleanup of temporary files
- Use type hints and comprehensive docstrings
- Include security rationale in comments for sensitive operations

## Dependencies
- pandas (data analysis)
- pdfplumber (PDF parsing) 
- pytesseract (OCR)
- scikit-learn (ML categorization)
- sqlcipher3 (encrypted SQLite)
- PyQt5 (cross-platform GUI)
- matplotlib/plotly (charts)
- cryptography (additional encryption utilities)

## Security Considerations
- No network imports or requests
- Secure memory handling for sensitive data
- Encrypted database with user-provided passwords
- Secure deletion of temporary files
- Input validation for all file operations
- Path traversal protection
