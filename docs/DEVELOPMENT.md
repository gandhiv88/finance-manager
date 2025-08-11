# Development Guide

## Setup Development Environment

### Prerequisites
- Python 3.9 or higher
- Git
- Tesseract OCR engine

### Environment Setup
1. Clone the repository
2. Create virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### IDE Configuration
The project is optimized for Visual Studio Code with the following extensions:
- Python
- Black Formatter
- Flake8
- Mypy Type Checker

## Project Structure

```
src/
├── main.py                 # Application entry point
├── analytics/              # Financial analytics and reporting
│   └── reporter.py
├── database/              # Database operations
│   └── db_manager.py
├── gui/                   # User interface
│   └── main_window.py
├── ml/                    # Machine learning
│   └── categorizer.py
├── parsers/               # File parsing
│   ├── csv_parser.py
│   ├── excel_parser.py
│   └── pdf_parser.py
└── security/              # Security components
    ├── file_handler.py
    └── network_blocker.py
```

## Development Workflow

### Running the Application
```bash
python src/main.py
```

### Running Tests
```bash
python -m pytest tests/ -v
```

### Code Formatting
```bash
python -m black src/ tests/
```

### Linting
```bash
python -m flake8 src/ tests/
```

### Type Checking
```bash
python -m mypy src/
```

## Security Development Guidelines

### Code Review Checklist
- [ ] No network imports or requests
- [ ] Proper input validation
- [ ] Secure file handling with cleanup
- [ ] Encrypted data storage
- [ ] Error handling doesn't expose sensitive data
- [ ] Memory cleared after sensitive operations

### Testing Security Features
- Test network blocking functionality
- Verify file validation and sanitization
- Check encryption implementation
- Validate secure cleanup procedures

### Documentation Requirements
- Document security rationale for sensitive code
- Include threat model considerations
- Explain privacy implications
- Provide security configuration guidance

## Building for Distribution

### Create Executable
```bash
pyinstaller --onefile --windowed --name PersonalFinanceManager src/main.py
```

### Cross-Platform Considerations
- Test on both macOS and Windows
- Verify file path handling
- Check GUI scaling and fonts
- Test file dialog behavior

## Contributing

### Pull Request Process
1. Create feature branch from main
2. Implement changes with tests
3. Run full test suite
4. Update documentation
5. Submit PR with security review

### Security Review Process
All changes involving:
- File operations
- Database access
- User input processing
- External dependencies

Must undergo security review focusing on:
- Data flow analysis
- Input validation
- Error handling
- Memory management

## Performance Considerations

### Memory Usage
- Large files are processed in chunks
- Temporary data is cleaned up promptly
- Database queries are optimized
- GUI updates use lazy loading

### File Processing
- Size limits prevent resource exhaustion
- Progress reporting for large operations
- Background processing for responsiveness
- Error recovery for corrupted files

## Debugging

### Common Issues
1. **Import errors**: Check virtual environment activation
2. **Database locked**: Ensure proper connection cleanup
3. **File parsing fails**: Verify file format and encoding
4. **GUI doesn't start**: Check PyQt5 installation

### Debug Mode
Set environment variable for verbose logging:
```bash
export DEBUG=1
python src/main.py
```

### Log Files
Application logs are stored in:
- macOS: `~/.personalfinance/logs/`
- Windows: `%USERPROFILE%\.personalfinance\logs\`
