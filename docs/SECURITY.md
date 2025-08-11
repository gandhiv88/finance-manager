# Security Guidelines

## Overview
This application prioritizes security and privacy above all else. All financial data remains on the user's device and is encrypted at rest.

## Key Security Principles

### 1. Local-First Architecture
- All data processing happens locally
- No network requests are made by the application
- No telemetry or usage tracking
- No external API dependencies

### 2. Data Encryption
- Database encrypted with SQLCipher (AES-256)
- User-provided password required for access
- Temporary files are securely deleted after use
- Sensitive data cleared from memory when possible

### 3. Input Validation
- All file inputs are validated for type, size, and content
- Path traversal protection for file operations
- CSV injection protection for imported data
- PDF processing with security controls

### 4. Network Security
- Network access is blocked at the socket level
- No external resource loading in GUI
- Offline operation guaranteed
- Prevents accidental data leaks

### 5. File Security
- Secure temporary file handling
- Automatic cleanup of processed files
- File hash verification for integrity
- Restricted file permissions

## Implementation Details

### Database Security
```python
# SQLCipher integration for encryption
conn.execute(f"PRAGMA key = '{password}'")
```

### Network Blocking
```python
# Socket monkey-patching to prevent network access
socket.socket = blocked_socket
```

### Secure File Handling
```python
# Temporary files with restricted permissions
os.chmod(temp_file, 0o600)  # Owner read/write only
```

### Input Validation
```python
# File type and size validation
if path.suffix.lower() not in ALLOWED_EXTENSIONS:
    raise ValueError("File type not allowed")
```

## Security Testing

### Manual Tests
1. Verify no network requests are made during operation
2. Check that database files are encrypted
3. Confirm temporary files are cleaned up
4. Validate input sanitization

### Automated Tests
- Unit tests for security functions
- Integration tests for data flow
- File handling security tests
- Database encryption verification

## Threat Model

### Threats Mitigated
- Data exfiltration via network
- Unauthorized file system access  
- Database compromise
- Memory dump attacks (partial)
- CSV/PDF injection attacks

### Limitations
- Cannot protect against OS-level compromises
- Physical access to unlocked device
- Keyloggers or screen capture
- Hardware-level attacks

## Compliance Considerations

While not designed for specific regulatory compliance, the architecture supports:
- Data locality requirements
- Encryption at rest mandates  
- Audit trail capabilities
- User data control principles
