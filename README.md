# PassSafe CLI - Local Encrypted Password Manager

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)
![Platform: Windows/Linux/macOS](https://img.shields.io/badge/Platform-Windows%2FLinux%2FmacOS-lightgrey.svg)

A secure, local password manager with AES-256-GCM encryption and PBKDF2 key derivation. PassSafe CLI stores all your passwords in an encrypted vault on your local machine with no cloud dependencies.

## 🔐 Security Features

- **AES-256-GCM Encryption**: Military-grade encryption for all vault data
- **PBKDF2-HMAC-SHA256**: 200,000 iterations for secure key derivation
- **Zero Knowledge**: All encryption happens locally, no data leaves your machine
- **Stealth Mode**: Hide service names with cryptographic hashes
- **Master Password Protection**: Single strong password protects all your data
- **Secure Password Generation**: Cryptographically secure random password generation

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Install from Source
```bash
git clone https://github.com/yourusername/smart-passsafe.git
cd smart-passsafe
pip install -r requirements.txt
```

### Install Dependencies
```bash
pip install cryptography
```

## 🚀 Quick Start

### 1. Initialize Your Vault
```bash
passsafe init
```
Create a strong master password. This will be the only password you need to remember.

### 2. Unlock Your Vault
```bash
passsafe unlock
```
Enter your master password to access your stored passwords.

### 3. Add Your First Password
```bash
passsafe add gmail user@example.com
```
The system will offer to generate a secure password for you.

### 4. Find Passwords
```bash
passsafe find gmail
```
Search for passwords by service name. Use `--reveal` to show the actual password.

## 📋 Commands Reference

### Vault Management
```bash
# Create new encrypted vault
passsafe init

# Unlock vault for operations
passsafe unlock

# Show vault status and statistics
passsafe status
```

### Password Operations
```bash
# Add new password entry
passsafe add <service> <username> [--category <cat>] [--notes <notes>]

# Find password entries
passsafe find <service> [--reveal]

# Generate secure password
passsafe generate [--len 16] [--no-symbols] [--no-digits] [--uppercase-only]
```

### Security Analysis
```bash
# Analyze password security
passsafe analyze
```
This command provides:
- Weak password detection
- Old password identification (>90 days)
- Duplicate password detection
- Security score (0-100)
- Improvement recommendations

### Backup & Restore
```bash
# Create encrypted backup
passsafe backup [--path /custom/path]

# Restore from backup
passsafe restore backup_2024-01-15.passsafe
```

### Privacy Features
```bash
# Enable stealth mode (hide service names)
passsafe stealth on

# Disable stealth mode
passsafe stealth off
```

## 🔧 Configuration

### Default Vault Location
- **Windows**: `%USERPROFILE%\smart-passsafe\data\vault.passsafe`
- **Linux/macOS**: `~/smart-passsafe/data/vault.passsafe`

### Environment Variables
```bash
# Custom vault directory
export PASSSAFE_VAULT_DIR="/path/to/vault"

# Disable colors in output
export NO_COLOR=1
```

## 📊 Security Analysis

PassSafe CLI includes comprehensive security analysis:

### Password Strength Categories
- **Very Strong**: 20+ chars, high entropy
- **Strong**: 16-19 chars, good entropy
- **Moderate**: 12-15 chars, decent entropy
- **Weak**: 8-11 chars, low entropy
- **Very Weak**: <8 chars, very low entropy

### Analysis Features
- **Weak Passwords**: Identifies passwords with insufficient length or complexity
- **Old Passwords**: Flags passwords not updated in 90+ days
- **Duplicate Passwords**: Detects identical passwords across different services
- **Category Analysis**: Reviews service categorization for consistency
- **Security Scoring**: Provides overall vault security score (0-100)

### Example Analysis Output
```
==================================================
PASSSAFE SECURITY ANALYSIS REPORT
==================================================
Total Items: 25
Average Password Length: 14.2

[WEAK PASSWORDS]
  instagram - 8 chars (weak)

[OLD PASSWORDS]
  paypal - 102 days old

[DUPLICATE PASSWORDS]
  gmail & youtube

[PASSWORD STRENGTH DISTRIBUTION]
  Very Strong: 15 (60.0%)
  Strong: 7 (28.0%)
  Moderate: 2 (8.0%)
  Weak: 1 (4.0%)

[SUMMARY]
  ⚠️  3 security issue(s) found
  Consider updating weak and old passwords
  Avoid using duplicate passwords
==================================================
```

## 🏷️ Auto-Categorization

PassSafe automatically categorizes services based on name patterns:

### Supported Categories
- **Social**: Facebook, Twitter, Instagram, LinkedIn, etc.
- **Email**: Gmail, Outlook, Yahoo, ProtonMail, etc.
- **Finance**: Banks, PayPal, credit cards, investment apps
- **Work**: Office tools, development platforms, collaboration software
- **Shopping**: Amazon, eBay, retail stores, etc.
- **Entertainment**: Netflix, Spotify, Steam, gaming platforms
- **Travel**: Airlines, hotels, booking platforms
- **Health**: Medical portals, pharmacy, insurance
- **Education**: Learning platforms, universities
- **Misc**: Everything else

### Category Colors in Terminal Output
- Social: Magenta
- Email: Blue  
- Finance: Green
- Work: Yellow
- Shopping: Red
- Entertainment: Cyan
- Travel: White
- Health: Gray
- Education: Blue
- Misc: Gray

## 🔒 Encryption Details

### Encryption Algorithm
- **Cipher**: AES-256-GCM
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 200,000
- **Salt**: 32 random bytes per vault
- **Nonce**: 12 random bytes per encryption
- **Authentication**: GCM tag ensures integrity

### Security Considerations
- Master password is never stored
- All vault data is encrypted at rest
- Memory is cleared when vault is locked
- No network communication or cloud storage
- Open source cryptography library (cryptography.io)

## 🛠️ Development

### Project Structure
```
smart-passsafe/
├── passsafe/
│   ├── __init__.py          # Package metadata
│   ├── core.py              # Encryption & crypto operations
│   ├── database.py          # Vault storage & management
│   ├── generator.py         # Secure password generation
│   ├── analyzer.py          # Security analysis
│   ├── categories.py        # Auto-categorization
│   └── cli.py               # Command-line interface
├── data/
│   └── vault.passsafe       # Encrypted vault file
├── tests/                   # Test suite
├── requirements.txt         # Python dependencies
├── pyproject.toml          # Project configuration
├── README.md               # This file
├── LICENSE                 # MIT License
└── .gitignore              # Git ignore rules
```

### Running Tests
```bash
python -m pytest tests/
```

### Code Style
```bash
black passsafe/
flake8 passsafe/
```

## 🔐 Security Best Practices

### Master Password
- Use at least 16 characters
- Include uppercase, lowercase, digits, and symbols
- Avoid dictionary words or personal information
- Don't reuse passwords from other services
- Consider using a passphrase for memorability

### Password Generation
```bash
# Generate 20-character password with symbols
passsafe generate --len 20

# Generate password without symbols (for systems with restrictions)
passsafe generate --no-symbols

# Generate alphanumeric only
passsafe generate --no-symbols --len 24
```

### Regular Security Tasks
```bash
# Run security analysis monthly
passsafe analyze

# Create backup before major changes
passsafe backup

# Review and update old passwords
passsafe find old --reveal
```

## 🚨 Security Warnings

### Important Security Notes
- **Master Password**: If you forget your master password, ALL data is permanently lost. There is no recovery mechanism.
- **Backup Responsibility**: You are responsible for backing up your vault file.
- **Local Storage**: This is a local-only solution. No cloud sync or recovery.
- **File Permissions**: Ensure proper file permissions on your vault file.
- **Memory Security**: Vault data is in memory while unlocked. Lock when not in use.

### Recommended Security Practices
1. **Regular Backups**: Create encrypted backups regularly
2. **Strong Master Password**: Use a unique, strong master password
3. **File Permissions**: Restrict access to vault file (600 permissions)
4. **Regular Updates**: Keep dependencies updated
5. **Security Audits**: Run `passsafe analyze` regularly

## 🐛 Troubleshooting

### Common Issues

#### Vault Corruption
```bash
# Restore from backup if vault is corrupted
passsafe restore backup_2024-01-15.passsafe
```

#### Permission Denied
```bash
# Check file permissions (Linux/macOS)
chmod 600 ~/smart-passsafe/data/vault.passsafe
```

#### Cannot Unlock Vault
- Verify master password is correct
- Check for vault file corruption
- Try restoring from backup

#### Import Errors
```bash
# Reinstall dependencies
pip install --upgrade cryptography
```

### Getting Help
- Check the GitHub Issues page
- Review security best practices
- Ensure you have recent backups

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
git clone https://github.com/yourusername/smart-passsafe.git
cd smart-passsafe
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## 🙏 Acknowledgments

- [cryptography.io](https://cryptography.io/) for the excellent cryptography library
- The Python community for the amazing ecosystem
- Security researchers who advance password management best practices

## 📞 Support

For support, please:
1. Check the troubleshooting section
2. Search existing GitHub issues
3. Create a new issue with detailed information

---

**⚠️ IMPORTANT SECURITY NOTE**: This is a local password manager. You are solely responsible for:
- Backing up your vault file
- Protecting your master password
- Securing your local machine
- Following security best practices

There is NO cloud backup, NO password recovery, and NO support for lost master passwords. Use responsibly!