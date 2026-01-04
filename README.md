# OpenSSL Cryptography Project

A Python implementation of RSA cryptographic operations compatible with OpenSSL. This project demonstrates RSA key parsing, encryption/decryption, and digital signatures using the `cryptography` library.

> **Note:** The RSA keys included in this repository are used as artifacts for demonstration and testing purposes. They are intentionally committed to enable reproducible examples and are not meant for production use.

## 📁 Project Structure

```
crypto1_openssl/
├── Demo/                    # Demo video links
├── Report/                  # Project reports
├── Source/
│   ├── project_03_01/       # RSA Key Parser
│   ├── project_03_02/       # RSA Encryption/Decryption
│   ├── project_03_03/       # RSA Digital Signatures
│   ├── requirements.txt     # Python dependencies
│   └── README.md
└── README.md                # This file
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- OpenSSL (for verification and key generation)

### Installation

```bash
# Navigate to Source directory
cd Source

# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/bin/activate    # Linux/macOS
# or
.venv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt
```

## 📦 Projects

### Project 1: RSA Key Parser (`project_03_01`)

Parse and validate RSA keys from PEM files. Displays all key components and validates their mathematical relationships.

**Features:**
- Extract key components: n, e, d, p, q, dP, dQ, qInv
- Validate RSA key constraints
- Output format matches OpenSSL's `pkey -text`

**Usage:**
```bash
cd project_03_01

# Parse private key
python rsa_key_parser.py priv.pem

# Parse both private and public keys
python rsa_key_parser.py priv.pem pub.pem
```

### Project 2: RSA Encryption/Decryption (`project_03_02`)

Encrypt and decrypt files using RSA with PKCS#1 v1.5 padding, fully compatible with OpenSSL.

**Features:**
- PKCS#1 v1.5 padding for OpenSSL compatibility
- Automatic block splitting for large plaintexts
- 2048-bit RSA supports up to 245 bytes per block

**Usage:**
```bash
cd project_03_02

# Encrypt a file
python rsa_encrypt.py pub.pem plaintext.txt cipher.bin

# Decrypt a file
python rsa_decrypt.py priv.pem cipher.bin decrypted.txt
```

**Cross-compatibility with OpenSSL:**
```bash
# Encrypt with Python, decrypt with OpenSSL
python rsa_encrypt.py pub.pem plain cipher_py
openssl pkeyutl -in cipher_py -out plain_check -inkey priv.pem -decrypt

# Encrypt with OpenSSL, decrypt with Python
openssl pkeyutl -in plain -out cipher_openssl -inkey pub.pem -pubin -encrypt
python rsa_decrypt.py priv.pem cipher_openssl plain_check
```

### Project 3: RSA Digital Signatures (`project_03_03`)

Sign and verify messages using raw RSA with PKCS#1 v1.5 padding, compatible with OpenSSL.

**Features:**
- Raw RSA signing (without hashing)
- PKCS#1 v1.5 signature padding
- Full OpenSSL compatibility

**Usage:**
```bash
cd project_03_03

# Sign a message
python rsa_signature.py sign priv.pem message.txt signature.bin

# Verify a signature
python rsa_signature.py verify pub.pem message.txt signature.bin
```

**Cross-compatibility with OpenSSL:**
```bash
# Sign with Python, verify with OpenSSL
python rsa_signature.py sign priv.pem mess.txt sign.bin
openssl pkeyutl -in mess.txt -inkey pub.pem -pubin -verify -sigfile sign.bin

# Sign with OpenSSL, verify with Python
openssl pkeyutl -in mess.txt -out sign_openssl.bin -inkey priv.pem -sign
python rsa_signature.py verify pub.pem mess.txt sign_openssl.bin
```

## 🔑 Generating RSA Keys

To generate your own RSA key pair using OpenSSL:

```bash
# Generate 2048-bit private key
openssl genpkey -out priv.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048

# Extract public key from private key
openssl pkey -in priv.pem -out pub.pem -pubout

# View key details
openssl pkey -in priv.pem -text -noout
```

## 📚 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| cryptography | 46.0.3 | RSA operations and key handling |

## 🎥 Demo

Demo videos are available in the [Demo/](Demo/) folder.

## 📄 License

This project is for educational purposes as part of a cryptography course at HCMUS.