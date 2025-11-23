<a href="url"><img src="./aegis.png" align="left" height="210" width="210">
</a>
<br/>
### AEGIS - Triple Layer Encryption System

RSA-4096 + Double Layer AES (AES-256-GCM + AES-256-EAX)

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-AES--256%20%2B%20RSA--4096-red.svg)]()
<br/><br/><br/><br/><br/>

---

## 🛡️ What is Aegis?

**Aegis** is a portable, zero-install file encryption tool that provides military-level security through a triple-layer encryption architecture. Works on Windows, Linux, and macOS out of the box - just download and run!

Available in both **Command Line (CLI)** and **Graphical Interface (GUI)** modes.

### ✨ Key Features

- 🔒 **Triple-Layer Security**: Dual AES-256 encryption (GCM + EAX) protected by RSA-4096
- ✅ **Tamper Detection**: Automatically detects any file modifications via authenticated encryption
- 🔑 **Unique Keys Per File**: Each file gets its own unique encryption keys
- 📁 **Unlimited File Size**: Efficient chunk-based processing handles files of any size
- 🚀 **High Performance**: Hardware-accelerated AES encryption (AES-NI support)
- 🖥️ **Dual Interface**: Use CLI for automation or GUI for ease of use

---

## 🚀 Quick Start

### No Installation Required

Aegis includes all dependencies for **Windows** (available compiled exe), **Linux**, and **macOS**. Just run it with Python 3.7+:

```bash
python aegis.py --version
```

### CLI or GUI Mode

Aegis can be used in two ways:

**Command Line Interface (CLI):**
```bash
python aegis.py -e document.pdf
```

**Graphical User Interface (GUI):**
```bash
python aegis_gui.py
```

> **Note for Linux users:** When installing from package manager, the CLI version is `aegis` and the GUI version is `aegis-gui`.

### Encrypt a File

```bash
python aegis.py -e document.pdf
```

**Generates 3 files:**
- `document.enc` - Encrypted data (double-layer AES)
- `document.keys` - Encrypted symmetric keys (RSA-protected)
- `document.rsakey` - RSA private key ⚠️ **KEEP THIS SAFE!**

### Decrypt a File

```bash
python aegis.py document.enc document.keys document.rsakey
```

**Files can be in ANY order** - Aegis automatically detects file types using magic bytes!

---

## 🔐 Security Architecture

```
┌─────────────────────────────────────────────┐
│           Original File                     │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  Layer 1: AES-256-GCM (Inner Protection)    │
│  • 256-bit encryption                       │
│  • Authenticated encryption (AEAD)          │
│  • Hardware-accelerated (AES-NI)            │
│  • Galois/Counter Mode                      │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  Layer 2: AES-256-EAX (Outer Protection)    │
│  • 256-bit encryption                       │
│  • Additional authentication layer          │
│  • Defense in depth strategy                │
│  • EAX authenticated encryption             │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  Layer 3: RSA-4096 (Key Protection)         │
│  • 4096-bit RSA encryption                  │
│  • OAEP padding + SHA-256                   │
│  • Protects symmetric keys                  │
│  • Unique key pair per file                 │
└─────────────────────────────────────────────┘
                    ↓
         3 Encrypted Files
```

---

## 📖 Usage Examples

### Basic Encryption

```bash
# Encrypt any file type
python aegis.py -e photo.jpg
```

### Basic Decryption

```bash
# Method 1: Auto-detect (any order works!)
python aegis.py photo.enc photo.keys photo.rsakey

# Method 2: Using flags
python aegis.py -d photo.enc -k photo.keys -r photo.rsakey

# Method 3: Auto-find companion files (same folder)
python aegis.py -d photo.enc
# Automatically finds photo.keys and photo.rsakey
```

### Advanced Options

```bash
# Custom output location
python aegis.py -e document.pdf -o /secure/backup/document

# Custom decryption output
python aegis.py -d document.enc -o restored.pdf

# Generate RSA-4096 key pair
python aegis.py -nk
# Generates aegis_private_key.pem and aegis_public_key.pem in current directory

python aegis.py -nk /path/to/directory
# Generates keys in specified directory

# Encrypt with custom RSA public key
python aegis.py -e document.pdf -re my_public_key.pem
# Only generates .enc and .keys (no .rsakey - you must have the private key)
```

---

## 🎯 Command Reference

| Command | Description |
|---------|-------------|
| `-e FILE`, `--encrypt FILE` | Encrypt specified file |
| `-d FILE`, `--decrypt FILE` | Decrypt specified .enc file |
| `-nk [DIR]`, `--newkeys [DIR]` | Generate RSA-4096 key pair (default: current directory) |
| `-re FILE`, `--rsa-encrypt FILE` | Custom RSA public key for encryption (optional) |
| `-k FILE`, `--keys FILE` | .keys file (for decryption) |
| `-r FILE`, `--rsakey FILE` | RSA private key file (.rsakey) for decryption |
| `-o FILE`, `--output FILE` | Custom output path |
| `--version` | Show version information |
| `-h`, `--help` | Show help message |

### Positional Arguments

```bash
python aegis.py [file1] [file2] [file3]
```
Pass 3 files in any order - automatic detection handles identification.

---

## 🔍 Triple-Layer Encryption

### Defense in Depth Strategy

Multiple independent security layers ensure that even if one algorithm is compromised, your data remains protected.

### Layer 1: AES-256-GCM (Inner)
- ✅ Industry-standard encryption (NIST approved)
- ✅ Hardware-accelerated on modern CPUs (AES-NI)
- ✅ Fast and efficient (used in TLS 1.3, IPsec, SSH)
- ✅ Authenticated encryption (detects tampering)

### Layer 2: AES-256-EAX (Outer)
- ✅ Additional encryption layer for maximum security
- ✅ Different cipher mode (defense in depth)
- ✅ Independent authentication
- ✅ Less common = harder to attack with known exploits

### Layer 3: RSA-4096 (Key Protection)
- ✅ Asymmetric encryption (public/private key pair)
- ✅ 4096-bit key (highly secure, future-proof for 20+ years)
- ✅ OAEP padding prevents padding oracle attacks
- ✅ SHA-256 hashing for additional security

---

## 🛡️ Security Features

### ✅ Authenticated Encryption

Both AES layers provide **AEAD** (Authenticated Encryption with Associated Data):
- Detects any modification to encrypted data
- Prevents tampering attacks
- Authentication tags verify integrity

**If 1 byte is modified:**
```
[ERROR] AES-EAX authentication failed - file modified
```

### ✅ Unique Keys Per File

Each encryption generates:
- ✨ New RSA-4096 key pair
- ✨ New AES-256-GCM key
- ✨ New AES-256-EAX key

**No key reuse** = maximum security. Compromising one file doesn't affect others.

### ✅ Magic Bytes Identification

Files are identified by content (magic bytes), not extension:
- 📝 Rename files freely
- 🔄 Process in any order
- 🎯 Automatic type detection
- 🛡️ Format validation

### ✅ Chunk-Based Processing

- 📦 Processes files in 64 MB chunks
- ♾️ No file size limit
- 💾 Low memory footprint

---

## ⚠️ Important Warnings

### 🚨 Critical Information

1. **All 3 files (.enc, .keys, .rsakey) are required for decryption**
   - Missing any file = permanent data loss
   - Keep backups in separate secure locations

2. **There is NO password recovery or reset option**
   - This is by design for security
   - No "forgot password" feature exists

---

## 📁 File Structure

### Generated Files After Encryption

```
document.pdf  (original, 1.5 MB)
    ↓
├── document.enc      (encrypted data, ~1.5 MB)
│   ├── Magic bytes: ENCFILE1
│   ├── Original filename
│   ├── AES-EAX metadata (nonce, tag)
│   ├── AES-GCM metadata (nonce, tag)
│   └── Double-encrypted data
│
├── document.keys     (encrypted keys, ~524 bytes)
│   ├── Magic bytes: KEYFILE1
│   └── RSA-encrypted AES keys (64 bytes)
│
└── document.rsakey   (RSA private key, ~3.2 KB)
    └── PEM-encoded RSA-4096 private key
```

---

## 🔧 Technical Specifications

| Component | Specification |
|-----------|--------------|
| **Inner Encryption** | AES-256-GCM (Galois/Counter Mode) |
| **Outer Encryption** | AES-256-EAX (Authenticated Encryption) |
| **Key Protection** | RSA-4096-OAEP-SHA256 |
| **Key Generation** | Cryptographically Secure Random (CSPRNG) |
| **Authentication** | AEAD (double authentication) |
| **Chunk Size** | 64 MB (adjustable) |
| **File Size Limit** | Unlimited (chunk-based processing) |
| **Filename Encoding** | UTF-8 |
| **Magic Bytes** | ENCFILE1 (enc), KEYFILE1 (keys) |

---

## 🔬 Cryptographic Details

### Algorithms Used

- **AES-256-GCM**: NIST FIPS 197 approved, hardware-accelerated
- **AES-256-EAX**: AEAD cipher, provable security
- **RSA-4096-OAEP**: NIST SP 800-56B compliant
- **SHA-256**: NIST FIPS 180-4 approved hash function

### Security Strength

- **AES-256**: 2^256 possible keys (computationally infeasible to brute force)
- **RSA-4096**: Secure for 20+ years against conventional computers
- **Combined**: Multiple layers provide defense-in-depth

---

## 📦 Requirements

- **Python 3.7 or higher** (that's it!)
- No additional installation required

### Included Dependencies

Aegis comes with PyCryptodome pre-bundled for:
- ✅ **Windows** (x86_64)
- ✅ **Linux** (x86_64)
- ✅ **macOS** (Intel & Apple Silicon - Universal Binary)
- ⚙️ **Other platforms**: Auto-installs on first run

---

## ❓ FAQ

**Q: Can I rename the encrypted files?**  
A: Yes! Aegis uses magic bytes for identification, not filenames. Rename freely.

**Q: Is this encryption really secure?**  
A: Yes. It uses battle-tested, industry-standard algorithms (AES-256, RSA-4096) with proper implementation and authenticated encryption.

**Q: How many files can I encrypt?**  
A: One at time. Each file automatically gets unique keys.

**Q: What if someone modifies my .enc file?**  
A: Authentication will fail immediately with an error. Tampered files cannot be decrypted.

**Q: What's the maximum file size?**  
A: Unlimited. Aegis uses chunk-based processing and can handle files of any size.

**Q: Is it quantum-resistant?**  
A: AES-256 is quantum-resistant. RSA-4096 is secure for 20+ years but may be vulnerable to future quantum computers.

**Q: Why three layers instead of one?**  
A: Defense in depth. Multiple independent layers ensure security even if one algorithm is compromised.

---

## 📊 Comparison with Other Tools

| Feature | Aegis | GPG | 7-Zip AES | VeraCrypt |
|---------|-------|-----|-----------|-----------|
| Triple-layer encryption | ✅ | ❌ | ❌ | ❌ |
| Unique keys per file | ✅ | ❌ | ❌ | ❌ |
| Authenticated encryption | ✅✅ (double) | ✅ | ❌ | ✅ |
| Automatic file detection | ✅ | ❌ | ❌ | N/A |
| No file size limit | ✅ | ✅ | ❌ | ✅ |
| Progress bars | ✅ | ❌ | ✅ | ✅ |
| Easy to use | ✅ | ❌ | ✅ | ⚠️ |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

---

## 📄 License

This software is provided as-is for educational and professional use.

> **DISCLAIMER: This software is under active development and provided AS-IS without any warranty.**
> 
> The author is NOT responsible for any data loss, corruption, or damage that may occur from using this software. Always:
> - Keep backups of your original files before encryption
> - Test with non-critical files first
> - Verify decryption works before deleting originals
> - Store your .rsakey files securely - losing them means permanent data loss
>
> **USE AT YOUR OWN RISK**



