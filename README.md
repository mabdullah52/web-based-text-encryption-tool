# Web-Based Text Encryption Tool

Assignment 2 solution: a single-page web application demonstrating multiple cryptographic techniques.

## Included techniques

### Encryption / encoding
1. Caesar Cipher
2. Vigenere Cipher
3. AES-256-GCM
4. RSA-2048 with OAEP/SHA-256
5. XOR Cipher
6. Rail Fence Cipher
7. Base64 encoding (encoding, not encryption)

### Hashing
- SHA-256
- SHA-512
- MD5 (included for educational comparison; not recommended for security)

## Features

- Encrypt and decrypt supported reversible methods
- Hash text
- Input validation
- Copy result
- Responsive single-page interface
- Node.js + Express backend

## Requirements

- Node.js LTS

## Installation

```bash
npm install
npm start
```

Open http://localhost:3000

## Important notes

- RSA uses an educational 2048-bit key pair generated when the server starts. RSA is intended for short messages; this demo limits RSA plaintext to 190 UTF-8 bytes.
- AES uses AES-256-GCM with a built-in assignment key. In a real application, secrets must not be hard-coded.
- XOR, Caesar, Vigenere, and Rail Fence are classical/educational ciphers and should not be used for real security.
- Base64 is encoding, not encryption.
- MD5 is cryptographically broken and is included only for educational comparison.
