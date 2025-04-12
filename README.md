# RSA Cryptography Implementation

This project is a *C/C++* implementation of the *RSA* cryptographic algorithm. It covers key generation, encryption/decryption, and digital signatures (signing and verification) using low-level cryptographic operations. The implementation follows *PKCS#1* standards and utilizes *ASN.1* structures for encoding.

## Features

- *RSA Key Generation*:  
  RSA key pairs (public and private) are generated and stored in the *DER* format, adhering to *PKCS#1* standards.

- *Encryption/Decryption*:  
  Implemented RSA encryption and decryption algorithms to securely transmit data.

- *Digital Signatures*:  
  The project also includes *digital signatures* for verifying the authenticity and integrity of messages. The private key is used for signing, and the public key is used for verification.

## Key Components

1. *RSA Key Generation*:
   - Uses large prime numbers to generate *public* and *private keys*.
   - Keys are stored in *DER format* following *PKCS#1* and *ASN.1* structure for encoding.

2. *Encryption and Decryption*:
   - The RSA algorithm encrypts data using the public key and decrypts it with the private key.
   - Supports variable key lengths and padding schemes.

3. *Digital Signature*:
   - The project implements the process of *signing* a message using the private key and *verifying* it with the public key, ensuring data integrity and authenticity.


## Prerequisites 📃

Before you begin, ensure you have **cmake (Build Automation Tool)** installed on your machine: <br>
You can download `cmake` here : [https://cmake.org/download/](https://cmake.org/download/)

### How to build 🔨

Clone the repository
```
git clone https://github.com/amanmaurya-406/RSA.git
```

Navigate to the build directory inside project
```bash
cd RSA/build
```

Build the project 🛠️
```bash
cmake ..
cmake --build .
```

Execute ▶️
```bash
../bin/rsa
```

## Requirements

- Libraries: OpenSSL (for some cryptographic functions), GMP (for large number calculations)
