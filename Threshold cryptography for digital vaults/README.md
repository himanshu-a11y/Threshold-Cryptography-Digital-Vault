# 🔐 Threshold Cryptography Digital Vault

An enterprise-grade, mathematically secure digital vault that leverages **Threshold Cryptography** to secure sensitive data. This project demonstrates how modern financial institutions, cryptocurrency exchanges, and secure corporate environments protect critical assets by removing single points of failure.

## 🌟 Key Features

1. **Hybrid Cryptography (AES-256 + SSS)**: Secures payloads of any size by combining symmetric authenticated encryption with threshold key distribution.
2. **Feldman Verifiable Secret Sharing (VSS)**: Protects against malicious shareholders by utilizing cryptographic commitments based on the Discrete Logarithm Problem.
3. **Interactive Web Dashboard**: A sleek, modern Flask application with an intuitive UI for encrypting vaults and distributing key shares.
4. **Information-Theoretic Security**: The mathematical foundation ensures that possessing anything less than the required threshold of shares yields absolutely zero information about the secret.

---

## 🛡️ How Is It Secure? (Security Architecture)

This project achieves a high level of security by layering three distinct cryptographic primitives. Here is a breakdown of why this system is mathematically uncrackable:

### 1. Data Confidentiality & Integrity (AES-256-GCM)
When you create a vault, your actual secret data (whether it's a short password or a 10-page document) is encrypted using **AES-256-GCM** (Advanced Encryption Standard with Galois/Counter Mode). 
* **Confidentiality:** AES-256 is the gold standard for symmetric encryption, currently approved by the NSA for Top Secret information. Brute-forcing a 256-bit key is computationally impossible with current or foreseeable classical computing.
* **Integrity (GCM):** The GCM mode is an *Authenticated Encryption* scheme. It attaches an authentication tag to the ciphertext. If an attacker flips even a single bit of the encrypted vault file, the decryption will immediately fail and throw an error, preventing tampering.

### 2. Perfect Secrecy & Decentralization (Shamir's Secret Sharing)
Instead of storing the AES Master Key in a database (which creates a single point of failure), the key is split into multiple mathematical "shares" using **Shamir's Secret Sharing (SSS)**.
* **The Math:** SSS maps the AES key to the Y-intercept (the constant term) of a random polynomial of degree `t - 1` over a massive finite field.
* **Information-Theoretic Security:** If the threshold is 3, any 2 shares provide an underspecified system of equations. In the finite field, the missing key could literally be *any* possible 256-bit number with perfectly equal probability. No amount of computing power can guess the key from `t - 1` shares.

### 3. Cryptographic Unforgeability (Feldman VSS)
A known vulnerability in basic SSS is that a malicious participant can submit a fake or altered share during the recovery phase, causing the vault to generate the wrong key and permanently destroying the data. 
* **The Fix:** We implemented **Feldman Verifiable Secret Sharing**. When the vault is created, the system generates public "Commitments" ($C_j = g^{a_j} \pmod p$) for every coefficient of the polynomial using a 2048-bit safe prime (RFC 3526).
* **The Proof:** When a share ($x, y$) is submitted, the system mathematically verifies it: $g^y \equiv \prod C_j^{x^j} \pmod{p}$.
* **Why it's unbreakable:** To forge a share that passes this mathematical check, an attacker would have to solve the **Discrete Logarithm Problem (DLP)** over a 2048-bit group, which is currently computationally infeasible.

---

## 📂 Project Structure

```text
├── app.py                      # Flask Web Dashboard server
├── advanced_digital_vault.py   # Hybrid AES-256 + SSS logic & CLI
├── shamir_secret_sharing.py    # Core Math: Finite Fields, SSS, and Feldman VSS
├── vault_converter.py          # String ↔ Integer hexadecimal conversion utils
├── templates/                  
│   └── index.html              # Frontend UI for the Web Dashboard
├── shares/                     # Auto-generated JSON key shares for distribution
└── vault_data.json             # The encrypted vault payload (ciphertext + nonce)
```

---

## 🚀 How to Run the Project

### Method 1: Web Dashboard (Recommended)
Launch the interactive visual dashboard:
```bash
python app.py
```
Then, open your web browser and navigate to: **http://127.0.0.1:5000**

**Workflow:**
1. Go to **Create Vault**. Type your secret, set the threshold (e.g., 3), and total shares (e.g., 5).
2. Click **Download All Key Shares**. Distribute these `.json` files to your authorized directors.
3. Switch to the **Open Vault** tab.
4. Drag and drop at least 3 valid `.json` share files into the upload zone.
5. Click **Unlock Vault** to verify the Feldman Commitments, reconstruct the AES key, and decrypt the data.

### Method 2: Command Line Interface (CLI)
Run the vault directly from the terminal for debugging or headless server environments:
```bash
python advanced_digital_vault.py
```
Choose **Mode 2 (Hybrid Mode)** to utilize AES-256 and Feldman VSS.
