# ADVANCED-ENCRYPTION-TOOL

COMPANY : JEFFERSON RAJA A 

INTERN ID : CT04DN1133

DOMAIN : Cyber Security & Ethical Hacking 

DURATION : 4 WEEKS

MENTOR : NEELA SANTHOSH

DESCRIPTION :

A secure Python script for encrypting and decrypting files using AES-256-CBC with HMAC-SHA256 integrity verification. Designed for protecting sensitive data with strong cryptographic standards, this tool ensures confidentiality and detects tampering.

Features
AES-256-CBC Encryption – Military-grade encryption with random salts and IVs.

PBKDF2 Key Derivation – Uses 210,000 iterations for brute-force resistance.

HMAC-SHA256 Verification – Detects file corruption or tampering.

Chunked Processing – Handles large files efficiently (1MB chunks).

Secure Password Handling – Optional hidden input to avoid command-line exposure.

Error Resilience – Automatically cleans up incomplete outputs on failure.


COMMANDS USED IN CMD/POWERSHELL :

FOR ENCRYPTING A FILE :
python "C:\Users\mariy\OneDrive\Documents\internship\codtech\advanced encryption tool with AES-256.py" encrypt "C:\Users\mariy\OneDrive\Documents\internship\codtech\input_file.txt" "encrypted.aes" -p "2007"

FOR DECRYPTNG MA FILE :
python "C:\Users\mariy\OneDrive\Documents\internship\codtech\advanced encryption tool with AES-256.py" decrypt "C:\Users\mariy\encrypted.aes" "C:\Users\mariy\OneDrive\Documents\internship\codtech\output.txt" -p "2007"

# OUTPUT :
