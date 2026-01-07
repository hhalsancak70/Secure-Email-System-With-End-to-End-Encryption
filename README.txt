Secure Email System (Java Console Application)
==========================================================

A secure, end-to-end encrypted email system implemented in Java, featuring robust cryptographic
protections for user authentication and message confidentiality. This system demonstrates industry-
standard security practices including password-based key derivation, encrypted key storage, and
hybrid encryption schemes.

Requirements
============
- Java 8 or higher JDK
- Maven 3.6 or higher (or manually add SQLite JDBC driver)

Building and Running (with Maven)
==================================
1. Navigate to the project directory
2. Download dependencies and compile:
   ```bash
   mvn clean compile
   ```
3. Run the application:
   ```bash
   mvn exec:java -Dexec.mainClass="KriptoProject"
   ```
4. Alternatively, build a JAR file and run:
   ```bash
   mvn package
   java -jar target/email-system-1.0.0-jar-with-dependencies.jar
   ```

Manual Build (without Maven)
=============================
1. Download SQLite JDBC driver from: https://github.com/xerial/sqlite-jdbc/releases
2. Place sqlite-jdbc-X.X.X.jar in the project directory
3. Compile:
   ```bash
   javac -cp sqlite-jdbc-*.jar src/main/java/*.java
   ```
4. Run:
   ```bash
   # Linux/Mac:
   java -cp .:sqlite-jdbc-*.jar:src/main/java KriptoProject
   
   # Windows:
   java -cp .;sqlite-jdbc-*.jar;src/main/java KriptoProject
   ```

Security Features
=================

1. Password Security (PBKDF2 + Salt)
   ----------------------------------
   - Passwords are hashed using PBKDF2WithHmacSHA256 algorithm
   - Each user receives a unique 16-byte randomly generated salt value
   - 100,000 iterations provide protection against brute-force attacks
   - Salt values are stored separately in the database
   - Prevents rainbow table attacks and ensures unique password hashes

2. Private Key Security (AES-GCM Encryption)
   ------------------------------------------
   - RSA private keys are never stored in plaintext in the database
   - Private keys are encrypted using AES-GCM with a key derived from the user's password
   - Each private key encryption uses unique random salt and IV values
   - Even if the database is compromised, private keys remain protected without the password
   - Implements defense-in-depth: database compromise does not expose cryptographic keys

3. Message Security
   -----------------
   - Messages are encrypted using AES-GCM (symmetric encryption)
   - AES keys are encrypted using the recipient's RSA public key (asymmetric encryption)
   - Message integrity is verified using SHA-256 hash
   - Digital signatures are created and verified using RSA
   - Hybrid encryption combines the efficiency of symmetric encryption with the security
     of asymmetric key exchange

Application Workflow
====================

1. User Registration
   -------------------
   - User provides username and password
   - System generates a random salt value
   - Password is hashed using PBKDF2WithHmacSHA256 with the salt
   - RSA key pair (public/private) is generated for the user
   - Private key is encrypted using AES-GCM with a key derived from the user's password
   - Hashed password, salt, public key, and encrypted private key are stored in the database

2. User Login
   -----------
   - User provides username and password
   - User's salt value is retrieved from the database
   - Entered password is hashed using PBKDF2 with the stored salt
   - Computed hash is compared with the stored hash value
   - Upon successful authentication, the encrypted private key is decrypted using
     the user's password
   - Decrypted private key is stored in memory (UserRecord) and used throughout the session

3. Sending Email
   --------------
   - User provides recipient username and message content
   - Message is encrypted using AES-GCM (symmetric encryption)
   - AES key is encrypted using the recipient's public key with RSA-OAEP
   - Message hash (SHA-256) is computed and digitally signed using the sender's private key
   - Encrypted message, encrypted key, IV, hash, and signature are stored in the database

4. Receiving and Verifying Email
   ------------------------------
   - Inbox is listed (message ID and sender)
   - Message is opened by entering the message ID
   - Recipient's private key is used to decrypt the AES key, then the message
   - Decrypted message hash is recomputed and compared with the stored hash
   - Sender's public key is used to verify the digital signature
   - Message is displayed only if both integrity and signature verification succeed

Database
========
- Data is stored in a SQLite database (email_system.db file)
- Database file is automatically created on first run
- Database schema is automatically migrated when needed
- If the salt_base64 column is missing from an existing schema, it is automatically added

Database Schema
---------------

Users Table:
  - username (TEXT, PRIMARY KEY)
  - password_hash (TEXT, NOT NULL) - PBKDF2 hash
  - salt_base64 (TEXT, NOT NULL) - Base64-encoded salt
  - public_key_base64 (TEXT, NOT NULL) - Base64-encoded RSA public key
  - private_key_base64 (TEXT, NOT NULL) - Encrypted private key (format: salt:iv:encryptedKey)

Messages Table:
  - id (INTEGER, PRIMARY KEY, AUTOINCREMENT)
  - from_user (TEXT, NOT NULL)
  - to_user (TEXT, NOT NULL)
  - enc_message (TEXT, NOT NULL) - Encrypted message
  - enc_key (TEXT, NOT NULL) - Encrypted AES key
  - iv (TEXT, NOT NULL) - Initialization Vector
  - hash_base64 (TEXT, NOT NULL) - Message hash
  - signature_base64 (TEXT, NOT NULL) - Digital signature

Important Notes
===============
- Users registered with the legacy system (SHA-256 hash, plaintext private keys) are not
  compatible with the new security system
- Legacy users attempting to log in will receive a warning message and must re-register
- Private keys are decrypted only during login and stored in memory
- Private keys are cleared from memory when the session ends
- You can reset all data by deleting the database file

Cryptographic Algorithms Used
==============================
- Password Hashing: PBKDF2WithHmacSHA256 (100,000 iterations, 256-bit output)
- Symmetric Encryption: AES-256-GCM (12-byte IV, 128-bit authentication tag)
- Asymmetric Encryption: RSA-2048 (OAEP padding, SHA-256 hash, MGF1)
- Message Hashing: SHA-256
- Digital Signature: SHA256withRSA
- All algorithms are implemented using standard Java libraries (javax.crypto.*, java.security.*)
- No external cryptographic libraries are required

Architecture
============
The system follows a modular architecture with clear separation of concerns:

- CryptoService: Handles all cryptographic operations (encryption, decryption, hashing, signing)
- UserService: Manages user registration and authentication
- EmailService: Handles email sending, receiving, and verification
- InMemoryDatabase: Provides database abstraction and persistence layer
- KriptoProject: Main application entry point and user interface

Security Considerations
=======================
- All cryptographic operations use secure random number generation
- Keys are never logged or exposed in error messages
- Private keys remain encrypted at rest
- Session-based key management ensures keys are cleared after logout
- Database migration preserves data integrity while upgrading security

## Project Owners

- **[Hüseyin Alsancak](https://github.com/hhalsancak70)**
- **[Ekin Tekin](https://github.com/EkinTekin)**
- **[Dilhan Deniz](https://github.com/uteodon)**
- **[Bekir Erakbıyık](https://github.com/bekirerkbyk)**

