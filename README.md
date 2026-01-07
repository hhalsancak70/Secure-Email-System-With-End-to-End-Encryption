# Secure Email System (Java Console Application)

<div align="center">
  <img src="https://cdn-icons-png.flaticon.com/512/2092/2092663.png" alt="Secure Email Logo" width="150" height="150"/>
  
  <br>

  [![Java](https://img.shields.io/badge/Java-8%2B-orange.svg?style=for-the-badge&logo=java&logoColor=white)](https://www.oracle.com/java/)
  [![Build](https://img.shields.io/badge/Build-Maven-blue.svg?style=for-the-badge&logo=apachemaven&logoColor=white)](https://maven.apache.org/)
  [![Security](https://img.shields.io/badge/Security-AES%20%7C%20RSA-red.svg?style=for-the-badge&logo=security&logoColor=white)]()
  [![Database](https://img.shields.io/badge/Database-SQLite-003B57.svg?style=for-the-badge&logo=sqlite&logoColor=white)]()

</div>

---

## 📝 About the Project

**Secure Email System** is a secure, end-to-end encrypted email application implemented in Java. It features robust cryptographic protections for user authentication and message confidentiality.

This system demonstrates industry-standard security practices including **password-based key derivation**, **encrypted key storage**, and **hybrid encryption schemes**.

---

## 🚀 Security Features

| Feature | Description |
| :--- | :--- |
| **Password Security** | Passwords are hashed using PBKDF2WithHmacSHA256 with a unique 16-byte salt and 100,000 iterations. |
| **Private Key Protection** | RSA private keys are encrypted using AES-GCM (derived from the user's password) and never stored in plaintext. |
| **Message Confidentiality** | Messages are secured using Hybrid Encryption (AES-GCM for content + RSA for key exchange). |
| **Integrity & Authenticity** | Every message is digitally signed (SHA256withRSA) to verify the sender and ensure no tampering occurred. |
| **Defense-in-Depth** | Even if the database is compromised, private keys remain protected without the user's password. |

---

## 🛠️ Cryptographic Specifications

<details>
<summary>Click to expand technical details</summary>

The system uses standard Java libraries (`javax.crypto.*`, `java.security.*`) with no external crypto dependencies.

| Component | Algorithm Used | Details |
| :--- | :--- | :--- |
| **Password Hashing** | `PBKDF2WithHmacSHA256` | 100,000 iterations, 256-bit output. |
| **Symmetric Encryption** | `AES-256-GCM` | 12-byte IV, 128-bit authentication tag. |
| **Asymmetric Encryption** | `RSA-2048` | OAEP padding, SHA-256 hash, MGF1. |
| **Message Hashing** | `SHA-256` | Verifies data integrity. |
| **Digital Signature** | `SHA256withRSA` | Ensures authenticity and non-repudiation. |

</details>

---

## 📋 Requirements

* **Java 8** or higher JDK
* **Maven 3.6+** (Recommended)
* *(Optional)* SQLite JDBC driver for manual builds

---

## 🔧 Installation & Usage

### **Option 1: Using Maven (Recommended)**

1.  **Navigate to the project directory:**
    ```bash
    cd project-directory
    ```

2.  **Download dependencies and compile:**
    ```bash
    mvn clean compile
    ```

3.  **Run the application:**
    ```bash
    mvn exec:java -Dexec.mainClass="KriptoProject"
    ```

4.  **Alternatively, build a JAR file:**
    ```bash
    mvn package
    java -jar target/email-system-1.0.0-jar-with-dependencies.jar
    ```

### **Option 2: Manual Build (No Maven)**

<details>
<summary>Click to expand manual instructions</summary>

1.  Download SQLite JDBC driver from [GitHub Releases](https://github.com/xerial/sqlite-jdbc/releases).
2.  Place `sqlite-jdbc-X.X.X.jar` in the project directory.
3.  **Compile:**
    ```bash
    javac -cp sqlite-jdbc-*.jar src/main/java/*.java
    ```
4.  **Run:**
    ```bash
    # Linux/Mac:
    java -cp .:sqlite-jdbc-*.jar:src/main/java KriptoProject
    
    # Windows:
    java -cp .;sqlite-jdbc-*.jar;src/main/java KriptoProject
    ```
</details>

---

## 🔄 Application Workflow

1.  **User Registration:**
    * System generates a random Salt.
    * Hashes Password using PBKDF2.
    * Generates RSA Key Pair.
    * Encrypts Private Key with AES-GCM (using a key derived from the password).
    * Stores encrypted data in SQLite.

2.  **User Login:**
    * Authenticates the user hash.
    * Decrypts the Private Key and stores it in volatile memory (RAM) for the session.

3.  **Sending Email:**
    * Encrypts the message body with AES.
    * Encrypts the AES key with the Recipient's Public RSA Key.
    * Signs the message hash with the Sender's Private RSA Key.

4.  **Receiving Email:**
    * Decrypts the AES key using the Recipient's Private Key.
    * Verifies the Digital Signature using the Sender's Public Key.

---

## 💾 Database Schema

The data is stored in a SQLite database (`email_system.db`), which is automatically created on the first run.

### **Users Table**
| Column | Type | Description |
| :--- | :--- | :--- |
| `username` | TEXT (PK) | Unique user identifier. |
| `password_hash` | TEXT | PBKDF2 hash of the password. |
| `salt_base64` | TEXT | Base64-encoded salt. |
| `public_key_base64` | TEXT | RSA Public Key. |
| `private_key_base64`| TEXT | Encrypted Private Key (salt:iv:encryptedKey). |

### **Messages Table**
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER (PK)| Auto-increment ID. |
| `from_user` | TEXT | Sender username. |
| `to_user` | TEXT | Recipient username. |
| `enc_message` | TEXT | Encrypted message content. |
| `enc_key` | TEXT | Encrypted AES key. |
| `iv` | TEXT | Initialization Vector. |
| `hash_base64` | TEXT | Message hash for integrity check. |
| `signature_base64`| TEXT | Digital signature for verification. |

---

## ⚠️ Important Notes

* **Legacy Incompatibility:** Users registered with the legacy system (SHA-256 hash, plaintext private keys) are not compatible with this version and must re-register.
* **Memory Security:** Private keys are decrypted only during login and stored in memory. They are cleared when the session ends.
* **Reset:** You can factory reset the application by deleting the `email_system.db` file.

---

## 👥 Project Owners

<div align="center">

| Team Member | GitHub Profile |
| :---: | :---: |
| **Hüseyin Alsancak** | [@hhalsancak70](https://github.com/hhalsancak70) |
| **Ekin Tekin** | [@EkinTekin](https://github.com/EkinTekin) |
| **Dilhan Deniz** | [@uteodon](https://github.com/uteodon) |
| **Bekir Erkbiyik** | [@bekirerkbyk](https://github.com/bekirerkbyk) |

</div>

