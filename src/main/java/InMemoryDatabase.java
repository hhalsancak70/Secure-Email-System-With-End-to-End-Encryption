import java.sql.*;
import java.util.*;

/**
 * SQLite veritabanı implementasyonu.
 * Kullanıcı bilgileri, public key'ler ve mesajlar SQLite veritabanında saklanır.
 */
public class InMemoryDatabase {

    public static class UserRecord {
        public final String username;
        public final String passwordHash;
        public final String saltBase64;
        public final String publicKeyBase64;
        public final String privateKeyBase64; // Şifrelenmiş private key (Base64)
        public final java.security.PrivateKey decryptedPrivateKey; // Login'de çözülmüş private key (bellekte)

        public UserRecord(String username, String passwordHash, String saltBase64,
                          String publicKeyBase64, String privateKeyBase64) {
            this(username, passwordHash, saltBase64, publicKeyBase64, privateKeyBase64, null);
        }

        public UserRecord(String username, String passwordHash, String saltBase64,
                          String publicKeyBase64, String privateKeyBase64, java.security.PrivateKey decryptedPrivateKey) {
            this.username = username;
            this.passwordHash = passwordHash;
            this.saltBase64 = saltBase64;
            this.publicKeyBase64 = publicKeyBase64;
            this.privateKeyBase64 = privateKeyBase64;
            this.decryptedPrivateKey = decryptedPrivateKey;
        }
    }

    public static class MessageRecord {
        public final int id;
        public final String fromUser;
        public final String toUser;
        public final String encMessage;
        public final String encKey;
        public final String iv;
        public final String hashBase64;
        public final String signatureBase64;

        public MessageRecord(int id, String fromUser, String toUser,
                             String encMessage, String encKey, String iv,
                             String hashBase64, String signatureBase64) {
            this.id = id;
            this.fromUser = fromUser;
            this.toUser = toUser;
            this.encMessage = encMessage;
            this.encKey = encKey;
            this.iv = iv;
            this.hashBase64 = hashBase64;
            this.signatureBase64 = signatureBase64;
        }
    }

    private static final String DB_URL = "jdbc:sqlite:email_system.db";
    private Connection connection;

    public InMemoryDatabase() {
        initializeDatabase();
    }

    private void initializeDatabase() {
        try {
            connection = DriverManager.getConnection(DB_URL);
            createTables();
            migrateDatabase();
        } catch (SQLException e) {
            throw new RuntimeException("Veritabanı bağlantısı kurulamadı: " + e.getMessage(), e);
        }
    }

    private void createTables() throws SQLException {
        // Users tablosu
        String createUsersTable = "CREATE TABLE IF NOT EXISTS users (" +
                "username TEXT PRIMARY KEY, " +
                "password_hash TEXT NOT NULL, " +
                "salt_base64 TEXT NOT NULL, " +
                "public_key_base64 TEXT NOT NULL, " +
                "private_key_base64 TEXT NOT NULL" +
                ")";

        // Messages tablosu
        String createMessagesTable = "CREATE TABLE IF NOT EXISTS messages (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "from_user TEXT NOT NULL, " +
                "to_user TEXT NOT NULL, " +
                "enc_message TEXT NOT NULL, " +
                "enc_key TEXT NOT NULL, " +
                "iv TEXT NOT NULL, " +
                "hash_base64 TEXT NOT NULL, " +
                "signature_base64 TEXT NOT NULL, " +
                "FOREIGN KEY (from_user) REFERENCES users(username), " +
                "FOREIGN KEY (to_user) REFERENCES users(username)" +
                ")";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createUsersTable);
            stmt.execute(createMessagesTable);
        }
    }

    /**
     * Veritabanı şemasını günceller (migration).
     */
    private void migrateDatabase() throws SQLException {
        // Users tablosunda salt_base64 sütununun var olup olmadığını kontrol et
        boolean hasSaltColumn = false;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(users)")) {
            while (rs.next()) {
                String columnName = rs.getString("name");
                if ("salt_base64".equals(columnName)) {
                    hasSaltColumn = true;
                    break;
                }
            }
        }

        // Eğer salt_base64 sütunu yoksa ekle
        if (!hasSaltColumn) {
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("ALTER TABLE users ADD COLUMN salt_base64 TEXT");
                // Eski kayıtlar için boş string atarız (bu kayıtlar yeni sistemle uyumlu olmayacak)
                stmt.execute("UPDATE users SET salt_base64 = '' WHERE salt_base64 IS NULL");
            }
            System.out.println("Veritabanı şeması güncellendi: salt_base64 sütunu eklendi.");
            System.out.println("NOT: Eski kullanıcılar yeni güvenlik sistemiyle uyumlu değildir. Lütfen yeniden kayıt olun.");
        }
    }

    private Connection getConnection() {
        try {
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection(DB_URL);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Veritabanı bağlantısı alınamadı: " + e.getMessage(), e);
        }
        return connection;
    }

    public boolean usernameExists(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        try (PreparedStatement pstmt = getConnection().prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            throw new RuntimeException("Kullanıcı kontrolü yapılamadı: " + e.getMessage(), e);
        }
        return false;
    }

    public void saveUser(UserRecord user) {
        String sql = "INSERT INTO users (username, password_hash, salt_base64, public_key_base64, private_key_base64) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = getConnection().prepareStatement(sql)) {
            pstmt.setString(1, user.username);
            pstmt.setString(2, user.passwordHash);
            pstmt.setString(3, user.saltBase64);
            pstmt.setString(4, user.publicKeyBase64);
            pstmt.setString(5, user.privateKeyBase64);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Kullanıcı kaydedilemedi: " + e.getMessage(), e);
        }
    }

    public UserRecord getUser(String username) {
        String sql = "SELECT username, password_hash, salt_base64, public_key_base64, private_key_base64 FROM users WHERE username = ?";
        try (PreparedStatement pstmt = getConnection().prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return new UserRecord(
                    rs.getString("username"),
                    rs.getString("password_hash"),
                    rs.getString("salt_base64"),
                    rs.getString("public_key_base64"),
                    rs.getString("private_key_base64")
                );
            }
        } catch (SQLException e) {
            throw new RuntimeException("Kullanıcı alınamadı: " + e.getMessage(), e);
        }
        return null;
    }

    public MessageRecord saveMessage(String fromUser, String toUser,
                                     String encMessage, String encKey, String iv,
                                     String hashBase64, String signatureBase64) {
        String sql = "INSERT INTO messages (from_user, to_user, enc_message, enc_key, iv, hash_base64, signature_base64) VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = getConnection().prepareStatement(sql)) {
            pstmt.setString(1, fromUser);
            pstmt.setString(2, toUser);
            pstmt.setString(3, encMessage);
            pstmt.setString(4, encKey);
            pstmt.setString(5, iv);
            pstmt.setString(6, hashBase64);
            pstmt.setString(7, signatureBase64);
            pstmt.executeUpdate();

            // SQLite için last_insert_rowid() kullanarak son eklenen ID'yi al
            try (Statement stmt = getConnection().createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT last_insert_rowid()")) {
                int id;
                if (rs.next()) {
                    id = rs.getInt(1);
                } else {
                    throw new RuntimeException("Mesaj ID alınamadı");
                }

                return new MessageRecord(
                    id,
                    fromUser,
                    toUser,
                    encMessage,
                    encKey,
                    iv,
                    hashBase64,
                    signatureBase64
                );
            }
        } catch (SQLException e) {
            throw new RuntimeException("Mesaj kaydedilemedi: " + e.getMessage(), e);
        }
    }

    public List<MessageRecord> getMessagesForUser(String username) {
        List<MessageRecord> result = new ArrayList<>();
        String sql = "SELECT id, from_user, to_user, enc_message, enc_key, iv, hash_base64, signature_base64 FROM messages WHERE to_user = ? ORDER BY id";
        try (PreparedStatement pstmt = getConnection().prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                MessageRecord rec = new MessageRecord(
                    rs.getInt("id"),
                    rs.getString("from_user"),
                    rs.getString("to_user"),
                    rs.getString("enc_message"),
                    rs.getString("enc_key"),
                    rs.getString("iv"),
                    rs.getString("hash_base64"),
                    rs.getString("signature_base64")
                );
                result.add(rec);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Mesajlar alınamadı: " + e.getMessage(), e);
        }
        return result;
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            // Ignore
        }
    }
}


