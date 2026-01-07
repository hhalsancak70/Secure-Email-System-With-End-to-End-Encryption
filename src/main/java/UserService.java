import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;

public class UserService {

    private final InMemoryDatabase db;
    private final CryptoService cryptoService;

    public UserService(InMemoryDatabase db, CryptoService cryptoService) {
        this.db = db;
        this.cryptoService = cryptoService;
    }

    public boolean register(String username, String password) throws GeneralSecurityException {
        if (db.usernameExists(username)) {
            return false;
        }
        
        // Salt üret
        byte[] salt = cryptoService.generateSalt();
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        
        // PBKDF2 ile parolayı hashle
        String passwordHash = cryptoService.hashPasswordWithPBKDF2(password, salt);
        
        // RSA anahtar çifti üret
        KeyPair keyPair = cryptoService.generateRsaKeyPair();
        String pub = CryptoService.encodePublicKey(keyPair.getPublic());
        
        // Private key'i kullanıcı parolasıyla şifrele
        String encryptedPrivateKey = cryptoService.encryptPrivateKey(keyPair.getPrivate(), password);
        
        // Kullanıcıyı kaydet
        InMemoryDatabase.UserRecord user = new InMemoryDatabase.UserRecord(
                username, passwordHash, saltBase64, pub, encryptedPrivateKey
        );
        db.saveUser(user);
        return true;
    }

    public InMemoryDatabase.UserRecord login(String username, String password) throws GeneralSecurityException {
        InMemoryDatabase.UserRecord user = db.getUser(username);
        if (user == null) return null;
        
        // Eski kullanıcı kontrolü (salt yoksa veya boşsa)
        if (user.saltBase64 == null || user.saltBase64.isEmpty()) {
            throw new IllegalStateException(
                "Bu kullanıcı eski güvenlik sistemiyle kaydedilmiş. " +
                "Lütfen yeni güvenlik sistemiyle yeniden kayıt olun."
            );
        }
        
        // Salt'ı al
        byte[] salt = Base64.getDecoder().decode(user.saltBase64);
        
        // PBKDF2 ile parolayı hashle ve kontrol et
        String computedHash = cryptoService.hashPasswordWithPBKDF2(password, salt);
        if (!computedHash.equals(user.passwordHash)) {
            return null;
        }
        
        // Private key'i çöz
        PrivateKey decryptedPrivateKey = cryptoService.decryptPrivateKey(user.privateKeyBase64, password);
        
        // Çözülmüş private key ile yeni bir UserRecord oluştur
        return new InMemoryDatabase.UserRecord(
                user.username,
                user.passwordHash,
                user.saltBase64,
                user.publicKeyBase64,
                user.privateKeyBase64,
                decryptedPrivateKey
        );
    }
}


