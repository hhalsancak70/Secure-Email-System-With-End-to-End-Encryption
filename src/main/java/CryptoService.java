import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Kriptografik işlemleri yöneten servis.
 * - Şifreleme (AES-GCM)
 * - Asimetrik anahtar çifti üretimi (RSA)
 * - Şifreleme için RSA ile simetrik anahtar sarma
 * - Hash (SHA-256)
 * - Dijital imza (RSA)
 */
public class CryptoService {

    // AES-GCM parametreleri
    private static final String SYMMETRIC_ALGO = "AES";
    private static final String SYMMETRIC_CIPHER = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    // RSA parametreleri
    private static final String ASYMMETRIC_ALGO = "RSA";
    private static final String ASYMMETRIC_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int RSA_KEY_SIZE = 2048;

    private static final String HASH_ALGO = "SHA-256";
    private static final String SIGN_ALGO = "SHA256withRSA";
    
    // PBKDF2 parametreleri
    private static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITERATIONS = 100000; // Güvenlik için yüksek iterasyon sayısı
    private static final int PBKDF2_KEY_LENGTH = 256; // 256 bit = 32 byte
    private static final int SALT_LENGTH = 16; // 16 byte salt

    private final SecureRandom secureRandom = new SecureRandom();

    public KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYMMETRIC_ALGO);
        keyGen.initialize(RSA_KEY_SIZE);
        return keyGen.generateKeyPair();
        }

    public SecretKey generateAesKey() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGO);
        keyGen.init(256);
        return keyGen.generateKey();
    }

    /**
     * Rastgele bir salt değeri üretir.
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * PBKDF2WithHmacSHA256 kullanarak parolayı hashler.
     * @param password Kullanıcı parolası
     * @param salt Salt değeri
     * @return Base64 kodlanmış hash değeri
     */
    public String hashPasswordWithPBKDF2(String password, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGO);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
        SecretKey key = factory.generateSecret(spec);
        byte[] hash = key.getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Eski SHA-256 hash metodu (geriye dönük uyumluluk için tutuldu, kullanılmıyor).
     * @deprecated PBKDF2 kullanın
     */
    @Deprecated
    public String hashPassword(String password) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public String[] encryptMessage(String plaintext, PublicKey recipientPublicKey) throws GeneralSecurityException {
        SecretKey aesKey = generateAesKey();

        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        byte[] cipherText = cipher.doFinal(plaintext.getBytes());

        Cipher rsaCipher = Cipher.getInstance(ASYMMETRIC_CIPHER);
        rsaCipher.init(Cipher.WRAP_MODE, recipientPublicKey);
        byte[] wrappedKey = rsaCipher.wrap(aesKey);

        String encMessage = Base64.getEncoder().encodeToString(cipherText);
        String encKey = Base64.getEncoder().encodeToString(wrappedKey);
        String encIv = Base64.getEncoder().encodeToString(iv);

        return new String[]{encMessage, encKey, encIv};
    }

    public String decryptMessage(String encMessage, String encKey, String encIv, PrivateKey recipientPrivateKey)
            throws GeneralSecurityException {
        byte[] cipherText = Base64.getDecoder().decode(encMessage);
        byte[] wrappedKey = Base64.getDecoder().decode(encKey);
        byte[] iv = Base64.getDecoder().decode(encIv);

        Cipher rsaCipher = Cipher.getInstance(ASYMMETRIC_CIPHER);
        rsaCipher.init(Cipher.UNWRAP_MODE, recipientPrivateKey);
        Key aesKey = rsaCipher.unwrap(wrappedKey, SYMMETRIC_ALGO, Cipher.SECRET_KEY);

        Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        byte[] plainBytes = cipher.doFinal(cipherText);
        return new String(plainBytes);
    }

    public String computeHash(String message) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
        byte[] hash = md.digest(message.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public String signHash(String hashBase64, PrivateKey privateKey) throws GeneralSecurityException {
        byte[] hashBytes = Base64.getDecoder().decode(hashBase64);
        Signature signature = Signature.getInstance(SIGN_ALGO);
        signature.initSign(privateKey);
        signature.update(hashBytes);
        byte[] sigBytes = signature.sign();
        return Base64.getEncoder().encodeToString(sigBytes);
    }

    public boolean verifySignature(String hashBase64, String signatureBase64, PublicKey publicKey)
            throws GeneralSecurityException {
        byte[] hashBytes = Base64.getDecoder().decode(hashBase64);
        byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
        Signature signature = Signature.getInstance(SIGN_ALGO);
        signature.initVerify(publicKey);
        signature.update(hashBytes);
        return signature.verify(sigBytes);
    }

    public static String encodePublicKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey decodePublicKey(String base64) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(ASYMMETRIC_ALGO);
        return kf.generatePublic(spec);
    }

    public static String encodePrivateKey(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PrivateKey decodePrivateKey(String base64) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(ASYMMETRIC_ALGO);
        return kf.generatePrivate(spec);
    }

    /**
     * Private key'i kullanıcı parolasıyla AES-GCM kullanarak şifreler.
     * @param privateKey Şifrelenecek private key
     * @param password Kullanıcı parolası
     * @return Base64 kodlanmış şifrelenmiş private key ve IV (format: "encryptedKeyBase64:ivBase64")
     */
    public String encryptPrivateKey(PrivateKey privateKey, String password) throws GeneralSecurityException {
        // Paroladan AES anahtarı türet (PBKDF2 kullanarak)
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGO);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
        SecretKey derivedKey = factory.generateSecret(spec);
        SecretKeySpec aesKey = new SecretKeySpec(derivedKey.getEncoded(), SYMMETRIC_ALGO);
        
        // IV üret
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        
        // Private key'i şifrele
        byte[] privateKeyBytes = privateKey.getEncoded();
        Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] encryptedKey = cipher.doFinal(privateKeyBytes);
        
        // Salt, IV ve şifrelenmiş key'i birleştir (format: "saltBase64:ivBase64:encryptedKeyBase64")
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedKey);
        
        return saltBase64 + ":" + ivBase64 + ":" + encryptedKeyBase64;
    }

    /**
     * Şifrelenmiş private key'i kullanıcı parolasıyla çözer.
     * @param encryptedPrivateKeyBase64 Şifrelenmiş private key (format: "saltBase64:ivBase64:encryptedKeyBase64")
     * @param password Kullanıcı parolası
     * @return Çözülmüş private key
     */
    public PrivateKey decryptPrivateKey(String encryptedPrivateKeyBase64, String password) throws GeneralSecurityException {
        // Format: "saltBase64:ivBase64:encryptedKeyBase64"
        String[] parts = encryptedPrivateKeyBase64.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Geçersiz şifrelenmiş private key formatı");
        }
        
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] encryptedKey = Base64.getDecoder().decode(parts[2]);
        
        // Paroladan AES anahtarı türet
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGO);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
        SecretKey derivedKey = factory.generateSecret(spec);
        SecretKeySpec aesKey = new SecretKeySpec(derivedKey.getEncoded(), SYMMETRIC_ALGO);
        
        // Private key'i çöz
        Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        
        // Private key nesnesini oluştur
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedKeyBytes);
        KeyFactory kf = KeyFactory.getInstance(ASYMMETRIC_ALGO);
        return kf.generatePrivate(keySpec);
    }
}


