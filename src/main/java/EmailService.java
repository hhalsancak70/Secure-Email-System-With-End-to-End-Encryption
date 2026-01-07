import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class EmailService {

    private final InMemoryDatabase db;
    private final CryptoService cryptoService;

    public EmailService(InMemoryDatabase db, CryptoService cryptoService) {
        this.db = db;
        this.cryptoService = cryptoService;
    }

    public InMemoryDatabase.MessageRecord sendMessage(InMemoryDatabase.UserRecord sender, String toUser, String content)
            throws GeneralSecurityException {
        InMemoryDatabase.UserRecord recipient = db.getUser(toUser);
        if (recipient == null || sender == null) {
            throw new IllegalArgumentException("Gönderici veya alıcı kullanıcı bulunamadı.");
        }
        
        if (sender.decryptedPrivateKey == null) {
            throw new IllegalStateException("Gönderici kullanıcı giriş yapmamış. Private key çözülememiş.");
        }

        PublicKey recipientPublicKey = CryptoService.decodePublicKey(recipient.publicKeyBase64);
        PrivateKey senderPrivateKey = sender.decryptedPrivateKey;

        String[] encParts = cryptoService.encryptMessage(content, recipientPublicKey);
        String encMessage = encParts[0];
        String encKey = encParts[1];
        String iv = encParts[2];

        String hashBase64 = cryptoService.computeHash(content);
        String signatureBase64 = cryptoService.signHash(hashBase64, senderPrivateKey);

        return db.saveMessage(sender.username, toUser, encMessage, encKey, iv, hashBase64, signatureBase64);
    }

    public List<InMemoryDatabase.MessageRecord> getInbox(String username) {
        return db.getMessagesForUser(username);
    }

    public String decryptMessageForUser(InMemoryDatabase.MessageRecord msg, InMemoryDatabase.UserRecord recipient)
            throws GeneralSecurityException {
        if (recipient == null) {
            throw new IllegalArgumentException("Kullanıcı bulunamadı.");
        }
        
        if (recipient.decryptedPrivateKey == null) {
            throw new IllegalStateException("Kullanıcı giriş yapmamış. Private key çözülememiş.");
        }
        
        PrivateKey recipientPrivateKey = recipient.decryptedPrivateKey;
        return cryptoService.decryptMessage(
                msg.encMessage,
                msg.encKey,
                msg.iv,
                recipientPrivateKey
        );
    }

    public boolean verifyMessageIntegrityAndSignature(InMemoryDatabase.MessageRecord msg, String plaintext)
            throws GeneralSecurityException {
        String recomputedHash = cryptoService.computeHash(plaintext);
        if (!recomputedHash.equals(msg.hashBase64)) {
            return false;
        }

        InMemoryDatabase.UserRecord sender = db.getUser(msg.fromUser);
        if (sender == null) {
            return false;
        }
        PublicKey senderPublicKey = CryptoService.decodePublicKey(sender.publicKeyBase64);
        return cryptoService.verifySignature(msg.hashBase64, msg.signatureBase64, senderPublicKey);
    }
}


