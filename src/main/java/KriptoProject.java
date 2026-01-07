import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Scanner;

public class KriptoProject {

    private static final InMemoryDatabase db = new InMemoryDatabase();
    private static final CryptoService cryptoService = new CryptoService();
    private static final UserService userService = new UserService(db, cryptoService);
    private static final EmailService emailService = new EmailService(db, cryptoService);

    public static void main(String[] args) {
        // Program kapanırken veritabanı bağlantısını kapat
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            db.close();
        }));

        Scanner scanner = new Scanner(System.in);
        System.out.println("=== COMP417 Güvenli ve Gizli E-Posta Sistemi ===");

        boolean exit = false;
        while (!exit) {
            System.out.println("\n1) Kayıt ol");
            System.out.println("2) Giriş yap");
            System.out.println("0) Çıkış");
            System.out.print("Seçiminiz: ");
            String choice = scanner.nextLine();

            try {
                switch (choice) {
                    case "1":
                        handleRegister(scanner);
                        break;
                    case "2":
                        handleLogin(scanner);
                        break;
                    case "0":
                        exit = true;
                        break;
                    default:
                        System.out.println("Geçersiz seçim.");
                }
            } catch (Exception e) {
                System.out.println("Hata: " + e.getMessage());
            }
        }

        System.out.println("Program sonlandırıldı.");
        scanner.close();
        db.close();
    }

    private static void handleRegister(Scanner scanner) throws GeneralSecurityException {
        System.out.print("Kullanıcı adı: ");
        String username = scanner.nextLine().trim();
        System.out.print("Şifre: ");
        String password = scanner.nextLine();

        boolean ok = userService.register(username, password);
        if (ok) {
            System.out.println("Kayıt başarılı. Kullanıcı için RSA anahtar çifti üretildi ve şifre hash'lendi.");
        } else {
            System.out.println("Bu kullanıcı adı zaten alınmış.");
        }
    }

    private static void handleLogin(Scanner scanner) throws GeneralSecurityException {
        System.out.print("Kullanıcı adı: ");
        String username = scanner.nextLine().trim();
        System.out.print("Şifre: ");
        String password = scanner.nextLine();

        InMemoryDatabase.UserRecord user = userService.login(username, password);
        if (user == null) {
            System.out.println("Giriş başarısız. Kullanıcı adı veya şifre hatalı.");
            return;
        }
        System.out.println("Giriş başarılı. Hoş geldin, " + username + "!");
        userMenu(scanner, user);
    }

    private static void userMenu(Scanner scanner, InMemoryDatabase.UserRecord user) throws GeneralSecurityException {
        String username = user.username;
        boolean logout = false;
        while (!logout) {
            System.out.println("\n--- Kullanıcı Menüsü (" + username + ") ---");
            System.out.println("1) E-posta gönder");
            System.out.println("2) Gelen kutusunu listele");
            System.out.println("3) Mesajı aç ve doğrula");
            System.out.println("0) Çıkış yap");
            System.out.print("Seçiminiz: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    handleSendEmail(scanner, user);
                    break;
                case "2":
                    handleListInbox(username);
                    break;
                case "3":
                    handleOpenAndVerify(scanner, user);
                    break;
                case "0":
                    logout = true;
                    break;
                default:
                    System.out.println("Geçersiz seçim.");
            }
        }
    }

    private static void handleSendEmail(Scanner scanner, InMemoryDatabase.UserRecord sender) throws GeneralSecurityException {
        System.out.print("Alıcı kullanıcı adı: ");
        String toUser = scanner.nextLine().trim();
        System.out.print("Mesaj içeriği: ");
        String content = scanner.nextLine();

        InMemoryDatabase.MessageRecord msg = emailService.sendMessage(sender, toUser, content);
        System.out.println("Mesaj gönderildi. Mesaj ID: " + msg.id);
        System.out.println("Mesaj şifrelenmiş, anahtar alıcının public key'i ile sarılmış, hash alınmış ve imzalanmıştır.");
    }

    private static void handleListInbox(String username) {
        List<InMemoryDatabase.MessageRecord> inbox = emailService.getInbox(username);
        if (inbox.isEmpty()) {
            System.out.println("Gelen kutunuz boş.");
            return;
        }
        System.out.println("Gelen Kutusu:");
        for (InMemoryDatabase.MessageRecord msg : inbox) {
            System.out.println("ID: " + msg.id + " | Gönderen: " + msg.fromUser);
        }
    }

    private static void handleOpenAndVerify(Scanner scanner, InMemoryDatabase.UserRecord user) throws GeneralSecurityException {
        List<InMemoryDatabase.MessageRecord> inbox = emailService.getInbox(user.username);
        if (inbox.isEmpty()) {
            System.out.println("Gelen kutunuz boş.");
            return;
        }
        System.out.print("Açmak istediğiniz mesaj ID: ");
        String idStr = scanner.nextLine();
        int id;
        try {
            id = Integer.parseInt(idStr);
        } catch (NumberFormatException e) {
            System.out.println("Geçersiz ID.");
            return;
        }
        InMemoryDatabase.MessageRecord target = null;
        for (InMemoryDatabase.MessageRecord msg : inbox) {
            if (msg.id == id) {
                target = msg;
                break;
            }
        }
        if (target == null) {
            System.out.println("Bu ID'ye sahip mesaj bulunamadı.");
            return;
        }

        String plaintext = emailService.decryptMessageForUser(target, user);
        System.out.println("Şifre çözülmüş mesaj içeriği: " + plaintext);

        boolean ok = emailService.verifyMessageIntegrityAndSignature(target, plaintext);
        if (ok) {
            System.out.println("Mesaj bütünlüğü ve gönderici dijital imzası BAŞARILI şekilde doğrulandı.");
        } else {
            System.out.println("Mesaj bütünlüğü veya imza doğrulaması BAŞARISIZ! Mesaj değiştirilmiş olabilir.");
        }
    }
}



