package main;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.apache.commons.codec.binary.Base64;

public class EncryptionModule {

	private static final String PROVIDER = "BC";
	private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";
	private static final String KEY_GEN_ALGO = "AES";
	private static final String KEY_STORE_FORMAT = "JCEKS";

	private static final String KEY_FILE = "secret.key";

	SecretKey key;
	KeyGenerator keyGen;
	Cipher encrypt;

	byte[] iv = "1234567812345678".getBytes();

	private BufferedReader input;

	public EncryptionModule(BufferedReader input) {
		Security.addProvider(new BouncyCastleProvider());
		this.input = input;
	}

	public void generateAndSaveKey() {
		try {
			keyGen = KeyGenerator.getInstance(KEY_GEN_ALGO, PROVIDER);
			keyGen.init(new SecureRandom());
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}

		key = keyGen.generateKey();

		char[] password = promptForPassword("Please choose a password for this key: ");
		try {

			KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);
			keyStore.load(null, password);

			KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(key);

			keyStore.setEntry("secretKey", skEntry,
					new KeyStore.PasswordProtection(password));

			try (FileOutputStream fos = new java.io.FileOutputStream(KEY_FILE)) {
				keyStore.store(fos, password);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}

	}

	public char[] promptForPassword(String message) {
		System.out.println(message);
		try {
			return input.readLine().toCharArray();
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}

		return "".toCharArray();
	}

	private boolean loadKey() {

		FileInputStream fis = null;
		boolean success = false;
		try {
			KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);

			fis = new FileInputStream(KEY_FILE);
			char[] password = promptForPassword("Please enter the password for the shared key: ");

			keyStore.load(fis, password);

			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
					password);

			KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
					.getEntry("secretKey", protParam);
			key = secretKeyEntry.getSecretKey();
			success = true;

		} catch (FileNotFoundException noFileEx) {
			System.out
					.println("No key on file. Use generate-key command to create a new key.");
			success = false;
		} catch (IOException io) {
			System.out.println("Password was incorrect. Start over.");
			success = false;
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					e.printStackTrace();
					System.exit(1);
				}
			}
		}
		return success;

	}

	public String encrypt(String sourceFilePath) {
		return encrypt(sourceFilePath, null);
	}

	public String encrypt(String sourceFilePath, String destinationFilePath) {

		boolean successfulLoad = loadKey();

		if (!successfulLoad) {
			return "Key load failed.";
		}

		String cipherText = "";

		try {
			encrypt = Cipher.getInstance(CIPHER_INSTANCE, PROVIDER);

			encrypt.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			CipherOutputStream cOut = new CipherOutputStream(bOut, encrypt);

			Path path = Paths.get(sourceFilePath);
			cOut.write(Files.readAllBytes(path));
			cOut.close();

			cipherText = bOut.toString();

			//If no output file is specified, use a temporary file to save data for upload.
			if (destinationFilePath == null) {
				destinationFilePath = CloudStorage.TEMP_FILE_PATH;
			}
			try (FileOutputStream out = new FileOutputStream(
					destinationFilePath)) {
				out.write(Base64.encodeBase64(bOut.toByteArray()));
				bOut.close();
			}
			System.out.println("Encryption successful.");
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		return cipherText;
	}

	public void decrypt(String sourceFilePath, String destinationFilePath) {
		boolean successfulLoad = loadKey();

		if (!successfulLoad) {
			System.out.println("Key load failed");
		}

		try {
			encrypt = Cipher.getInstance(CIPHER_INSTANCE, PROVIDER);

			encrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			CipherOutputStream cOut = new CipherOutputStream(bOut, encrypt);

			Path path = Paths.get(sourceFilePath);
			cOut.write(Base64.decodeBase64(Files.readAllBytes(path)));
			cOut.close();

			try (OutputStream out = new BufferedOutputStream(
					new FileOutputStream(destinationFilePath))) {
				out.write(bOut.toByteArray());
				bOut.close();
			}
			System.out.println("Decryption successful.");

		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

}
