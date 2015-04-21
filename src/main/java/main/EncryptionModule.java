package main;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptionModule {
	
	Key key;
	KeyGenerator keyGen;
	Cipher encrypt;
	
	byte[] iv = "12345678".getBytes();

	public EncryptionModule(){
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public String encrypt() {

		/*
		 * This will generate a random key, and encrypt the data
		 */
		
		String cipherText = "";

		try {
			// "BC" is the name of the BouncyCastle provider
			keyGen = KeyGenerator.getInstance("DES", "BC");
			keyGen.init(new SecureRandom());

			key = keyGen.generateKey();

			encrypt = Cipher.getInstance("DES/CBC/PKCS5Padding", "BC");

			encrypt.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			CipherOutputStream cOut = new CipherOutputStream(bOut, encrypt);

			cOut.write("plaintext".getBytes());
			cOut.close();
			
			cipherText = bOut.toString();
			System.out.println(cipherText);			
			bOut.close();
		} catch (Exception e) {
			System.err.println(e);
			System.exit(1);
		}
		return cipherText;
	}
	
	public void decrypt(String cipherText){
		try {
			encrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			CipherOutputStream cOut = new CipherOutputStream(bOut, encrypt);
			
			cOut.write(cipherText.getBytes());
			cOut.close();
			
			System.out.println(bOut.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
