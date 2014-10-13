package com.yas.cryptographyapp.methods;

import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.*;

/**
 * Simple cryptography using specified secret key.
 * 
 * @author YAS
 * @version 1.0
 */
public class SimpleCryptography {

	/**
	 * Default constructor.
	 */
	public SimpleCryptography() {
		super();
	}

	/**
	 * secret key.
	 */
	private static final byte[] keyValue = new byte[] { 'j', 'f', 'i', 's',
			'#', 's', '2', 'S', 'e', '4', 'r', 'e', '5', 'K', 'g', ')' };

	/**
	 * Encrypt the given string value.
	 * 
	 * @param valueToEnc
	 *            string value for encrypt.
	 * @return encrypted string value.
	 * @throws Exception
	 */
	public final String encrypt(final String valueToEnc) throws Exception {
		Key key = generateKey();
		// Returns a Cipher object that implements the specified transformation.
		Cipher c = Cipher.getInstance("AES");
		// Initializes this cipher with a key.
		c.init(Cipher.ENCRYPT_MODE, key);
		// Finishes a multiple-part encryption depending on how this cipher was
		// initialized.
		byte[] encValue = c.doFinal(valueToEnc.getBytes());
		String encryptedValue = new BASE64Encoder().encode(encValue);
		return encryptedValue;
	}

	/**
	 * Decrypt the given string value.
	 * 
	 * @param encryptedValue
	 *            encrypted string for decrypt.
	 * @return decrypted string value.
	 * @throws Exception
	 */
	public final String decrypt(final String encryptedValue) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedValue);
		byte[] decValue = c.doFinal(decordedValue);
		String decryptedValue = new String(decValue);
		return decryptedValue;
	}

	/**
	 * Genarate the key using secret value.
	 * 
	 * @return genarated key.
	 * @throws Exception
	 */
	private final Key generateKey() throws Exception {
		Key key = new SecretKeySpec(keyValue, "AES");
		return key;
	}
}