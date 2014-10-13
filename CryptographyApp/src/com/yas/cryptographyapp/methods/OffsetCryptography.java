package com.yas.cryptographyapp.methods;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptography using offset values.
 * 
 * @author YAS
 * @version 1.0
 */
public class OffsetCryptography {

	/**
	 * key as byte array.
	 */
	byte[] keyBytes = new byte[] { 0x08, 0x09, 0x0a, 0x0c, 0x0c, 0x0d, 0x0e,
			0x09, 0x10, 0x11, 0x12, 0x65, 0x14, 0x15, 0x45, 0x17 };

	/**
	 * used to construct a SecretKey from a byte array.
	 */
	private SecretKeySpec key;
	/**
	 * class provides the functionality of a cryptographic cipher for encryption
	 * and decryption.
	 */
	private Cipher cipher;
	/**
	 * the number of bytes stored in output.
	 */
	private int ctLength;
	/**
	 * the number of bytes stored in output.
	 */
	private int ptLength;

	/**
	 * Default constructor that inizialize the key.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	public OffsetCryptography() throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException {
		super();
		// Adds a provider to the next position available
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// Constructs a secret key from the given byte array.
		key = new SecretKeySpec(keyBytes, "AES");
		// Returns a Cipher object that implements the specified transformation.
		cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

	}

	/**
	 * 
	 * @param plainText
	 *            to encrypt
	 * @return encrypted ciper text.
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public final byte[] doEncrypt(final String plainText)
			throws InvalidKeyException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {

		byte[] input = plainText.getBytes();
		// Initializes this cipher with a key.
		cipher.init(Cipher.ENCRYPT_MODE, key);
		// Returns the length in bytes that an output buffer would need to be in
		// order to hold the result of the next update or doFinal operation
		byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
		// Continues a multiple-part encryption
		ctLength = cipher.update(input, 0, input.length, cipherText, 0);
		// Finishes a multiple-part encryption depending on how this cipher was
		// initialized.
		ctLength += cipher.doFinal(cipherText, ctLength);
		return cipherText;
	}

	/**
	 * 
	 * @param cipherText
	 *            to decrypt.
	 * @return decrypted text.
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public final String doDecrypt(final byte[] cipherText)
			throws InvalidKeyException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {

		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
		ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
		ptLength += cipher.doFinal(plainText, ptLength);
		return new String(plainText);
	}
}
