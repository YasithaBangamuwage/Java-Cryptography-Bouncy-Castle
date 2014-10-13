package com.yas.cryptographyapp.main;

import com.yas.cryptographyapp.methods.OffsetCryptography;
import com.yas.cryptographyapp.methods.SimpleCryptography;

/**
 * Testing the cryptography methods.
 * 
 * @author YAS
 * @version 1.0
 */
public class TestCryptography {

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		// test OffsetCryptography
		System.out
				.println("==================Offset Cryptography start=============================");
		OffsetCryptography offsetCrypt = new OffsetCryptography();
		String input = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
		System.out.println("Input text      : " + input);
		System.out.println("After encrypted : "
				+ new String(offsetCrypt.doEncrypt(input)));
		System.out.println("After decrypted : "
				+ offsetCrypt.doDecrypt(offsetCrypt.doEncrypt(input)));

		System.out
				.println("=================Offset Cryptography end================================");

		System.out.println("");
		System.out.println("");

		// test SimpleCryptography
		SimpleCryptography testSimpleCrypt = new SimpleCryptography();
		System.out
				.println("==================Simple Cryptography start=============================");
		System.out.println("Input text      : " + input);
		String inputEnc = testSimpleCrypt.encrypt(input);
		System.out.println("After encrypted : " + inputEnc);
		String passwordDec = testSimpleCrypt.decrypt(inputEnc);
		System.out.println("After decrypted : " + passwordDec);

		System.out
				.println("=================Simple Cryptography end================================");

	}

}
