package edu.rit.crypto.inception;

import edu.rit.util.Hex;

/**
 * Tests IDEA
 * @author William
 *
 */
public class IDEA_Test
{
	
	public static void main(String[] args)
	{
		String hexKey = "31323334353637383930313233343536";
		String hexPlaintext = "6F7269676E6D7367";
		
		byte[] k = Hex.toByteArray(hexKey);
		byte[] p = Hex.toByteArray(hexPlaintext);
		
		System.out.println("Plaintext: " + Hex.toString(p));
		System.out.println("Key: " + Hex.toString(k));
		
		IDEA cipher = new IDEA();
		cipher.setKey(k);
		cipher.encrypt(p);
		
		System.out.println("Ciphertext: " + Hex.toString(p));
	}

}
