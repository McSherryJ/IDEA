package edu.rit.crypto.inception;

import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * Tests IDEA
 * @author William
 *
 */
public class IDEA_Test
{
	
	public static void main(String[] args)
	{
		// First test vector
		String hexKey = "31323334353637383930313233343536";
		String hexPlaintext = "6F7269676E6D7367";
		
		byte[] k = Hex.toByteArray(hexKey);
		byte[] p = Hex.toByteArray(hexPlaintext);
		
		System.out.println("Plaintext: " + Hex.toString(p));
		System.out.println("Key: " + Hex.toString(k));
		
		IDEA cipher = new IDEA();
		cipher.setKey(k);
		cipher.encrypt(p);
		
		String hexCiphertext = Hex.toString(p);
		String hexAns = "43DA094FC6379D16";
		
		System.out.println("Ciphertext: " + hexCiphertext);
		System.out.println("Did the first test pass? " + hexAns.equalsIgnoreCase(hexCiphertext) + "\n");
		
		// Second test vector
		cipher = new IDEA();
		p = new byte[cipher.blockSize()];
		Packing.unpackShortBigEndian(new short[]{0, 1, 2, 3}, 0, p, 0, 4);
		k = new byte[cipher.keySize()];
		Packing.unpackShortBigEndian(new short[]{1, 2, 3, 4, 5, 6, 7, 8}, 0, k, 0, 8);
		
		System.out.println("Plaintext: " + Hex.toString(p));
		System.out.println("Key: " + Hex.toString(k));
		
		cipher.setKey(k);
		cipher.encrypt(p);
		
		byte[] c = new byte[cipher.blockSize()];
		Packing.unpackShortBigEndian(new short[]{4603, -4821, 408, 28133}, 0, c, 0, 4);
		System.out.println("Ciphertext: " + Hex.toString(c));
		System.out.println("Did the second test pass? " + Hex.toString(c).equalsIgnoreCase(Hex.toString(p)));
		
	}

}
