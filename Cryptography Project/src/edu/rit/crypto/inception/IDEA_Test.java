package edu.rit.crypto.inception;

import edu.rit.util.Hex;
import edu.rit.util.Packing;
import java.util.Random;

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
		
		cipher.decrypt(p);
		String hexCalcPlaintext = Hex.toString(p);
		
		System.out.println("Ciphertext: " + hexCiphertext);
		System.out.println("Decrypted Plaintext: " + hexCalcPlaintext);
		System.out.println("Did the first test pass? " + hexAns.equalsIgnoreCase(hexCiphertext) 
							+ " and " + hexPlaintext.equalsIgnoreCase(hexCalcPlaintext) + "\n");
		
		// Second test vector
		p = new byte[cipher.blockSize()];
		Packing.unpackShortBigEndian(new short[]{0, 1, 2, 3}, 0, p, 0, 4);
		k = new byte[cipher.keySize()];
		Packing.unpackShortBigEndian(new short[]{1, 2, 3, 4, 5, 6, 7, 8}, 0, k, 0, 8);
		
		String hexPlaintext2 = Hex.toString(p);
		
		System.out.println("Plaintext: " + hexPlaintext2);
		System.out.println("Key: " + Hex.toString(k));
		
		cipher.setKey(k);
		cipher.encrypt(p);
		
		byte[] c = new byte[cipher.blockSize()];
		Packing.unpackShortBigEndian(new short[]{4603, -4821, 408, 28133}, 0, c, 0, 4);
		
		String hexCiphertext2 = Hex.toString(p);
		
		cipher.decrypt(p);
		
		String hexCalcPlaintext2 = Hex.toString(p);
		
		System.out.println("Ciphertext: " + hexCiphertext2);
		System.out.println("Decrypted Plaintext: " + hexCalcPlaintext2);
		System.out.println("Did the second test pass? " + Hex.toString(c).equalsIgnoreCase(hexCiphertext2) 
							+ " and " + hexPlaintext2.equalsIgnoreCase(hexCalcPlaintext2));
		
		
		//random tests
		int numTests = 500;
		System.out.println("\nBeginning "+numTests+" randomized tests:");
		
		Random randGen = new Random(567);//seed the generator so we can recreate any issues encountered
		boolean mistakeMade = false;
		for (int i = 0; i < numTests; i++)
		{
			System.out.print(".");
			if (i%100 == 99) System.out.println();
			byte[] plainText3 = new byte[cipher.blockSize()];
			randGen.nextBytes(plainText3);
			String plainTextString3 = Hex.toString(plainText3);
			byte[] key3 = new byte[cipher.keySize()];
			randGen.nextBytes(key3);
			
			cipher.setKey(key3);
			cipher.encrypt(plainText3);
			cipher.decrypt(plainText3);
			
			String decryptedString3 = Hex.toString(plainText3);
			if (!plainTextString3.equalsIgnoreCase(decryptedString3))
			{
				mistakeMade = true;
				System.out.print("\nIncorrect decryption: decrypted "+plainTextString3+" as "+decryptedString3);
			}
		}
		System.out.println("\nRandom decryption finished "+(mistakeMade ? "un" : "")+"successfully");
	}

}
