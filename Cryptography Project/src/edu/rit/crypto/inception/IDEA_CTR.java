package edu.rit.crypto.inception;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * Encrypts or decrypts a file using CTR mode
 * @author Team Inception
 *
 */
public class IDEA_CTR {

	/**
	 * Encrypts or decrypts a file using CTR mode
	 * @param input - input file
	 * @param output - output file
	 * @param key - the 16-byte key
	 * @param nonce - the 4-byte IV (half of block size)
	 */
	public static void process_ctr(String input, String output, byte[] key, int nonce)
	{
		// Initialize the cipher of choice
		BlockCipher cipher = new IDEA();
		cipher.setKey(key);
		
		DataInputStream inputStream = null;
		DataOutputStream outputStream = null;
		try
		{
			// Initialize these very verbose streams
			inputStream = 
					new DataInputStream(
							new BufferedInputStream(
									new FileInputStream(input)));
			outputStream = 
					new DataOutputStream(
							new BufferedOutputStream(
									new FileOutputStream(output, false)));
			
			// Begin the CTR mode
			int counter = 0;
			byte[] counterBlock = new byte[8];
			byte[] inputBlock = new byte[8];
			byte[] outputBlock = new byte[8];
			int bytesRead = -1;
			while((bytesRead = inputStream.read(inputBlock, 0, 8)) != -1)
			{
				// Ready the counter block
				Packing.unpackIntBigEndian(nonce, counterBlock, 0);
				Packing.unpackIntBigEndian(counter, counterBlock, 4);
				
				// Encrypt
				cipher.encrypt(counterBlock);
				
				// XOR with input
				long ciphertext = 	Packing.packLongBigEndian(counterBlock, 0) ^
									Packing.packLongBigEndian(inputBlock, 0);
				Packing.unpackLongBigEndian(ciphertext, outputBlock, 0);
				
				// Write block to file (only write as many as read)
				outputStream.write(outputBlock, 0, bytesRead);
				
				// Increment Counter (Incrementing here to be explicit)
				counter++;
			}
		} catch( IOException ioe )
		{
			System.err.println(ioe.getMessage());
		} finally
		{
			try {
				if( inputStream != null) inputStream.close();
				if( outputStream != null) outputStream.close();
			} catch ( IOException e ) { System.err.println(e.getMessage()); }
		}
	}
	
	/**
	 * Program driver. Encrypts or decrypts a file and outputs to another file
	 * using a key and nonce
	 * @param args - [0] = input filename; [1] = output filename; 
	 * [2] = key; [3] = nonce
	 */
	public static void main(String[] args) {
		// Check number of arguments
		if( args.length != 4 )
		{
			System.err.println(	"Usage: IDEA_CTR " + 
								"<input filename> <output filename> " +
								"<16-byte key in hex> <4-byte nonce in hex>");
			return;
		}
		
		String input = args[0];
		String output = args[1];
		String hexKey = args[2];
		String hexNonce = args[3];
		byte[] key;
		byte[] nonce;
		
		// Check if the input file exists
		if( !new File(input).exists() )
		{
			System.err.println("Usage: Cannot find " + input);
			return;
		}
		
		// Check the key
		if( hexKey.startsWith("0x") )
			hexKey = hexNonce.substring(2);
		if( hexKey.length() != 32 )	// Must be 16 bytes = 32 hex characters
		{
			System.err.println("Usage: Key must be 16 bytes.");
			return;
		}
		
		key = Hex.toByteArray(hexKey);
		
		// Check nonce
		if( hexNonce.startsWith("0x") )
			hexNonce = hexNonce.substring(2);
		if( hexNonce.length() != 8 )	// Must be 4 bytes = 8 hex characters
		{
			System.err.println("Usage: Nonce must be 4 bytes.");
			return;
		}
		
		nonce = Hex.toByteArray(hexNonce);
		
		// Execute
		process_ctr(input, output, key, Packing.packIntBigEndian(nonce, 0));
	}

}
