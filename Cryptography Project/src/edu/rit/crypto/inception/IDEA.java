package edu.rit.crypto.inception;

import edu.rit.util.Packing;

/**
 * An implementation of IDEA for the Introduction to
 * Cryptography project
 *  
 * @author Team Inception
 *
 */
public class IDEA implements BlockCipher {

	/**
	 * Precomputed maximum value for a 16-bit number; also known
	 * as 2^16 = 65,536
	 */
	private static final int SIXTEEN_BIT_MAX = (int)Math.pow(2, 16);
	
	/**
	 * An array of the generated 16-bit/2-byte (short) subkeys
	 */
	private short[] z;
	
	/**
	 * The current subkey index
	 */
	private int zIndex;
	
	/**
	 * Initializes a new IDEA object
	 */
	public IDEA()
	{
		this.z = new short[56];
		this.zIndex = 0;
	}
	
	/**
	 * Returns the size of the blocks for IDEA
	 * in bytes, which is 8 bytes, or 64 bits
	 * @return 8 bytes
	 */
	@Override
	public int blockSize() {
		return 8;
	}
	
	/**
	 * Returns the size of the secret key for IDEA
	 * in bytes, which is 16 bytes, or 128 bits
	 */
	@Override
	public int keySize() {
		return 16;
	}

	/**
	 * Sets the key for this IDEA object to
	 * the consumed key. The key should be >= keySize().
	 * If the key is larger than the keySize(), then
	 * only the first keySize() bytes are taken
	 * @param key - a 16-byte array or larger
	 */
	@Override
	public void setKey(byte[] key) {
		if(key.length < keySize()) return;
		
		this.zIndex = 0;
		long uKey = Packing.packLongBigEndian(key, 0);
		long lKey = Packing.packLongBigEndian(key, 8);
		
		// Generate the subkeys
		generateSubkeys(uKey, lKey);
	}
	
	/**
	 * Get the next subkey (may need to generate additional ones)
	 * @return the next subkey
	 */
	private short nextSubkey()
	{
		if(this.zIndex >= this.z.length)
			return -1; // Bad!
		
		return this.z[this.zIndex++];
	}
	
	/**
	 * Populates the subkey array z with all 52 necessary
	 * subkeys + 4 unused ones
	 * @param uKey - upper 64 bits of the secret key
	 * @param lKey - lower 64 bits of the secret key
	 */
	private void generateSubkeys(long uKey, long lKey)
	{
		// Generate keys 7 times which yields 52 keys
		int i = 0;
		do
		{
			// Extract the subkeys
			Packing.unpackLongBigEndian(uKey, this.z, 8*i);
			Packing.unpackLongBigEndian(lKey, this.z, 8*i + 4);
			
			// Perform the cyclic 25-bit shift
			long uShiftedBits = (uKey & 0xFFFFFF10) >>> 39;
			long lShiftedBits = (lKey & 0xFFFFFF10) >>> 39;
			uKey = uKey << 25;
			lKey = lKey << 25;
			uKey = uKey | lShiftedBits;
			lKey = lKey | uShiftedBits;
			
			i++;
		} while(i < 7);
	}
	

	/**
	 * Encrypts a 64-bit/8-byte value
	 */
	@Override
	public void encrypt(byte[] text) {
		// Pack the bytes into shorts for processing
		short[] x = new short[5]; // 5 to keep subscript = index
		x[1] = Packing.packShortBigEndian(text, 0);
		x[2] = Packing.packShortBigEndian(text, 2);
		x[3] = Packing.packShortBigEndian(text, 4);
		x[4] = Packing.packShortBigEndian(text, 6);
		
		// 8 Rounds
		for(int i = 0; i < 8; i++)
			round(x);
		
		// Output Transformation
		outputTransformation(x);
		
		// Unpack encrypted shorts back into the byte array
		Packing.unpackShortBigEndian(x[1], text, 0);
		Packing.unpackShortBigEndian(x[2], text, 2);
		Packing.unpackShortBigEndian(x[3], text, 4);
		Packing.unpackShortBigEndian(x[4], text, 6);
	}
	
	/**
	 * Performs a round as defined in the IDEA specification
	 *@param x - an array of the x values where the subscript = index
	 */
	private void round(short[] x)
	{
		short a = multiply(x[1], nextSubkey());
		short b = add(x[2], nextSubkey());
		short c = add(x[3], nextSubkey());
		short d = multiply(x[4], nextSubkey());
		short e = multiply(xor(a, c), nextSubkey());
		short f = multiply(add(e, xor(b, d)), nextSubkey());
		short g = add(e, f);
		
		x[1] = xor(a, f);
		x[2] = xor(c, f);
		x[3] = xor(b, g);
		x[4] = xor(d, g);
	}
	
	/**
	 * Performs the output transformation as defined
	 * in the IDEA specification after the 8th round
	 * @param x - an array of the x values where the subscript = index
	 */
	private void outputTransformation(short[] x)
	{
		short temp = x[2];
		x[1] = multiply(x[1], nextSubkey());
		x[2] = add(x[3], nextSubkey());
		x[3] = add(temp, nextSubkey());
		x[4] = multiply(x[4], nextSubkey());
	}
	
	/**
	 * 16-bit addition mod 2^16
	 * @param a - a 16-bit value
	 * @param b - another 16-bit value
	 * @return the sum of 'a' and 'b' mod 2^16
	 */
	private short add(short a, short b)
	{
		int x = a < 0 ? SIXTEEN_BIT_MAX + a : a; // 2's complement
		int y = b < 0 ? SIXTEEN_BIT_MAX + b : b;
		return (short)((x + y) % SIXTEEN_BIT_MAX);
	}
	
	/**
	 * 16-but multiplication mod (2^16 + 1) where
	 * 0 = 2^16
	 * @param a - a 16-bit value
	 * @param b - another 16-bit value
	 * @return the product of 'a' and 'b' mod (2^16 + 1)
	 * where 0 = 2^16
	 */
	private short multiply(short a, short b)
	{
		long x = a < 0 ? SIXTEEN_BIT_MAX + a : a; // 2's complement
	    long y = b < 0 ? SIXTEEN_BIT_MAX + b : b;
		
		// Have to treat 0 as 2^16
		if (x == 0) x = SIXTEEN_BIT_MAX;
		if (y == 0) y = SIXTEEN_BIT_MAX;
		
		long result = (x * y) % (SIXTEEN_BIT_MAX + 1);
		
		return result == SIXTEEN_BIT_MAX ? 0 : (short)result; 
	}
	
	/**
	 * 16-bit XOR
	 * @param a - a 16-bit value
	 * @param b - another 16-bit value
	 * @return the result of 'a' xor 'b'
	 */
	private short xor(short a, short b)
	{
		return (short)(a ^ b);
	}

}
