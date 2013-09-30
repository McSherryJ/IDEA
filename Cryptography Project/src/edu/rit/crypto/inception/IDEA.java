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
	 * The user-defined 16-byte secret key divided
	 * between 2 longs
	 */
	private long uKey;
	private long lKey;
	
	/**
	 * The derived 16-bit/2-byte (short) subkeys
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
		this.uKey = 0;
		this.lKey = 0;
		this.z = new short[8];
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
		
		this.uKey = Packing.packLongBigEndian(key, 0);
		this.lKey = Packing.packLongBigEndian(key, 8);
		
		// First subkeys are derived directly from the key
		Packing.unpackLongBigEndian(this.lKey, this.z, 4);
		Packing.unpackLongBigEndian(this.uKey, this.z, 0);
		this.zIndex = this.z.length - 1;
	}
	
	/**
	 * Get the next subkey (may need to generate additional ones)
	 * @return the next subkey
	 */
	private short nextSubkey()
	{
		if(this.zIndex < 0)
			GenerateNextSubkeys();
		
		return this.z[this.zIndex--];
	}
	
	/**
	 * Populates the subkeys array with the next 8
	 * subkeys derived from the key by shifting the
	 * key to the left by 25
	 */
	private void GenerateNextSubkeys()
	{
		this.zIndex = this.z.length - 1; // reset
		
		// Perform the cyclic 25-bit shift
		long uShiftedBits = (this.uKey & 0xFFFFFF10) >>> 39;
		long lShiftedBits = (this.lKey & 0xFFFFFF10) >>> 39;
		this.uKey = this.uKey << 25;
		this.lKey = this.lKey << 25;
		this.uKey = this.uKey | lShiftedBits;
		this.lKey = this.lKey | uShiftedBits;
		
		// Extract the subkeys
		Packing.unpackLongBigEndian(this.lKey, this.z, 4);
		Packing.unpackLongBigEndian(this.uKey, this.z, 0);
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
		return (short)((a + b) % SIXTEEN_BIT_MAX);
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
		int v1 = a;
		int v2 = b;
		if (v1 == 0) v1 = SIXTEEN_BIT_MAX;
		if (v2 == 0) v2 = SIXTEEN_BIT_MAX;
		
		int result = (v1 * v2) % (SIXTEEN_BIT_MAX + 1);
		
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
