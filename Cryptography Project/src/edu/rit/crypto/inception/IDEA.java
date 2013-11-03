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
	 * One more than the maximum value for a 16-bit number; also known
	 * as 2^16 = 65,536 = 0x10000
	 */
	private static final int TWO_TO_THE_16 = (int)Math.pow(2, 16);
	
	/**
	 * An array of the generated 16-bit/2-byte (short) ENCRYPTION subkeys
	 */
	private short[] z;
	
	/**
	 * An array of the generated 16-bit/2-byte (short) DECRYPTION subkeys
	 */
	private short[] y;
	
	/**
	 * The current ENCRYPTION subkey index
	 */
	private int zIndex;
	
	/**
	 * The current DECRYPTION subkey index
	 */
	private int yIndex;
	
	/**
	 * whether we are encrypting (true) or decrypting (false)
	 */
	private boolean encrypting;
	
	/**
	 * Initializes a new IDEA object
	 */
	public IDEA()
	{
		this.z = new short[56];
		this.y = new short[56];
		this.zIndex = 0;
		this.yIndex = 0;
		encrypting = true;
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
		this.yIndex = 0;
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
		if (encrypting)
		{
			if(this.zIndex >= this.z.length)
				return -1; // Bad!
			
			return this.z[this.zIndex++];
		}
		else
		{
			if(this.yIndex >= this.y.length)
				return -1; // Bad!
			
			return this.y[this.yIndex++];	
		}
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
		// Technically we get 56 keys but the last 4 are unnecessary
		int i = 0;
		do
		{
			// Extract the ENCRYPTION subkeys
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
		
		// Calculate the DECRYPTION subkeys
		for (int j = 0; j < 52; j++)
		{
			int oppositePosition = (8 - (j / 6)) * 6 + (j % 6);
			if (j % 6 == 0 || j % 6 == 3)
			{
				int mulInverse = this.z[oppositePosition] & 0x0000ffff;
				if (mulInverse == 0) mulInverse = TWO_TO_THE_16; 
				int result = (euclideanAlg(1, 0, TWO_TO_THE_16 + 1, 0, 1, mulInverse)[1] + 5 * (TWO_TO_THE_16 + 1)) % (TWO_TO_THE_16 + 1);
				if (result == TWO_TO_THE_16) result = 0;
				this.y[j] = (short)result;
			}
			else if (j % 6 == 1 || j % 6 == 2)
			{
				if (j < 6 || 47 < j)
				{
					int result = TWO_TO_THE_16 - (((int)this.z[oppositePosition]) & 0xffff);
					if (result == TWO_TO_THE_16) result = 0;
					this.y[j] = (short)result;
				}
				else
				{
					int result;
					if (j % 6 == 1) result = TWO_TO_THE_16 - (((int)this.z[oppositePosition + 1]) & 0xffff);
					else result = TWO_TO_THE_16 - (((int)this.z[oppositePosition - 1]) & 0xffff);
					if (result == TWO_TO_THE_16) result = 0;
					this.y[j] = (short)result;
				}
			}
			else 
			{
				//spec has some disagreement on this point.  it's either z[oppositePosition], 
				// or z[oppositePosition - 6], or z[j]
				this.y[j] = this.z[oppositePosition - 6];
			}
		}
	}
	
	/**
	 * Calculate the coefficients for the Diophantine equations used in the Euclidean Algorithm. 
	 * The equations are as follows:
	 * first1 * x + second1 * y = result1
	 * first2 * x + second2 * y = result2
	 * where x and y are the numbers that we are finding the gcd of.  Any 2 different equations 
	 * can be used, but typically one would do the following:
	 * 1 * x + 0 * y = xValue
	 * 0 * x + 1 * y = yValue
	 * 
	 * @param first1 is the coefficient of the first number in the first gcd calculation 
	 * @param second1 is the coefficient of the second number in the first gcd calculation
	 * @param result is the result of the first equation using the appropriate coefficients
	 * @param first2 is the coefficient of the first number in the second gcd calculation 
	 * @param second2 is the coefficient of the second number in the second gcd calculation
	 * @param result2 is the result of the first equation using the appropriate coefficients 
	 * @return an array containing first the first and second coefficients that result in 1
	 */
	private int[] euclideanAlg(int first1, int second1, int result1, 
							   int first2, int second2, int result2)
	{
		if (result1 < result2){//then swap the equations
			int temp = first1;
			first1 = first2;
			first2 = temp;
			temp = second1;
			second1 = second2;
			second2 = temp;
			temp = result1;
			result1 = result2;
			result2 = temp;
		}
		
		while (result2 != 1){
			int firstTemp = first1 - (result1 / result2) * first2;
			int secondTemp = second1 - (result1 / result2) * second2;
			int resultTemp = result1 % result2;
			first1 = first2;
			second1 = second2;
			result1 = result2;
			first2 = firstTemp;
			second2 = secondTemp;
			result2 = resultTemp;
		}
		
		return new int[] {first2, second2}; 
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
		
		// Reset subkey counters
		zIndex = 0;
		yIndex = 0;
	}
	
	/**
	 * Decrypts a 64-bit/8-byte value
	 */
	public void decrypt(byte[] text) {
		encrypting = false;
		encrypt(text);
		encrypting = true;
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
		int x = a < 0 ? TWO_TO_THE_16 + a : a; // 2's complement
		int y = b < 0 ? TWO_TO_THE_16 + b : b;
		return (short)((x + y) % TWO_TO_THE_16);
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
		long x = a < 0 ? TWO_TO_THE_16 + a : a; // 2's complement
	    long y = b < 0 ? TWO_TO_THE_16 + b : b;
		
		// Have to treat 0 as 2^16
		if (x == 0) x = TWO_TO_THE_16;
		if (y == 0) y = TWO_TO_THE_16;
		
		long result = (x * y) % (TWO_TO_THE_16 + 1);
		
		return result == TWO_TO_THE_16 ? 0 : (short)result; 
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
