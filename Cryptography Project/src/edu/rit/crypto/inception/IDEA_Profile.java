package edu.rit.crypto.inception;

import java.util.Arrays;

/**
 * Time profile for IDEA
 * @author William, Brian
 *
 */
public class IDEA_Profile {

	public static void main(String[] args) {
		long start, end;
		start = System.currentTimeMillis();
		
		if (args.length != 1)
		{
			System.out.println("Usage: IDEA_Profile encryptions");
			System.exit(0);
		}
		int n = Integer.parseInt(args[0]);
		
		byte[] k = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		byte[] p = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		//byte[] q = new byte[8];
		
		BlockCipher ideaCipher = new IDEA();
		ideaCipher.setKey(k);
		
		while (n > 0)
		{
			//System.arraycopy(p, 0, q, 0, 8);
			ideaCipher.encrypt(p);
			n--;
			Arrays.fill(p, (byte)0x00);
			//p[0]=0x00;p[1]=0x00;p[2]=0x00;p[3]=0x00;p[4]=0x00;p[5]=0x00;p[6]=0x00;p[7]=0x00;
			//why aren't these faster than p.clone()?!?!
		}
		
		end = System.currentTimeMillis();
		
		System.out.println("elapsed time = "+(end-start)+" ms");
	}
}
