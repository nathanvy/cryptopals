using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace ex8
{
    class Program
    {
        static void Main(string[] args)
        {
            //ECB tends to produce patterns in ciphertext that correspond to patterns in plaintext

	    string[] strinput = File.ReadAllLines("8.txt");
	    List<byte[]> ciphertexts = new List<byte[]>();

	    //yuck
	    foreach( string line in strinput ){
		byte[] bytes = new byte[ line.Length / 2];
		
		for( int i=0; i < (line.Length / 2); i++ ){
		    bytes[i] = Convert.ToByte( line.Substring(i*2, 2), 16 );
		}
		ciphertexts.Add( bytes );
	    }

	    int probablythisline = 0;
	    int currentline = 0;
	    int mostdupessofar = 0;
	    foreach( byte[] bline in ciphertexts ){
		//Console.WriteLine( BitConverter.ToString( bline ).Replace("-", "") );
		HashSet<BigInteger> getdupes = new HashSet<BigInteger>();
		int dupes = 0;

		for(int i=0; i<(bline.Length / 16); i++ ){
		    byte[] temp = new byte[16];
		    Buffer.BlockCopy(bline, i*16, temp, 0, 16);
		    BigInteger bigint = new BigInteger( temp );
		    //Console.WriteLine( BitConverter.ToString( temp ).Replace("-", "") );

		    if( !getdupes.Add( bigint ) ){
			Console.WriteLine( "found a dupe" );
			dupes++;
		    }
		    
		}
		
		if( dupes > mostdupessofar ){
		    mostdupessofar = dupes;
		    probablythisline = currentline;
		}

		dupes = 0;
		currentline++;
	    }

	    Console.WriteLine( "Probably, it's possible that maybe potentially line {0} ({1} dupes) is encrypted with AES in ECB mode: ", probablythisline, mostdupessofar );
	    Console.WriteLine( strinput[probablythisline] );
	}
    }
}
