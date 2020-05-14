using System;
using System.Collections;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using CryptoPals;

namespace chal11
{
    class Program
    {
	enum DetectedCipherMode {
	    ECB,
	    CBC
	};

	static DetectedCipherMode DetectECBvsCBC( byte[] cipherdata ){
	    // i think if we have any duplicated blocks of data at all that's sufficient
	    // because then it's distinguishable from random data
	    
	    HashSet<BigInteger> getdupes = new HashSet<BigInteger>();
	    int blocksize = 16;
	    int dupes = 0;
	    
	    for( int i = 0; i < cipherdata.Length; i += blocksize ){
		byte[] block = new byte[blocksize];
		Buffer.BlockCopy( cipherdata, i, block, 0, blocksize );
		BigInteger bigint = new BigInteger( block );
		if( !getdupes.Add( bigint ) ){
		    dupes++;
		}
	    }

	    if( dupes > 0 ){
		return DetectedCipherMode.ECB;
	    }
	    else {
		return DetectedCipherMode.CBC;
	    }
	}

	static byte[] AddRandomBullshitData( byte[] input ){
	    RNGCryptoServiceProvider CSPRNG = new RNGCryptoServiceProvider();
	    Random rng = new Random();
	    int pre = rng.Next( 5, 11 ); //inclusive lower bound, exclusive upper bound because fuck you
	    int post = rng.Next( 5, 11 );
	    int newsize = input.Length + pre + post;

	    byte[] output = new byte[ newsize ];
	    
	    CSPRNG.GetBytes( output, 0, pre );
	    Buffer.BlockCopy( input, 0, output, pre, input.Length );
	    CSPRNG.GetBytes( output, pre + input.Length, post );

	    return output;
	}
			 	
	static DetectedCipherMode EncryptionOracle( string input ){
	    int blocksize = 16;
	    byte[] preinput = AddRandomBullshitData( Encoding.UTF8.GetBytes( input ) );
	    byte[] plaindata = PKCS.Pad( preinput, blocksize );
	    	    
	    RNGCryptoServiceProvider CSPRNG = new RNGCryptoServiceProvider();
	    Random rng = new Random();
	    
	    //generate a random AES key
	    byte[] RandomAESKey = new byte[blocksize];
	    CSPRNG.GetBytes( RandomAESKey );

	    if( rng.Next(2) > 0 ){
		//Console.WriteLine( "shhh, choosing ECB mode" );
		
		byte[] ECBcipherdata = new byte[ plaindata.Length ];
		for( int i = 0; i < plaindata.Length; i += blocksize ){
		    byte[] block = new byte[blocksize];
		    Buffer.BlockCopy( plaindata, i, block, 0, blocksize );
		    
		    byte[] result = ShittyAES.EncryptECB( block, RandomAESKey );

		    Buffer.BlockCopy( result, 0, ECBcipherdata, i, blocksize );
		}

		return DetectECBvsCBC( ECBcipherdata );
	    }
	    else {
		//Console.WriteLine( "shhh, choosing CBC mode" );

		byte[] randomIV = new byte[blocksize];
		CSPRNG.GetBytes( randomIV );

		byte[] CBCcipherdata = ShittyAES.EncryptCBC( plaindata, RandomAESKey, randomIV, 128 );
		
		return DetectECBvsCBC( CBCcipherdata );
	    }
	}
	
        static void Main(string[] args)
        {
	    // this took me a long time to figure out but imagine that picture of tux from wikipedia's article
	    // on weaknesses of ECB mode.  You want plaintext that is highly uniform so it shows up in the ciphertext.
	    //
            // per the problem spec, we need to prepend and append 5-10 bytes (randomly) to the plaintext
	    // that means the first block of ciphertext will have 5-10 bytes we can't control, however
	    // since we can chose our plaintext we can choose one that is sufficiently long to get
	    // 3-4 blocks in a row of controllable ciphertext, which if it's something like ZZZZZZZZZZZZ
	    // should be obvious when encrypted via ECB

	    for( int i = 0; i < 100; i++ ){
		Console.WriteLine("The Oracle discerns that the Gods have chosen to use {0}!", EncryptionOracle( "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").ToString() );
	    }
        }
    }
}
