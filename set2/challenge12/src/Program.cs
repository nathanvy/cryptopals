using System;
using System.Collections;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using CryptoPals;

namespace challenge12
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

	//take input, cat it with the unknown string, shit out resulting ciphertext as a byte array
	static byte[] EncryptionOracle( string input, byte[] key ){
	    string unknownb64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	    byte[] unknowndata = Convert.FromBase64String( unknownb64 );
	    string unknownstring = Encoding.UTF8.GetString( unknowndata );
	    //Console.WriteLine( unknownstring );
	    string combo = input + unknownstring;
	    	    
	    byte[] cipherdata = ShittyAES.EncryptECB( Encoding.UTF8.GetBytes( combo ), key );

	    return cipherdata;
	}

	//just do a single block
	static string BytewiseFuckery( int index, int blocksize, string recovered, byte[] key ){
	    string lookuptable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.,;:\'\"|-={}()[]!@#$%^&*?\n\r ";

	    //                123456789abcdef
	    string payload = "aaaaaaaaaaaaaaa";
	    //string recovered = "";
	    
	    //Console.WriteLine( "index = {0}", index );
	    
	    for( int i=15; i >= 0; i-- ){
		HashSet<BigInteger> hs = new HashSet<BigInteger>();
		Dictionary<BigInteger, char> d = new Dictionary<BigInteger, char>();
		//Console.WriteLine( "iteration {0}, {1} + {2}", i, payload, recovered );
	   
		foreach( char c in lookuptable ){
		    string s = payload + recovered + c;
		    byte[] b = EncryptionOracle( s, key );
		    byte[] t = new byte[blocksize];
		    Buffer.BlockCopy( b, index, t, 0, blocksize );
		    BigInteger realt = new BigInteger(t);

		    if( hs.Add( realt ) ){
		    //if( !d.Values.Contains( t ) ){
			d.Add( realt, c );
			//Console.WriteLine(" added {0}", s );
		    }
		    else{
			//Console.WriteLine( "already present: {0}", s );
		    }
		}

		byte[] realb = EncryptionOracle( payload, key );
		byte[] realciphertext = new byte[blocksize];
		Buffer.BlockCopy( realb, index, realciphertext, 0, blocksize );

		BigInteger realint = new BigInteger( realciphertext );
		char lastchar;
		
		if( !hs.Add( realint )){
		//if( d.Values.Contains( realciphertext ) ){
		    //if can't add it then it must be present
		    //i hate linq but here we go:
		    lastchar = d[realint];
		    if( !String.IsNullOrEmpty( payload )) {
			payload = payload.Remove(0, 1);
		    }
		    recovered += lastchar;
		    hs.Clear();
		    d.Clear();
		}

	    }

	    return recovered;
	}		
	
	static void Main(string[] args)
	{
	    //generate a random AES key
	    RNGCryptoServiceProvider CSPRNG = new RNGCryptoServiceProvider();
	    byte[] RandomAESKey = new byte[16];
	    CSPRNG.GetBytes( RandomAESKey );		

	    int blocksize = 16;
	    int targetlength = EncryptionOracle( "", RandomAESKey ).Length;
	    string recovered = "";
	    //Console.WriteLine( "123456789ABCDEF" );
	    for( int i=0; i < (targetlength + blocksize); i += blocksize ){
		string result = BytewiseFuckery( i, blocksize, recovered, RandomAESKey );
		//Console.WriteLine( result );
		recovered = result;
	    }

	    Console.WriteLine("Le answer is \n" + recovered );
	}
    }
}

