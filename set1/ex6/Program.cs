using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using CryptoPals;

namespace ex6
{
    public class Program
    {
	public static int FindKeysize( byte[] ciphertext ){
	    Dictionary<double, int> results = new Dictionary<double, int>();

	    //problem suggests 2 to 40
	    for( int keysize = 2; keysize < 41; keysize++ ){
		int keysizes = ciphertext.Length / keysize;  //i.e. the number of KEYSIZES that fit in the input, rounded down via int division
		int dist = 0;
		int keysused = 0;
		
		for( int i=1; i< keysizes; i++ ){
		    byte[] a1 = new byte[keysize];
		    byte[] a2 = new byte[keysize];
		    
		    Buffer.BlockCopy(ciphertext, keysize * (i-1), a1, 0, keysize);
		    Buffer.BlockCopy(ciphertext, keysize * i, a2, 0, keysize);

		    dist += HammingDistance.Compute( a1, a2 );
		    keysused++;
		}

		double score = (double)dist / (double)keysused;
		score /= (double)keysize;

		results.Add( score, keysize );
	    }

	    double bestscore = results.Keys.Min();

	    Console.WriteLine("Candidate key size: {0} with score of {1}", results[bestscore], bestscore);
	    return results[bestscore];
	}

	public static void Main(string[] args)
	{
	    //Console.WriteLine("Test (should be 37): {0}", HammingDistance.Compute( "this is a test", "wokka wokka!!!") );
	    
	    string[] strinput = File.ReadAllLines("/Users/nathan/Code/cryptopals/6.txt");
	    string b64ciphertext = "";
	    foreach( string s in strinput ){
		b64ciphertext += s;
	    }
	    
	    byte[] ciphertext = Convert.FromBase64String( b64ciphertext );
	    //Console.WriteLine( BitConverter.ToString( ciphertext ) );
	    int keysize = FindKeysize( ciphertext );
	    
	    //make blocks of KEYSIZE length
	    int numblocks = ciphertext.Length / keysize;
	    int leftover = ciphertext.Length % keysize;
	    
	    List<byte[]> blocks = new List<byte[]>();
	    
	    for( int i=0; i<numblocks; i++ ){
		byte[] thisblock = new byte[keysize];
		
		for( int j=0; j<keysize; j++ ){
		    thisblock[j] = ciphertext[ (keysize * i) + j ];
		}

		//Console.WriteLine( BitConverter.ToString( thisblock ) );
		blocks.Add(thisblock);
	    }

	    if( leftover != 0 ){
		byte[] lastblock = new byte[keysize];
		Array.Clear(lastblock, 0, lastblock.Count()); //zero-fill
		Buffer.BlockCopy(ciphertext, keysize * numblocks, lastblock, 0, ciphertext.Length - (keysize * numblocks) );
		blocks.Add( lastblock );

		numblocks++;
		//Console.WriteLine( "Added one block for padding, {0} total", numblocks);
	    }
	    
	    Console.WriteLine( "Transposing..." );
	    List<byte[]> transposedblocks = new List<byte[]>();
	    
	    for( int i=0; i<keysize; i++ ){
		transposedblocks.Add(new byte[numblocks]);
	    }

	    for( int idx=0; idx<keysize; idx++ ){
		for( int blk=0; blk<numblocks; blk++ ){
		    transposedblocks[idx][blk] = blocks[blk][idx];
		}
	    }
			
	    //break single byte xor
	    const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890!@#$%^&*()-=/;:., _][{}";
	    
	    Console.WriteLine("Bruteforcing blocks...");
	    List<char> blockkeys = new List<char>();
	    
	    foreach( byte[] tblock in transposedblocks ){
		Console.WriteLine(BitConverter.ToString( tblock ) );
		
		byte[] tempblock = new byte[numblocks];
		tblock.CopyTo(tempblock, 0);
		
		double score = 0;
		char candidatekey = ' ';
		//xor the block with the next item in alphabet
		//keep highest score and also the letter/key
		foreach( char possiblekey in alphabet ){

		    int i=0;
		    foreach( byte b in tblock ){
			tempblock[i] = (byte)(b ^ possiblekey);
			i++;
		    }

		    double result = FrequencyAnalysis.Evaluate( System.Text.Encoding.ASCII.GetString( tempblock ) );
		    //Console.WriteLine("Score for {0} was {1} ({2})", possiblekey, result, score );
		    if( result > score ){
			score = result;
			candidatekey = possiblekey;
		    }
		}

		blockkeys.Add(candidatekey);
	    }

	    Console.Write("Recovered key: ");
	    string key = "";
	    foreach( char c in blockkeys ){
		//Console.Write( c );
		key += c;
	    }
	    Console.WriteLine( key );
	    Console.WriteLine( "Plaintext: ");
	    int index = 0;
	    foreach( byte b in ciphertext ){
		Console.Write( (char)( b ^ key[index] ));
		index++;
		if( index >= keysize ){
		    index = 0;
		}
	    }
	}
    }
}
