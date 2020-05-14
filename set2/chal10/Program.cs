using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections;
using System.Text;
using CryptoPals;

namespace chal10
{
    class Program
    {
	static void Main(string[] args)
        {
	    string[] strinput = File.ReadAllLines("10.txt");
	    string b64ciphertext = "";
	    foreach( string s in strinput ){
		b64ciphertext += s;
	    }

	    byte[] input = Convert.FromBase64String( b64ciphertext );
	    byte[] key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
	    byte[] iv = new byte[16];
	    for( int i=0; i<iv.Length; i++ ){
		iv[i] = (byte)0x00;
	    }
	    
	    byte[] plaindata = ShittyAES.DecryptCBC( input, key, iv, 128 );

	    Console.WriteLine( "Plaintext: ");
	    Console.WriteLine( Encoding.UTF8.GetString( plaindata ) );
	    Console.WriteLine( "" );

	    //test crypt/decrypt

	    string plaintext2 = "My rhymes are so potent that in this small segment I got all of the ladies in the next three blocks pregnant.";
	    byte[] plaindata2 = Encoding.UTF8.GetBytes( plaintext2 );
	    
	    byte[] cipherdata2 = ShittyAES.EncryptCBC( plaindata2, key, iv, 128);

	    Console.WriteLine( Encoding.UTF8.GetString( ShittyAES.DecryptCBC( cipherdata2, key, iv, 128)));

	  
        }
    }
}
