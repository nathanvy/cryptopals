using System;
using System.Collections;
using System.Collections.Generic;
using CryptoPals;
using System.Text;
using System.Security.Cryptography;

namespace challenge13
{
    class Program
    {
	//parse a k=v cookie string into a dict
	static Dictionary<string, string> Parse( string input ){
	    Dictionary<string, string> d = new Dictionary<string, string>();
	    string[] inputparams = input.Split( '&' );
	    foreach( string s in inputparams ){
		string[] kvpairs = s.Split( '=' );
		d.Add( kvpairs[0], kvpairs[1] );
	    }
	    	    
	    return d;
	}

	static string ProfileFor( string email ){
	    email.Replace( '&', ' ');
	    email.Replace( '=', ' ');

	    return "email=" + email + "&uid=10&role=user";
	}

	static byte[] EncryptProfile( string inputcookie, byte[] AESkey ){
	    byte[] cipherdata = ShittyAES.EncryptECB( Encoding.UTF8.GetBytes(inputcookie), AESkey );

	    return cipherdata;
	}

	static string DecryptProfile( byte[] cipherdata, byte[] AESkey ){
	    byte[] plaindata = ShittyAES.DecryptECB( cipherdata, AESkey );

	    return Encoding.UTF8.GetString( plaindata );
	}
	
       	//I find the problem definition to be somewhat vague but let's assume I understand the challenge correctly lol
        static void Main(string[] args)
        {
	    byte[] secretkey = new byte[16];
	    RNGCryptoServiceProvider CSPRNG = new RNGCryptoServiceProvider();
	    CSPRNG.GetBytes( secretkey );
	    
	    // ok now let's build a proper ciphertext where last block will be { u, s, e, r, pad pad pad ... }
	    // and where the 2nd block with begin with { a, d, m, i, n, ... }
	    // and where the 3rd block ends with { .... &, r, o, l, e, = }
	    // then we can just mix and match
	    string padding = Encoding.UTF8.GetString( new byte[] { 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B }); //need this so that final block is valid PKCS7
	    string email = ProfileFor("bbbbbbbbbbadmin" + padding + "@fuuuuuuuuuuuck.com");
	    byte[] cipherdata = EncryptProfile( email, secretkey);
	    byte[] attackdata = new byte[ cipherdata.Length - 16 ]; //remove 16 bytes/1 block because we can drop the { u, s, e, r, padding... } block entirely
	    Buffer.BlockCopy( cipherdata, 0, attackdata, 0, 16 ); //first block verbatim
	    Buffer.BlockCopy( cipherdata, 0x20, attackdata, 0x10, 16 ); //second block of attackdata should be 3rd block of cipherdata
	    Buffer.BlockCopy( cipherdata, 0x30, attackdata, 0x20, 16 ); //third block of attackdata should be 4th block of cipherdata
	    Buffer.BlockCopy( cipherdata, 0x10, attackdata, 0x30, 16 ); // fourth block of attackdata should be the 2nd block of cipherdata

	    //shove the maliciously-crafted blocks into the decryptor and create a role=admin profile
	    string decrypted = DecryptProfile( attackdata, secretkey );
	    Dictionary<string, string> d = Parse( decrypted );
	    foreach( string key in d.Keys ){
		Console.WriteLine( "{0} -> {1}", key, d[key] );
	    }
	}
    }
}
