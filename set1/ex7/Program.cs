using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ex7
{
    class Program
    {
	static void Main(string[] args)
        {
            byte[] key = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");

	    string[] strinput = File.ReadAllLines("7.txt");
	    string b64ciphertext = "";
	    foreach( string s in strinput ){
		b64ciphertext += s;
	    }
	    byte[] ciphertext = Convert.FromBase64String( b64ciphertext );

	    //go tiem
	    Aes session = Aes.Create();
	    session.Mode = CipherMode.ECB;
	    session.Key = key;

	    ICryptoTransform aestransform = session.CreateDecryptor();
	    byte[] result = aestransform.TransformFinalBlock( ciphertext, 0, ciphertext.Length );
	    string plaintext = Encoding.ASCII.GetString( result );

	    Console.WriteLine( plaintext );
	    
        }
    }
}
