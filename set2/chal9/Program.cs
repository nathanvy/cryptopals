using System;
using System.Collections;
using System.Text;
using CryptoPals;

namespace chal9
{
    class Program
    {
        static void Main(string[] args)
        {
	    byte[] input = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
	    Console.WriteLine( "Input: " + BitConverter.ToString( input ) );
            byte[] b = PKCS.Pad( input, 20 );

	    Console.WriteLine( "Output: " + BitConverter.ToString( b ) );
        }
    }
}
