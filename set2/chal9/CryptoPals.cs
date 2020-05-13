using System;
using System.Collections;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace CryptoPals {
    public static class PKCS{
	public static byte[] Pad( byte[] inputblock, int padto ){
	    int k = padto;
	    int length = inputblock.Length;
	    if( k < length ){
		throw new ArgumentException("Can't pad to less than length!");
	    }
	    
	    int n = k - ( length % k );

	    byte[] b = new byte[k];
	    Buffer.BlockCopy(inputblock, 0, b, 0, length);
	    
	    for( int i=length; i<k; i++ ){
		b[i] = (byte)n;
	    }

	    return b;
	}
    }
    
    public static class FrequencyAnalysis{
	public static readonly Dictionary<char, double> EnglishFreq = new Dictionary<char, double>
	{
	    {'E', 12.02}, {'T', 9.10}, {'A', 8.12}, {'O', 7.68}, {'I', 7.31}, {'N', 6.95},
	    {'S', 6.28}, {'R', 6.02}, {'H', 5.92}, {'D', 4.32}, {'L', 3.98}, {'U', 2.88},
	    {'C', 2.71}, {'M', 2.61}, {'F', 2.30}, {'Y', 2.11}, {'W', 2.09}, {'G', 2.03},
	    {'P', 1.82}, {'B', 1.49}, {'V', 1.11}, {'K', 0.69}, {'X', 0.17}, {'Q', 0.11},
	    {'J', 0.10}, {'Z', 0.07}, {'e', 12.02}, {'t', 9.10}, {'a', 8.12}, {'o', 7.68},
	    {'i', 7.31}, {'n', 6.95}, {'s', 6.28}, {'r', 6.02}, {'h', 5.92}, {'d', 4.32},
	    {'l', 3.98}, {'u', 2.88}, {'c', 2.71}, {'m', 2.61}, {'f', 2.30}, {'y', 2.11},
	    {'w', 2.09}, {'g', 2.03}, {'p', 1.82}, {'b', 1.49}, {'v', 1.11}, {'k', 0.69},
	    {'x', 0.17}, {'q', 0.11}, {'j', 0.10}, {'z', 0.07}, {' ', 0.19}
	};

	public static double Evaluate( string text ){
	    double score = 0;

	    Dictionary<char, double> LetterFreq = new Dictionary<char, double>();
	    
	    foreach( char c in text ){
		if( !LetterFreq.TryAdd( c, 1.0 / (double)text.Length ) ){
		    LetterFreq[c] += (1.0 / (double)text.Length);
		}
	    }

	    //Bhattacharyya coefficient 
	    foreach( KeyValuePair<char, double> entry in LetterFreq ){
		double thefreq;
		if( EnglishFreq.TryGetValue( entry.Key, out thefreq ) ){
		    score += Math.Sqrt( thefreq * entry.Value );
		}
	    }

	    return score;
	}
    }		
	    
    public static class HammingDistance{

	//computes the hamming distance (number of differing bits) between two arrays of equal length
	public static int Compute( byte[] a1, byte[] a2 ){
	    if( a1.Length != a2.Length ){
		Console.WriteLine("Arrays are not equal dimensions!");
		throw new ArgumentException( String.Format(" Arguments are not of equal length ({0} : {1}) !", a1.Length, a2.Length ) );
	    }
	    
	    int count = 0;
	    for( int i=0; i< a1.Length; i++ ){
		count += BitOperations.PopCount( Convert.ToUInt32( a1[i] ^ a2[i] ) );
	    }
	    
	    return count;
	}
	
	public static int Compute( string s1, string s2 ){
	    if( s1.Length != s2.Length ){
		Console.WriteLine("Strings are not equal length!");
		throw new ArgumentException( String.Format("Arguments are not of equal length ({0} : {1}) !", s1.Length, s2.Length) );
	    }

	    byte[] a1 = Encoding.ASCII.GetBytes( s1 );
	    byte[] a2 = Encoding.ASCII.GetBytes( s2 );

	    return Compute( a1, a2 );
	}
    }
}
