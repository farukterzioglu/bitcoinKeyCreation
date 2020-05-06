using System;
using System.Linq;
using NBitcoin;
using NBitcoin.DataEncoders;

namespace vanityCreator
{
    class Program
    {
        static void Main(string[] args)
        {
            string text = "BTC";
            for(int i = 0; i < args.Length; i++) 
                if( args[i] == "-text" ) 
                    text = args[i+1];

            bool caseSensitive = args.Any( x => x == "-casesensitive");
            if(!caseSensitive) 
                text = text.ToLower();
            
            Func<BitcoinAddress, bool> isMatched = (BitcoinAddress bitcoinAddress) => { 
                var address = bitcoinAddress.ToString();
                if(!caseSensitive) address = address.ToLower();

                return 
                    address.StartsWith($"1{text}") || 
                    address.StartsWith($"bc1q{text}") || 
                    address.StartsWith($"3{text}");
            };

            BitcoinAddress addressLegacy;
            BitcoinAddress addressSegwit;
            BitcoinAddress addressSegwitP2SH;
            BitcoinSecret wif;

            bool addressLegacyFound = false, addressSegwitFound = false, addressSegwitP2SHFound = false;
            while(!addressLegacyFound || !addressSegwitFound || !addressSegwitP2SHFound)
            {
                Key privateKey = new Key();
                PubKey publicKey = privateKey.PubKey;

                addressLegacy = publicKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main);
                addressSegwit = publicKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main);
                addressSegwitP2SH = publicKey.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main);
                wif = privateKey.GetWif(Network.Main);

                if(!addressLegacyFound && isMatched(addressLegacy))
                {
                    addressLegacyFound = true;
                    Console.WriteLine($"\nPri : {wif} (Wif)");
                    Console.WriteLine($"Add : {addressLegacy} (Legacy)");
                }

                if(!addressSegwitFound && isMatched(addressSegwit))
                {
                    addressSegwitFound = true;
                    Console.WriteLine($"\nPri : {wif} (Wif)");
                    Console.WriteLine($"Add : {addressSegwit} (Segwit)");
                }

                if(!addressSegwitP2SHFound && isMatched(addressSegwitP2SH))
                {
                    addressSegwitP2SHFound = true;
                    Console.WriteLine($"\nPri : {wif} (Wif)");
                    Console.WriteLine($"Add : {addressSegwitP2SH} (SegwitP2SH)");
                }
            }
        }
    }
}
