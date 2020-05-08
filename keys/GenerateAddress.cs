using System;
using System.Numerics;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NUnit.Framework;

namespace keys
{
    public class GenerateAddress
    {
        // Private key (hex)   : 5f9666def1d582ad6f2684f781a96c472274bf20bfb89d74fbc55908b6c1faba
        // Pub key (uncomp.)   : 04d43521a3863412bfad61ffa3c8fb6f0e4cc3e3a5d032f82e60ef198829e9212b3c202b63db1cdc4948f76e5524fc0c12d8ad58655b98fefc811c3f716ac34ebf
        // Address             : 1hBsGTr3KEen9Y2FyqoXRzG6pEvCNj1U1
        [Test]
        public void CreateAddress()
        {
            Console.WriteLine();

            // Priv key length
            int KEY_SIZE = 32;

            // Max priv key value
            // 115792089237316195423570985008687907852837564279074904382605163141518161494337
		    uint256 N = uint256.Parse("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"); 
            
            // Add some enyropy
            RandomUtils.AddEntropy("key-creation-test");
            RandomUtils.AddEntropy(new byte[] { 99, 98, 97 });
            
            // Randomizer
            Random rand = new Random();
            byte[] privateKey = new byte[KEY_SIZE];

            // Generate a valid random value
            uint256 candidateKey;
            do
            {
                rand.NextBytes(privateKey);    
                candidateKey = new uint256(privateKey, false);
            } while (!(candidateKey > 0 && candidateKey < N));
            Console.WriteLine($"Private key (hex)   : { Encoders.Hex.EncodeData(privateKey) }");

            // Elliptic curve multiplication (with help of NBitcoin)
            NBitcoin.Secp256k1.ECPrivKey privKey = Context.Instance.CreateECPrivKey(new Scalar(privateKey));
            ECPubKey pubKey = privKey.CreatePubKey();

            // X / Y
            var x = pubKey.Q.x.ToBytes();
            var y = pubKey.Q.y.ToBytes();

            // Uncompressed public key 
            var pubKeyUncomp = Helper.Concat(new byte[] { (04) }, x, y);
            Console.WriteLine($"Pub key (uncomp.)   : {Encoders.Hex.EncodeData(pubKeyUncomp)}");

            // Public key hash (pkh)
            var hash1 =  NBitcoin.Crypto.Hashes.SHA256(pubKeyUncomp);
            var pkh = NBitcoin.Crypto.Hashes.RIPEMD160(hash1, hash1.Length);

            // base53 encoded pkh : address
            byte[] PKHWithVersionBytes = Helper.Concat(new byte[] { 00 }, pkh);
            var address = Encoders.Base58Check.EncodeData(PKHWithVersionBytes); 

            Console.WriteLine($"Address             : {address}");
        }
    }
}