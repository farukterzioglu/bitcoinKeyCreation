using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NUnit.Framework;

namespace keys
{
    public class GeneratePublicKey
    {
        [Test]
        public void CreatePubKEy()
        {
            Console.WriteLine();

            uint256 N = uint256.Parse("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"); 
            Random rand = new Random();

            byte[] privateKey = new byte[32];
            uint256 candidateKey;
            do
            {
                rand.NextBytes(privateKey);    
                candidateKey = new uint256(privateKey, false);
            } while (!(candidateKey > 0 && candidateKey < N));

            // Public key 
            NBitcoin.Secp256k1.ECPrivKey privKey = Context.Instance.CreateECPrivKey(new Scalar(privateKey));
            ECPubKey pubKey = privKey.CreatePubKey();

            var pubKeyBytes = pubKey.ToBytes();
            Console.WriteLine($"Pub key  : {Encoders.Hex.EncodeData(pubKeyBytes)}");

            var x = pubKey.Q.x.ToBytes();
            var y = pubKey.Q.y.ToBytes();
            Console.WriteLine($"Pub key x: {Encoders.Hex.EncodeData(x)}");
            Console.WriteLine($"Pub key y: {Encoders.Hex.EncodeData(y)}");
        }
    }
}