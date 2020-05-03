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
        public void CreatePubKEy()
        {
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
            var pubKey = privKey.CreatePubKey();

            Span<byte> tmp = new byte[65];
            pubKey.WriteToSpan(true, tmp, out var l);
            tmp = tmp.Slice(0, l);
            var pubHex = Encoders.Hex.EncodeData(tmp);

            Console.WriteLine($"PublicKey: {pubHex} ");
        }
    }
}