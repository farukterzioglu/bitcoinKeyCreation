using System;
using System.Numerics;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NUnit.Framework;

namespace keys
{
    public class GeneratePublicKey
    {
        // Pub key x           :   cd6d7a395e79b34efb091e8658d9cf4bc158e0f1f22a5af17dadd63363a253f8
        // Pub key y           :   																   05da8518812fee082721c4191bb0a055ce268e46592a7ba82e475d2cc53f7eb3
        // Pub key (uncomp.)   : 04cd6d7a395e79b34efb091e8658d9cf4bc158e0f1f22a5af17dadd63363a253f805da8518812fee082721c4191bb0a055ce268e46592a7ba82e475d2cc53f7eb3
        // Pub key (comp.)     : 03cd6d7a395e79b34efb091e8658d9cf4bc158e0f1f22a5af17dadd63363a253f8
        [Test]
        public void CreatePubKey()
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
            privateKey = Encoders.Hex.DecodeData("da7639a9e2ed4e918b57151509ee34b3f80ad4ab60fb52de59cc3a7386b19007");

            NBitcoin.Secp256k1.ECPrivKey privKey = Context.Instance.CreateECPrivKey(new Scalar(privateKey));
            ECPubKey pubKey = privKey.CreatePubKey();
            byte[] pubKeyBytes = pubKey.ToBytes();
            // Console.WriteLine($"Pub key             : {Encoders.Hex.EncodeData(pubKeyBytes)}");

            var x = pubKey.Q.x.ToBytes();
            var y = pubKey.Q.y.ToBytes();
            Console.WriteLine($"Pub key x           :   {Encoders.Hex.EncodeData(x)}");
            Console.WriteLine($"Pub key y           :   {string.Empty.PadLeft(16, '\t')}{Encoders.Hex.EncodeData(y)}");

            var pubKeyUncomp = Helper.Concat(new byte[] { (04) }, x, y);
            Console.WriteLine($"Pub key (uncomp.)   : {Encoders.Hex.EncodeData(pubKeyUncomp)}");

            BigInteger yBig = new BigInteger(y, isUnsigned: true, isBigEndian: true);
            byte pubKeyPrefix = (byte)(yBig % 2 == 0 ? 02 : 03);
            var pubKeyComp = Helper.Concat(new byte[] { pubKeyPrefix }, x);
            Console.WriteLine($"Pub key (comp.)     : {Encoders.Hex.EncodeData(pubKeyComp)}");
            Assert.AreEqual(pubKeyBytes , pubKeyComp);
        }
    }
}