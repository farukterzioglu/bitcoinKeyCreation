using System;
using System.Linq;
using System.Numerics;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NUnit.Framework;

namespace keys
{
    public class GenerateAddress
    {
        // Private key (hex)   : 48d4c26bac72a52145efe05505cdc52fa9a06c0fbe98ee4d53c34a873ca96ce6
        // Priv. key (Base58)  : 5JNMxHVYeLQd9GbGiwBKHWSU3WoQZAHhykMjFP6SXaQyF1iBhZd
        // Priv. key (Base58)  : KyfHV1nzfnfGXVpGQ68XhrwQN6XpxwzjsUNVUUX1fxUoEcezHsV8 (Compressed)
        // Pub key (uncomp.)   : 04ca46b6f91053ded9860e7e2e5e91d4eb8178a1525892baf02e8e5dbf1e5a1b960791e7f710aa9b49b0889e8f659d825ce90217047b643b9a127c0f6cca62da28
        // Pub key (comp.)     : 02ca46b6f91053ded9860e7e2e5e91d4eb8178a1525892baf02e8e5dbf1e5a1b96
        // Address             : 16LtGmnFGV4hy3vWZ7bg55Ud6bpjf6y36w
        // Address (Comp.)     : 1LbDCHizjETtXU4mjnnqMPNXSmJ6j4KS5v
        [Test]
        public void CreateAddress()
        {
            Console.WriteLine();

            // Priv key length
            int KEY_SIZE = 32;

            // Max priv key value
            // 115792089237316195423570985008687907852837564279074904382605163141518161494337
		    uint256 N = uint256.Parse("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"); 
            
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

            // base58 encoded private key
            byte[] privKeyWithVersionBytes = Helper.Concat( new byte[] { 128 }, privateKey); 
            string privKeyBase58 = Encoders.Base58Check.EncodeData(privKeyWithVersionBytes); 
            Console.WriteLine($"Priv. key (Base58)  : {privKeyBase58}");

            // base58 encoded compressed private key
            byte[] compPrivKeyWithVersionBytes = Helper.Concat( privKeyWithVersionBytes, new byte[] { 01 }); 
            var compPrivKeyBase58 = Encoders.Base58Check.EncodeData(compPrivKeyWithVersionBytes);
            Console.WriteLine($"Priv. key (Base58)  : {compPrivKeyBase58} (Compressed)");

            // Elliptic curve multiplication (with help of NBitcoin)
            // privateKey = Encoders.Hex.DecodeData("da7639a9e2ed4e918b57151509ee34b3f80ad4ab60fb52de59cc3a7386b19007"); // for testing
            NBitcoin.Secp256k1.ECPrivKey privKey = Context.Instance.CreateECPrivKey(new Scalar(privateKey));
            ECPubKey pubKey = privKey.CreatePubKey();

            // X, Y
            var x = pubKey.Q.x.ToBytes();
            var y = pubKey.Q.y.ToBytes();

            // Uncompressed public key 
            var pubKeyUncomp = Helper.Concat(new byte[] { (04) }, x, y);
            Console.WriteLine($"Pub key (uncomp.)   : {Encoders.Hex.EncodeData(pubKeyUncomp)}");

            // Compressed public key 
            BigInteger yBig = new BigInteger(y, isUnsigned: true, isBigEndian: true);
            var pubKeyComp = Helper.Concat(new byte[] { (byte)(yBig % 2 == 0 ? 02 : 03) }, x);
            Console.WriteLine($"Pub key (comp.)     : {Encoders.Hex.EncodeData(pubKeyComp)}");

            //// Uncompressed Public Key
            // Public key hash (pkh)

            var pubKeyHash =  NBitcoin.Crypto.Hashes.SHA256(pubKeyUncomp);
            var pubKeyHash160 = NBitcoin.Crypto.Hashes.RIPEMD160(pubKeyHash, pubKeyHash.Length);
            Console.WriteLine($"Public key hash     : {Encoders.Hex.EncodeData(pubKeyHash160)}");

            // base58 encoded pkh : address
            byte[] PKHWithVersionBytes = Helper.Concat(new byte[] { 00 }, pubKeyHash160);
            var address = Encoders.Base58Check.EncodeData(PKHWithVersionBytes); 
            Assert.DoesNotThrow( () => {
                BitcoinAddress.Create(str: address, Network.Main);
            });
            Console.WriteLine($"Address             : {address}");

            //// Uncompressed Public Key (w/ checksum calculation)
            var hash1 = NBitcoin.Crypto.Hashes.SHA256(PKHWithVersionBytes);
            var hash2 = NBitcoin.Crypto.Hashes.SHA256(hash1);
            var checksum = hash2.Take(4).ToArray();
            var pkhWithChecksum = Helper.Concat(PKHWithVersionBytes, checksum);

            var address1 = Encoders.Base58.EncodeData(pkhWithChecksum);
            Assert.AreEqual(address, address1);

            //// Compressed Public Key
            // Public key hash (Compressed)
            var pubKeyCompHash =  NBitcoin.Crypto.Hashes.SHA256(pubKeyComp);
            var pubKeyCompHash160 = NBitcoin.Crypto.Hashes.RIPEMD160(pubKeyCompHash, pubKeyCompHash.Length);

            // base58 encoded compressed pkh : address
            byte[] compPKHWithVersionBytes = Helper.Concat(new byte[] { 00 }, pubKeyCompHash160);
            var addressComp = Encoders.Base58Check.EncodeData(compPKHWithVersionBytes); 
            Assert.DoesNotThrow( () => {
                BitcoinAddress.Create(str: addressComp, Network.Main);
            });
            Console.WriteLine($"Address (Comp.)     : {addressComp}");
        }
    }
}