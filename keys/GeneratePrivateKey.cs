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
    public class GeneratePrivateKey
    {
        [Test]
        public void CreatePrivateKey()
        {
            RandomUtils.AddEntropy("key-creation-test");
            RandomUtils.AddEntropy(new byte[] { 99, 98, 97 });
            
            Key privateKey = new Key();
            Console.WriteLine($"Private key : {privateKey.GetWif(Network.Main)}");
        }

        // Private key (hex)       : da7639a9e2ed4e918b57151509ee34b3f80ad4ab60fb52de59cc3a7386b19007
        // Private key (Base58)    : 5KUVttUHHrYU9WBUU1o8FLDNXT947cRxDjxGoTsEpX8JTxTqRxs
        // Private key (Comp.)     : L4YNY2BQuPftpXoEEEWazFoc1QNYkBP8jEaxk5ajzjyE5r2wCQL5
        [Test]
        public void CreateManually()
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
            Console.WriteLine($"Private key (hex)       : { Encoders.Hex.EncodeData(privateKey) }");

            // Base58  
            byte[] privKeyPrefix = new byte[] { (128) }; // Base58 prefix for private key, 0x80 in hex
            byte[] prefixedPrivKey = Helper.Concat(privKeyPrefix, privateKey);
            
            Base58CheckEncoder base58Check = new Base58CheckEncoder();
            
            string privKeyEncoded = string.Empty;
            {
                privKeyEncoded = base58Check.EncodeData(prefixedPrivKey);
            }
            // or
            {
                var hash1 = NBitcoin.Crypto.Hashes.SHA256(prefixedPrivKey);
                var hash2 = NBitcoin.Crypto.Hashes.SHA256(hash1);
                var checksum = hash2.Take(4).ToArray();
                var prefixedPrivKeyChecksum = Helper.Concat(prefixedPrivKey, checksum);

                Base58Encoder base58 = new Base58Encoder();
                privKeyEncoded = base58.EncodeData(prefixedPrivKeyChecksum);
            }

            Assert.DoesNotThrow(() => { 
                Key.Parse(privKeyEncoded, Network.Main);
            });
            Console.WriteLine($"Private key (Base58)    : {privKeyEncoded}");

            // Compressed private key
            byte[] privKeySuffix = new byte[] { (1) }; // Suffix for compressed private key, 0x01 in hex
            byte[] suffixedPrivKey = Helper.Concat(prefixedPrivKey, privKeySuffix);
            string compressedPrivKeyEncoded = base58Check.EncodeData(suffixedPrivKey);
            Assert.DoesNotThrow(() => { 
                Key.Parse(compressedPrivKeyEncoded, Network.Main);
            });
            Console.WriteLine($"Private key (Comp.)     : {compressedPrivKeyEncoded}");

            // P2PK private key
            byte[] p2pkhPrivKeySuffix = new byte[] { (16) }; // 0x10 in hex
            byte[] suffixedP2pkhPrivKey = Helper.Concat(prefixedPrivKey, p2pkhPrivKeySuffix);
            string compressedP2pkhPrivKeyEncoded = base58Check.EncodeData(suffixedP2pkhPrivKey);
            Console.WriteLine($"Private key (P2PKH)     : {compressedP2pkhPrivKeyEncoded}");
        }

        // Private key (Base58): 5JE7s6mThX637rmc7GGnqCuPCQ1dFD3fhRbeMiG1zAbzYtgnCb6
        [Test]
        public void CreateFromHash()
        {
            using (var sha = new SHA256Managed())
			{
				byte[] privateKey = sha.ComputeHash(Encoding.UTF8.GetBytes("some_random_text"));
                byte[] prefixedPrivKey = Helper.Concat(new byte[] { (128) }, privateKey);
                
                Base58CheckEncoder base58Check = new Base58CheckEncoder();
                string privKeyEncoded = base58Check.EncodeData(prefixedPrivKey);
                Console.WriteLine($"Private key (Base58): {privKeyEncoded}");

                Key privKey = Key.Parse(privKeyEncoded, Network.Main);
			}
        }

        [Test]
        public void GetDecimalPrivFromWif()
        {
            Base58CheckEncoder base58Check = new Base58CheckEncoder();
            byte[] privKeyPrefixed = base58Check.DecodeData("5KV7hnn73NJCumzmviZ6UpjC68dw86r3WSG4DvuaTgw4968rZuo");
            Assert.AreEqual(128, privKeyPrefixed[0]); // 0x80
            
            // Dropping first byte
            byte[] privateKey = privKeyPrefixed.Skip(1).ToArray();

            // Encode to hex to print
            string privHex = Encoders.Hex.EncodeData(privateKey);
            Assert.AreEqual("dbdd1a034b5ac2f2cfa1ef09daf032dee9015586427d4cbd6f810a32ea45173a", privHex);
        }

        // HMACSHA512 hmac = new HMACSHA512(Encoders.ASCII.DecodeData("Bitcoin seed"));
        // byte[] hashMAC = hmac.ComputeHash(seed).Take(32).ToArray();
        // NBitcoin.Secp256k1.ECPrivKey privKey = Context.Instance.CreateECPrivKey(new Scalar(hashMAC));
        // string privHex = Encoders.Hex.EncodeData(hashMAC);
    }
}