using System;
using System.Linq;
using NBitcoin;
using NBitcoin.DataEncoders;
using NUnit.Framework;

namespace keys
{
    public class Tests
    {
        // Pri : fb401b5261327d8543382c065af27e28a9775c278b7c3dba8cd0d88f0ad042b1 (Hex)
        // Pri : 5KiwSFcZuAM3N5Ruf8cfiNzdCFupxFoFuqPafmK7JHqtsEms7HB (Base58)
        // Pri : 6PYWRpL1zPnz5kVxn74H9WdGJZVQ3ah6Pnq54GNinkfrXdd9fWNVS6dn95 (Encrypted)
        // Pri : L5e7GTVzDEFTS2YwRJcRse5LkgpAetKApCafc6avoKLovPcnFE74 (Wif)
        // Pub : 03c092d451383dedd6052de6778f9b7c393252ecbd4cd05e842638a84a2c6e2528
        // Pub : 04c092d451383dedd6052de6778f9b7c393252ecbd4cd05e842638a84a2c6e2528fe41f265a1d8884eb304a33b6f8a6a245fab83f7bf503d7dfc532ffc6593df15 (Decomp.)
        // PKH : 815ea7e8372ae215c40dc3d07a024adc7ddaf858
        // Add : 1Co3ZZ3U5ELVmZrV3oXk2qbv58AjuwRrnB (Legacy)
        // Add : 3JCvRhjrEyw9pvZiE3TxsdSHNPJQh1vHTe (SegwitP2SH)
        // Add : bc1qs90206ph9t3pt3qdc0g85qj2m37a47zclpwws7 (Segwit)
        [Test]
        public void TestAddressCreation()
        {
            Key privateKey; // = new Key(); 
            privateKey = Key.Parse("L5e7GTVzDEFTS2YwRJcRse5LkgpAetKApCafc6avoKLovPcnFE74", Network.Main); // For getting the same outputs
            PubKey publicKey = privateKey.PubKey;
            BitcoinAddress addressLegacy = publicKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main);
            BitcoinAddress addressSegwit = publicKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main);
            BitcoinAddress addressSegwitP2SH = publicKey.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main);
            KeyId publicKeyHash = publicKey.Hash;

            // Wif -> 
            // Priv. key -> Wif (Check README.md - Wif)
            BitcoinSecret wif = privateKey.GetWif(Network.Main);
            BitcoinSecret wif2 = new BitcoinSecret("L5e7GTVzDEFTS2YwRJcRse5LkgpAetKApCafc6avoKLovPcnFE74", Network.Main);
            Assert.AreEqual(wif, wif2);

            // Private key -> 
            // Wif -> Priv. key
            Key privateKey1 = Key.Parse("L5e7GTVzDEFTS2YwRJcRse5LkgpAetKApCafc6avoKLovPcnFE74", Network.Main); 
            Assert.AreEqual(privateKey, privateKey1);

            // Base58 encoded priv key
            var privKeyVersionBytes = Network.Main.GetVersionBytes(Base58Type.SECRET_KEY, true); 
            byte[] privKeyWithVersionBytes = Concat(privKeyVersionBytes, privateKey.ToBytes());
            var privKeyBase58 = Encoders.Base58Check.EncodeData(privKeyWithVersionBytes); 
            
            // Encrypted priv key (BIP38)
            BitcoinEncryptedSecret encryptedPrivKey = wif.Encrypt("password");

            // Decrypted priv key 
            BitcoinEncryptedSecret encryptedPrivKeyFromStr = BitcoinEncryptedSecret.Create("6PYWRpL1zPnz5kVxn74H9WdGJZVQ3ah6Pnq54GNinkfrXdd9fWNVS6dn95", Network.Main);
            BitcoinSecret decryptedPrivKey = encryptedPrivKeyFromStr.GetSecret("password");
            Assert.AreEqual(wif, decryptedPrivKey);

            // Public key hash -> 
            // Check README (Hash160(Public Key))
            var hash1 =  NBitcoin.Crypto.Hashes.SHA256(publicKey.ToBytes());
            var pkh = NBitcoin.Crypto.Hashes.RIPEMD160(hash1, hash1.Length); // SHA256(RIPEMD160(PUB_KUY))
            var generatedPubKeyHash = new KeyId(pkh);
            Assert.AreEqual(publicKeyHash, generatedPubKeyHash);

            // Bitcoin Address > 
            var versionBytes = Network.Main.GetVersionBytes(Base58Type.PUBKEY_ADDRESS, true); // 0x00
            byte[] PKHWithVersionBytes = Concat(versionBytes, pkh); // 0x00 + PKH
            var address1 = Encoders.Base58Check.EncodeData(PKHWithVersionBytes); 
            Assert.AreEqual(addressLegacy.ToString(), address1); // 1Co3ZZ3U5ELVmZrV3oXk2qbv58AjuwRrnB

            Console.WriteLine();
            Console.WriteLine($"Pri : {privateKey.ToHex()} (Hex)");         // fb401b5261327d8543382c065af27e28a9775c278b7c3dba8cd0d88f0ad042b1
            Console.WriteLine($"Pri : {privKeyBase58} (Base58)");           // 5KiwSFcZuAM3N5Ruf8cfiNzdCFupxFoFuqPafmK7JHqtsEms7HB
            Console.WriteLine($"Pri : {encryptedPrivKey} (Encrypted)");     // 6PYWRpL1zPnz5kVxn74H9WdGJZVQ3ah6Pnq54GNinkfrXdd9fWNVS6dn95
            Console.WriteLine($"Pri : {wif} (Wif)");                        // L5e7GTVzDEFTS2YwRJcRse5LkgpAetKApCafc6avoKLovPcnFE74
            Console.WriteLine($"Pub : {publicKey}");                        // 03c092d451383dedd6052de6778f9b7c393252ecbd4cd05e842638a84a2c6e2528
            Console.WriteLine($"Pub : {publicKey.Decompress()} (Decomp.)"); // 04c092d451383dedd6052de6778f9b7c393252ecbd4cd05e842638a84a2c6e2528fe41f265a1d8884eb304a33b6f8a6a245fab83f7bf503d7dfc532ffc6593df15
            Console.WriteLine($"PKH : {publicKey.Hash}");                   // 815ea7e8372ae215c40dc3d07a024adc7ddaf858
            Console.WriteLine($"Add : {addressLegacy} (Legacy)");           // 1Co3ZZ3U5ELVmZrV3oXk2qbv58AjuwRrnB
            Console.WriteLine($"Add : {addressSegwitP2SH} (SegwitP2SH)");   // 3JCvRhjrEyw9pvZiE3TxsdSHNPJQh1vHTe
            Console.WriteLine($"Add : {addressSegwit} (Segwit)");           // bc1qs90206ph9t3pt3qdc0g85qj2m37a47zclpwws7
        }

        // From NBitcoin
        public static byte[] Concat(byte[] arr, params byte[][] arrs)
		{
			var len = arr.Length + arrs.Sum(a => a.Length);
			var ret = new byte[len];
			Buffer.BlockCopy(arr, 0, ret, 0, arr.Length);
			var pos = arr.Length;
			foreach (var a in arrs)
			{
				Buffer.BlockCopy(a, 0, ret, pos, a.Length);
				pos += a.Length;
			}
			return ret;
		}
    }
}