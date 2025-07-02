using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace QuantumCrytography
{
    internal class PostQuantumCryptography
    {
        public static (byte[] key, byte[] iv) GenerateKeyAndIV()
        {
            var random = new SecureRandom();

            byte[] key = new byte[32];//Must use a 32 byte key for AES-256
            byte[] iv = new byte[16];//16 byte initialisation vector for CBC cipher mode

            random.NextBytes(key);
            random.NextBytes(iv);

            return (key, iv);
        }

        public static string EncryptString(string plainText, byte[] key, byte[] iv)
        {
            if(key.Length < 32)
                throw new ArgumentException("Encryption key must be 32 bytes");//Safety incase someone tries to use an unsafe key

            var engine = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            var keyParam = new ParametersWithIV(new KeyParameter(key), iv);
            engine.Init(true, keyParam);

            byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] outputBytes = new byte[engine.GetOutputSize(inputBytes.Length)];
            int length = engine.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            length += engine.DoFinal(outputBytes, length);

            return Convert.ToBase64String(outputBytes, 0, length);
        }

        public static string DecryptString(string cipherTextBase64, byte[] key, byte[] iv)
        {
            var engine = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            var keyParam = new ParametersWithIV(new KeyParameter(key), iv);
            engine.Init(false, keyParam);

            byte[] inputBytes = Convert.FromBase64String(cipherTextBase64);
            byte[] outputBytes = new byte[engine.GetOutputSize(inputBytes.Length)];
            int length = engine.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            length += engine.DoFinal(outputBytes, length);

            return Encoding.UTF8.GetString(outputBytes, 0, length);
        }
    }
}
