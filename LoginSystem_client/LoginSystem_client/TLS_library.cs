using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LoginSystem_client
{
    internal class TLS_library
    {
        static RSACryptoServiceProvider rsa_ser = new RSACryptoServiceProvider();
        Aes aesAlgorithm = Aes.Create();


        public TLS_library()
        {
            aesAlgorithm.KeySize = 256;
            aesAlgorithm.GenerateKey();
        }




        public string GetPublicKey()
        {
            return rsa_ser.ToXmlString(false);
        }
        public byte[] GetSymmetricKey()
        {
            return aesAlgorithm.Key;
        }
        public byte[] GenerateNewSymmetricKey()
        {
            aesAlgorithm.KeySize = 256;
            aesAlgorithm.GenerateKey();
            return aesAlgorithm.Key;
        }
        public string GetPrivateKey()
        {
            return rsa_ser.ToXmlString(true);
        }
        public byte[] DecryptAssymetric(byte[] input, string keys)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(keys);
            return rsa.Decrypt(input, false);
        }
        public byte[] EncryptAssymetric(byte[] input, string public_keys)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(public_keys);
            return rsa.Encrypt(input, false);
        }



        public string EncryptSymmetric(string data, byte[] key)
        {
            byte[] initializationVector = Encoding.ASCII.GetBytes("abcede0123456789");
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = initializationVector;
                var symmetricEncryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream as Stream, symmetricEncryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream as Stream))
                        {
                            streamWriter.Write(data);
                        }
                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
        }
        public string DecryptSymmetric(string cipherText, byte[] key)
        {
            byte[] initializationVector = Encoding.ASCII.GetBytes("abcede0123456789");
            byte[] buffer = Convert.FromBase64String(cipherText);
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = initializationVector;
                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (var memoryStream = new MemoryStream(buffer))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream as Stream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream as Stream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
