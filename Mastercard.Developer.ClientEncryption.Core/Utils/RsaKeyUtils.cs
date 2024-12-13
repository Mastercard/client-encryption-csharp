using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Mastercard.Developer.ClientEncryption.Core.Utils
{
    internal static class RsaKeyUtils
    {
        private const string Pkcs1PemHeader = "-----BEGIN RSA PRIVATE KEY-----";
        private const string Pkcs1PemFooter = "-----END RSA PRIVATE KEY-----";
        private const string Pkcs8PemHeader = "-----BEGIN PRIVATE KEY-----";
        private const string Pkcs8PemFooter = "-----END PRIVATE KEY-----";
        
        internal static RSA ReadPrivateKeyFile(string keyFilePath)
        {
            if (keyFilePath == null) throw new ArgumentNullException(nameof(keyFilePath));
            var key = File.ReadAllBytes(keyFilePath);
            return ReadPrivateKey(key);
        }
        
        internal static RSA ReadPrivateKey(byte[] key)
        {
            var keyString = Encoding.UTF8.GetString(key);
            if (keyString.Contains(Pkcs1PemHeader))
            {
                // OpenSSL / PKCS#1 Base64 PEM encoded file
                keyString = keyString.Replace(Pkcs1PemHeader, string.Empty);
                keyString = keyString.Replace(Pkcs1PemFooter, string.Empty);
                keyString = keyString.Replace(Environment.NewLine, string.Empty);
                return ReadPkcs1Key(Convert.FromBase64String(keyString));
            }

            if (keyString.Contains(Pkcs8PemHeader))
            {
                // PKCS#8 Base64 PEM encoded file
                keyString = keyString.Replace(Pkcs8PemHeader, string.Empty);
                keyString = keyString.Replace(Pkcs8PemFooter, string.Empty);
                keyString = keyString.Replace(Environment.NewLine, string.Empty);
                return ReadPkcs8Key(Convert.FromBase64String(keyString));
            }
            return ReadPkcs8Key(key);
        }

        private static RSA ReadPkcs8Key(byte[] pkcs8Bytes)
        {
            try
            {
                var memoryStream = new MemoryStream(pkcs8Bytes);
                var keyLength = (int) memoryStream.Length;
                var reader = new BinaryReader(memoryStream);
                
                var bytes = reader.ReadUInt16();
                if (bytes == 0x8130)
                {
                    reader.ReadByte();
                }
                else if (bytes == 0x8230)
                {
                    reader.ReadByte();
                    reader.ReadByte();
                }
                else
                {
                    throw new ArgumentException("Failed to parse PKCS#8 key, 0x8130 or 0x8230 was expected!");
                }

                bytes = reader.ReadByte();
                if (bytes != 0x02)
                {
                    throw new ArgumentException("Failed to parse PKCS#8 key, 0x02 was expected!");
                }

                bytes = reader.ReadUInt16();
                if (bytes != 0x0001)
                {
                    throw new ArgumentException("Failed to parse PKCS#8 key, 0x0001 was expected!");
                }

                if (!reader.ReadBytes(15).SequenceEqual(new byte[] { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 }))
                {
                    throw new ArgumentException("Failed to parse PKCS#8 key, RSA OID was expected!");
                }

                bytes = reader.ReadByte();
                if (bytes != 0x04)
                {
                    throw new ArgumentException("Failed to parse PKCS#8 key, 0x04 was expected!");
                }

                bytes = reader.ReadByte();
                if (bytes == 0x81)
                {
                    reader.ReadByte();
                }
                else if (bytes == 0x82)
                {
                    reader.ReadByte();
                    reader.ReadByte();
                }

                var pkcs1Bytes = reader.ReadBytes((int) (keyLength - memoryStream.Position));
                return ReadPkcs1Key(pkcs1Bytes);
            }
            catch (ArgumentException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new ArgumentException("Failed to parse PKCS#8 key!", e);
            }
        }

        private static RSA ReadPkcs1Key(byte[] pkcs1Bytes)
        {
            try
            {
                var memoryStream = new MemoryStream(pkcs1Bytes);
                var reader = new BinaryReader(memoryStream);
            
                var bytes = reader.ReadUInt16();
                if (bytes == 0x8130)
                {
                    reader.ReadByte();
                }
                else if (bytes == 0x8230)
                {
                    reader.ReadByte();
                    reader.ReadByte();
                }
                else
                {
                    throw new ArgumentException("Failed to parse PKCS#1 key, 0x8130 or 0x8230 was expected!");
                }

                var versionBytes = reader.ReadUInt16();
                if (versionBytes != 0x0102)
                {
                    throw new ArgumentException("Failed to parse PKCS#1 key, 0x0102 was expected!");
                }

                bytes = reader.ReadByte();
                if (bytes != 0x00)
                {
                    throw new ArgumentException("Failed to parse PKCS#1 key, 0x00 was expected!");
                }

                byte[] padded(byte[] array, int totalLength)
                {
                    var currentLength = array.Length;
                    if(currentLength >= totalLength) {
                        return array;
                    }

                    var paddedArray = new byte[totalLength];
                    Array.Copy(array, 0, paddedArray, totalLength - currentLength, currentLength);

                    return paddedArray;
                }

                var modulus = reader.ReadBytes(GetIntegerSize(reader));
                
                var modulusLength = modulus.Length;
                var modulusHalfLength = (modulus.Length + 1) / 2; // half length rounded up

                var publicExponent = reader.ReadBytes(GetIntegerSize(reader));
                var privateExponent = padded(reader.ReadBytes(GetIntegerSize(reader)), modulusLength);
                var prime1 = padded(reader.ReadBytes(GetIntegerSize(reader)), modulusHalfLength);
                var prime2 = padded(reader.ReadBytes(GetIntegerSize(reader)), modulusHalfLength);
                var exponent1 = padded(reader.ReadBytes(GetIntegerSize(reader)), modulusHalfLength);
                var exponent2 = padded(reader.ReadBytes(GetIntegerSize(reader)), modulusHalfLength);
                var coefficient = padded(reader.ReadBytes(GetIntegerSize(reader)), modulusHalfLength);

                var rsa = CreateRsa();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = modulus,
                    Exponent = publicExponent,
                    D = privateExponent ,
                    P = prime1,
                    Q = prime2,
                    DP = exponent1,
                    DQ = exponent2,
                    InverseQ = coefficient
                });
                return rsa;
            }
            catch (ArgumentException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new ArgumentException("Failed to parse PKCS#1 key!", e);
            }
        }

        private static RSA CreateRsa()
        {
            var rsa = RSA.Create();
            switch (rsa.GetType().Name)
            {
                case "RSACryptoServiceProvider":
                {
                    // .NET Framework 4.6+: we need a RSACng key for OaepSHA256 and OaepSHA512
                    var rsaCngType = Type.GetType("System.Security.Cryptography.RSACng, System.Security.Cryptography.Cng");
                    if (null == rsaCngType)
                    {
                        throw new NotSupportedException("Failed to create a RSACng key! Consider adding System.Security.Cryptography.Cng to your project.");
                    }
                    return Activator.CreateInstance(rsaCngType) as RSA;
                }
                default:
                    return rsa;
            }
        }

        /// <summary>
        /// Returns the DER-encoded form of a key (exact same binary as https://docs.oracle.com/javase/7/docs/api/java/security/Key.html#getEncoded())
        /// </summary>
        internal static byte[] GetEncoded(PublicKey publicRsaKey)
        {
            var rawKeyBytes = publicRsaKey.EncodedKeyValue.RawData;
            var rawKeyLength = rawKeyBytes.Length + 1;
            byte[] sequenceBytes;
            byte[] bitStringBytes;
            byte[] oidBytes = { 0x30, 0xD, 0x6, 0x9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0 }; // 1.2.840.113549.1.1.1, NULL

            if (rawKeyLength > 270)
            {
                // 2048, 4096 bits
                var totalLength = rawKeyLength + 19;
                sequenceBytes = new byte[] { 0x30, 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff) };
                bitStringBytes = new byte[] { 0x3, 0x82, (byte) ((rawKeyLength >> 8) & 0xff), (byte) (rawKeyLength & 0xff) };
            }
            else if (rawKeyLength > 140)
            {
                // 1024 bits
                var totalLength = rawKeyLength + 18;
                sequenceBytes = new byte[] { 0x30, 0x81, (byte) (totalLength & 0xff) };
                bitStringBytes = new byte[] { 0x3, 0x81, (byte) (rawKeyLength & 0xff) };
            }
            else
            {
                // 512 bits
                var totalLength = rawKeyLength + 17;
                sequenceBytes = new byte[] { 0x30, (byte) (totalLength & 0xff) };
                bitStringBytes = new byte[] { 0x3, (byte) (rawKeyLength & 0xff) };
            }

            return sequenceBytes.Concat(oidBytes)
                .Concat(bitStringBytes)
                .Concat(new byte[] { 0x0 })
                .Concat(rawKeyBytes)
                .ToArray();
        }

        private static int GetIntegerSize(BinaryReader reader)
        {
            int size;
            var bytes = reader.ReadByte();
            if (bytes != 0x02)
            {
                return 0;
            }

            bytes = reader.ReadByte();
            if (bytes == 0x81)
            {
                size = reader.ReadByte();
            }
            else if (bytes == 0x82)
            {
                var high = reader.ReadByte();
                var low = reader.ReadByte();
                size = BitConverter.ToInt32(new byte[] { low, high, 0x00, 0x00 }, 0);
            }
            else
            {
                size = bytes;
            }

            while (reader.ReadByte() == 0x00)
            {
                size -= 1;
            }

            reader.BaseStream.Seek(-1, SeekOrigin.Current);
            return size;
        }
    }
}
