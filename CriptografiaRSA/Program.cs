using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CriptografiaRSA
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //var rsa1 = new RSACryptoServiceProvider();
                //string chavePublicaPrivadaXml = rsa1.ToXmlString(true);

                // Carrega o XML--------------------------------------------------
                System.Xml.XmlDocument xmldoc = new System.Xml.XmlDocument();

                //MemoryStream stream = new MemoryStream();
                //StreamWriter writer = new StreamWriter(stream);
                //writer.Write(chavePublicaPrivadaXml);
                //writer.Flush();
                //stream.Position = 0;

                xmldoc.Load("C:\\Users\\p-rdrago\\Desktop\\chave.xml");

                // pega o nó base RSAKeyValue...
                //System.Xml.XmlNode refNode = xmldoc.SelectSingleNode("RSAKeyValue");

                //string modulus = refNode.SelectSingleNode("Modulus").InnerText;

                //string exponent = refNode.SelectSingleNode("Exponent").InnerText;

                //string P = refNode.SelectSingleNode("P").InnerText;

                //string Q = refNode.SelectSingleNode("Q").InnerText;

                //string DP = refNode.SelectSingleNode("DP").InnerText;

                //string DQ = refNode.SelectSingleNode("DQ").InnerText;

                //string inverseQ = refNode.SelectSingleNode("InverseQ").InnerText;

                //string D = refNode.SelectSingleNode("D").InnerText;
                //-----------------------------------------------------------------------

                //Create a UnicodeEncoder to convert between byte array and string.
                UnicodeEncoding ByteConverter = new UnicodeEncoding();

                string chavePublica = "<RSAKeyValue><Modulus>5hnGaAwkS22PYPNUyduCBVKVvHjdLutT8MmLo8eqTG30AcW5Jo0jknl82QTk4V74Y0eR3JuBDYU/CQSGQUB3zER+1X4C8HWS8saq6BJvdYom8nHibfYeqlChH/ZSWrczzYBFPWTja4T7uyJb7OoX/qqY4T9XsIZsT2IYqDSLBTE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

                string chavePrivada = xmldoc.OuterXml;

                //Create byte arrays to hold original, encrypted, and decrypted data.
                byte[] dataToEncrypt = ByteConverter.GetBytes("Drago");
                byte[] encryptedData;
                byte[] decryptedData;

                using (var rsa = new RSACryptoServiceProvider(1024))
                {
                    try
                    {
                        rsa.FromXmlString(chavePublica);
                        encryptedData = rsa.Encrypt(dataToEncrypt, true);

                        rsa.FromXmlString(chavePrivada);
                        decryptedData = rsa.Decrypt(encryptedData, true);

                        Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }

                Console.ReadLine();

            }
            catch (ArgumentNullException ex)
            {
                Console.WriteLine("Encryption failed." + ex.Message.ToString());
                Console.ReadLine();
            }
        }

        static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;

                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Import the RSA Key information. This only needs toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }

        static public byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;

                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }
        }

        static public RSAParameters getPublicPrivateKeyInformation()
        {
            RSAParameters RSAParams = new RSAParameters();

            try
            {
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Export the key information to an RSAParameters object.
                    //Pass false to export the public key information or pass
                    //true to export public and private key information.
                    RSAParams = RSA.ExportParameters(true);

                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }

            return RSAParams;
        }
    }
}
