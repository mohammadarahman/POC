using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main(string[] args)
    {
        // Path to your .cer file
        string certPath = "C:\\Users\\rahmanma\\OneDrive - Intel Corporation\\Documents\\3_work\\certificates\\TEST_SC1_001.cer";

        // Load the certificate
        X509Certificate2 cert = new X509Certificate2(certPath);
        // print cert.PublicKey
        PublicKey publicKey = cert.PublicKey;
        Console.WriteLine($"Public Key OID: Friendly Name: {publicKey.Oid.FriendlyName}");
        Console.WriteLine($"Public Key OID: Value: {publicKey.Oid.Value}");
        Console.WriteLine("Signature Algorithm: " + cert.SignatureAlgorithm.FriendlyName);
        Console.WriteLine("\nEncoded Key Value (Base64):  `Convert.ToBase64String(publicKey.EncodedKeyValue.RawData)`  :: ");
        Console.WriteLine(Convert.ToBase64String(publicKey.EncodedKeyValue.RawData));

        // Print Encoded Parameters
        Console.WriteLine("\nEncoded Parameters (Base64): `Convert.ToBase64String(publicKey.EncodedParameters.RawData)` :: ");
        Console.WriteLine(Convert.ToBase64String(publicKey.EncodedParameters.RawData));
        // Get the RSA public key
        using (RSA rsa = cert.GetRSAPublicKey())
        {
            if (rsa == null)
            {
                Console.WriteLine("The certificate does not contain an RSA public key.");
                //return;
            }
            else
            {
                Console.WriteLine("RSA Public Key Found");
                // Extract RSA parameters
                RSAParameters rsaParams = rsa.ExportParameters(false); // False = public key only

                // Convert modulus and exponent to Base64 strings for display
                string modulus = Convert.ToBase64String(rsaParams.Modulus);
                string exponent = Convert.ToBase64String(rsaParams.Exponent);

                // Print the results
                Console.WriteLine("Modulus (n):");
                Console.WriteLine(modulus);
                Console.WriteLine();
                Console.WriteLine("Exponent (e):");
                Console.WriteLine(exponent);
            }

            
        }
        using (ECDsa ecdsa = cert.GetECDsaPublicKey())
        {
            if (ecdsa != null)
            {
                Console.WriteLine("\n\nECDSA Public Key Found");

                // Export the ECDSA public key parameters
                ECParameters ecParams = ecdsa.ExportParameters(false); // False = public key only

                // Print the curve details
                Console.WriteLine("Curve Name: " + ecParams.Curve.Oid.FriendlyName);
                Console.WriteLine("Curve OID: " + ecParams.Curve.Oid.Value);

                // Print the public key point (X, Y coordinates)
                Console.WriteLine("\nPublic Key Point:");
                Console.WriteLine("X: " + Convert.ToBase64String(ecParams.Q.X));
                Console.WriteLine("Y: " + Convert.ToBase64String(ecParams.Q.Y));
            }
            else
            {
                Console.WriteLine("The certificate does not contain an ECDSA public key.");
            }
        }
    }
}
