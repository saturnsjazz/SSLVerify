using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SSLVerify
{

    //Validates Certs in the trusted root authority.  Still WIP.
    public class Validate509Cert
    {
        private static bool ValidateServerCertficate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            bool certMatch = false; // Assume failure
            switch (sslPolicyErrors)
            {
                case SslPolicyErrors.None:
                    Console.WriteLine("No validation errors - accepting certificate");
                    certMatch = true;
                    break;
                case SslPolicyErrors.RemoteCertificateChainErrors:
                    Console.WriteLine("Failed to validate certificate chain. Most likely a self-signed certificate");
                    if (chain.ChainElements.Count == 1 && chain.ChainStatus[0].Status == X509ChainStatusFlags.UntrustedRoot) //It is a self-signed certificate, so chain length will be 1.
                    {
                        X509Certificate savedCert = X509Certificate.CreateFromCertFile("CertName");
                        if (savedCert.Equals(cert)) //This verifies that the issuer and serial number matches. You can also use a cryptographic hash, or match the two certificates byte by byte.
                        {
                            Console.WriteLine("The certificates match");
                            certMatch = true;
                        }
                    }
                    break;
                default:
                    Console.WriteLine("Name mismatch or remote-cert not available. Rejecting connection");
                    break;
            }
            return certMatch;
        }
    }
}
