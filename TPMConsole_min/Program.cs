using System;
using System.Collections;
using System.Reflection.Metadata;
using System.Text;
using System.Xml.Linq;
using Tpm2Lib;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;

namespace TPMKeyCreationExample
{
    class Program
    {
        private static uint tpm_ht = 0x01C00000; // Default value
        private static uint en_getprop = 0;
        private static uint en_getcmd = 0;
        private static uint en_rdhdl = 0;
        private static uint en_gencer = 0;
        private static Tpm2 tpm;
        static void Main(string[] args)
        {
            TbsDevice tpmDevice = null;
            try
            {

                // Initialize the TPM device
                tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                tpm = new Tpm2(tpmDevice, Behavior.Default);
                readXml();
                if(en_getprop!=0)
                    GetProperties();
                TpmHandle[] nvindexes = GetHandles();
                if (en_rdhdl != 0)
                    ReadHandles(nvindexes);
                if(en_getcmd != 0)
                    GetCommands();
                if(en_gencer != 0)
                    GenerateCert(nvindexes);
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
            finally
            {
                // Clean up and close the TPM connection
                tpm.Dispose();
                tpmDevice.Close();
            }

        }
        static void readXml()
        {
            try
            {
                XDocument xmlDoc = XDocument.Load("config.xml");
                XElement handleElement = xmlDoc.Root.Element("TpmHandleType");
                if (handleElement != null)
                {
                    tpm_ht = Convert.ToUInt32(handleElement.Value, 16);
                }
                en_getprop = Convert.ToUInt32(xmlDoc.Root.Element("getproperties").Value, 16);
                en_getcmd = Convert.ToUInt32(xmlDoc.Root.Element("getcommands").Value, 16);
                en_rdhdl = Convert.ToUInt32(xmlDoc.Root.Element("readhandles").Value, 16);
                en_gencer = Convert.ToUInt32(xmlDoc.Root.Element("generatecert").Value, 16);

            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while reading the XML file: " + ex.Message);
            }
        }
        static void ReadHandles(TpmHandle[] indexes)
        {
            foreach (var index in indexes)
            {
                try
                {
                    uint nvIndex = index.GetIndex();
                    // Step 3: Read the NV index using TPM2_NV_ReadPublic() and TPM2_NV_Read()
                    var nvPublic = tpm.NvReadPublic(index, out var nvName);
                    //string result = Encoding.UTF8.GetString(nvName);
                    //Console.WriteLine($"nvName : ---{result}----");
                    Console.WriteLine($"\n\nnvPublic.attributes :  {nvPublic.attributes}");
                    Console.WriteLine($"nvPublic.dataSize :    {nvPublic.dataSize}");
                    Console.WriteLine($"nvPublic.nameAlg :     {nvPublic.nameAlg}");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

            }
        }
        static TpmHandle[] GetHandles()
        {
            TpmHandle[] indexes = null;
            try
            {
                ICapabilitiesUnion nvIndices;
                // Step 1: Get a list of all NV indices in the EK certificate handle range
                const uint size = 0xFF;
                var value = tpm.GetCapability(Cap.Handles, tpm_ht, size, out nvIndices);
                indexes = ((HandleArray)nvIndices).handle;
                Console.WriteLine($"\n\n         #### Finding NV Indices ####");
                foreach (var index in indexes)
                {
                    Console.WriteLine($"Index : {index.GetIndex():X}");
                }
                // Step 2: Identify whether the NV indices are in the Low Range or High Range
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in Getting Handles: " + ex.Message);
            }
            return indexes;
        }
        static void GetProperties()
        {

            try
            {
                ICapabilitiesUnion caps;

                Console.WriteLine($"         #### TpmProperties ####");
                var value = tpm.GetCapability(Cap.TpmProperties, (uint)Pt.Revision, 256, out caps);

                TaggedProperty[] arr = (caps as TaggedTpmPropertyArray).tpmProperty;
                foreach (var item in arr)
                {
                    Console.WriteLine($"{item.property}  :  {item.value}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error occurred in getting properties: " + ex.Message);
            }
        }
        static void GetCommands()
        {
            try
            {
                ICapabilitiesUnion caps;

                Console.WriteLine($"         #### Library Commands ####");
                var value = tpm.GetCapability(Cap.Commands, (uint)Pt.LibraryCommands, 256, out caps);
                CcAttr[] arr = ((CcaArray)caps).commandAttributes;
                foreach (var item in arr)
                {
                    Console.WriteLine($"{item}");
                }
                Console.WriteLine($"         #### Vendor Commands ####");
                value = tpm.GetCapability(Cap.Commands, (uint)Pt.VendorCommands, 256, out caps);
                arr = ((CcaArray)caps).commandAttributes;
                foreach (CcAttr item in arr)
                {
                    Console.WriteLine($"{item}");

                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error getting commands: " + ex.Message);
            }


        }

        static void GenerateCert(TpmHandle[] indexes)
        {
            foreach (var index in indexes)
            {
                try
                {
                    uint nvIndex = index.GetIndex();
                    bool isLowRange = nvIndex >= 0x01C00002 && nvIndex <= 0x01C0000C;
                    //bool isHighRange = nvIndex >= 0x01C00012 && nvIndex <= ekCertHandleRangeEnd;

                    // Step 3: Read the NV index using TPM2_NV_ReadPublic() and TPM2_NV_Read()
                    var nvPublic = tpm.NvReadPublic(index, out var nvName);
                    var nvData = GetEkCertificateContent(nvPublic, index, tpm);
                    var certificate = new X509Certificate2(nvData);
                    if (certificate != null && certificate.PublicKey != null)
                    {
                        // Certificate is valid and has a private key (if applicable)
                        Console.WriteLine("Certificate is valid");
                        var cert = new X509Certificate2(nvData);
                        var pubKey = cert?.GetPublicKeyString();
                        var fileName = $"_TPM_EK_Cert_Index_{index.GetIndex():X}.crt";
                        byte[]? certData = cert?.GetRawCertData();
                        if (certData != null)
                            File.WriteAllBytes(fileName, certData);

                        Console.WriteLine($"{fileName} generated successfully.");

                    }
                    else
                    {
                        Console.WriteLine("Certificate is not valid");
                    }
                    
                }
                catch (Exception e)
                {

                    Console.WriteLine(e.Message);
                }

            }
        }
        static byte[] GetEkCertificateContent(NvPublic nvPublic, TpmHandle handle, Tpm2 tpm)
        {
            try
            {
                const ushort maxChunkSize = 700;

                byte[] ekCert = new byte[nvPublic.dataSize];

                ushort offset = 0;

                while (nvPublic.dataSize != offset)
                {
                    ushort dataSize = Math.Min(maxChunkSize, (ushort)(nvPublic.dataSize - offset));

                    byte[] data = tpm.NvRead(handle, handle, dataSize, offset);

                    data.CopyTo(ekCert, offset);

                    Array.Clear(data, 0, data.Length);

                    offset += dataSize;
                }

                return ekCert;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed GetEkCertificateContent :--------" + e.Message);

                throw;
            }

        }
    }
}