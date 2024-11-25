using System;
using System.Collections;
using System.Reflection.Metadata;
using System.Text;
using System.Xml.Linq;
using Tpm2Lib;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using System.Runtime.InteropServices;

namespace TPMKeyCreationExample
{
    class Program
    {
        private static uint tpm_ht = 0x01C00000; // Default value
        private static Cap tpm_cap = Cap.Handles; // Default value
        private static uint en_getprop = 0;
        private static uint en_getcmd = 0;
        private static uint en_rdhdl = 0;
        private static uint en_rdpcr = 0;
        private static uint en_gencer = 0;
        private static uint en_getalgpr = 0;
        private static uint en_nvrd = 0;
        private static uint nvidx = 3001;
        private static uint nvhdl = 3001;
        private static ushort nvsz = 8;
        private static Tpm2 tpm;
        static void Main()
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
                if ((en_rdhdl != 0)&& nvindexes != null)
                    ReadHandles(nvindexes);
                if (en_nvrd != 0)
                {
                    NvRead();
                    NvReadPublic();
                }
                if ((en_rdpcr != 0)&&nvindexes!=null)
                    ReadPcr();
                if (en_getcmd != 0)
                    GetCommands();
                if((en_gencer != 0)&&nvindexes!=null)
                    GenerateCert(nvindexes);
                if (en_getalgpr != 0)
                    GetAlgProperties();

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
                    tpm_ht = Convert.ToUInt32(handleElement.Value, 16);

                XElement capElement = xmlDoc.Root.Element("TpmCapType");
                if (capElement != null)
                {
                    tpm_cap = (Cap)Convert.ToUInt32(capElement.Value, 16);
                    //Tpm2Lib.Cap cap = (Tpm2Lib.Cap)tpm_cap;

                }

                en_getprop = Convert.ToUInt32(xmlDoc.Root.Element("getproperties").Value, 16);
                en_getcmd = Convert.ToUInt32(xmlDoc.Root.Element("getcommands").Value, 16);
                en_rdhdl = Convert.ToUInt32(xmlDoc.Root.Element("readhandles").Value, 16);
                en_rdpcr = Convert.ToUInt32(xmlDoc.Root.Element("readpcr").Value, 16);
                en_gencer = Convert.ToUInt32(xmlDoc.Root.Element("generatecert").Value, 16);
                en_getalgpr = Convert.ToUInt32(xmlDoc.Root.Element("GetAlgProperties").Value, 16);
                en_nvrd = Convert.ToUInt32(xmlDoc.Root.Element("NvRead").Value, 16);
                nvidx = Convert.ToUInt32(xmlDoc.Root.Element("NvRead_idx").Value, 16);
                nvhdl = Convert.ToUInt32(xmlDoc.Root.Element("NvRead_hdl").Value, 16);
                nvsz = Convert.ToUInt16(xmlDoc.Root.Element("NvRead_sz").Value, 16);

            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while reading the XML file: " + ex.Message);
            }
        }
        static void NvRead()
        {
            Console.WriteLine($"\n         #### NV Read ####");
            TpmHandle nvHandle = TpmHandle.NV(nvhdl);
            TpmHandle nvIndex = TpmHandle.NV(nvidx);
            byte[] nvRead = tpm.NvRead(nvHandle, nvIndex, nvsz, 0);
            Console.WriteLine($"NV Read: {nvRead.Length}  #  {BitConverter.ToString(nvRead).Replace("-", "")}");
        }
        static void NvReadPublic()
        {
            Console.WriteLine($"\n         #### NV Read Public ####");
            TpmHandle nvIndex = TpmHandle.NV(nvidx);
            byte[] nvRead = tpm.NvReadPublic(nvIndex, out var nvName);
            ParseNvName(nvName);
            Console.WriteLine($"NV Read Public: {nvRead.Length}  #  {BitConverter.ToString(nvRead).Replace("-", "")}");
        }
        static void ReadHandles(TpmHandle[] indexes)
        {
            Console.WriteLine($"\n\n         #### Reading data from found handles.  ####");
            foreach (var index in indexes)
            {
                try
                {
                    uint nvIndex = index.GetIndex();
                    Console.WriteLine($"\n\n {nvIndex:X}");
                    // Step 3: Read the NV index using TPM2_NV_ReadPublic() and TPM2_NV_Read()
                    var nvPublic = tpm.NvReadPublic(index, out var nvName);
                    //string result = Encoding.UTF8.GetString(nvName);
                    ParseNvName(nvName);
                    //Console.WriteLine($"nvName : ---{result}----");
                    Console.WriteLine($"\nnvPublic.attributes :  {nvPublic.attributes}");
                    Console.WriteLine($"nvPublic.dataSize :    {nvPublic.dataSize}");
                    Console.WriteLine($"nvPublic.nameAlg :     {nvPublic.nameAlg}");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

            }
        }
        static void ReadPcr()
        {
            Console.WriteLine($"\n\n         #### Reading PCR ####");
            
            ICapabilitiesUnion caps;
            const uint size = 0xFF;
            var value = tpm.GetCapability(Cap.Pcrs, (uint)PtPcr.First, size, out caps);
            PcrSelection[] pcrs = (caps as PcrSelectionArray).pcrSelections;
            foreach (var index in pcrs)
            {
                try
                {
                    byte[] nvIndex = index.pcrSelect;
                    string hexString = BitConverter.ToString(nvIndex).Replace("-", " ");
                    Console.WriteLine($"PcrSelect: {hexString}");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

            }


            Console.WriteLine("Available PCR banks:");
            foreach (PcrSelection pcrBank in pcrs)
            {
                var sb = new StringBuilder();
                sb.AppendFormat("PCR bank for algorithm {0} has registers at index:", pcrBank.hash);
                sb.AppendLine();
                foreach (uint selectedPcr in pcrBank.GetSelectedPcrs())
                {
                    sb.AppendFormat("{0},", selectedPcr);
                }
                Console.WriteLine(sb);
            }

            tpm.GetCapability(Cap.PcrProperties, 0, size, out caps);

            Console.WriteLine();
            Console.WriteLine("PCR attributes:");
            TaggedPcrSelect[] pcrProperties = ((TaggedPcrPropertyArray)caps).pcrProperty;
            foreach (TaggedPcrSelect pcrProperty in pcrProperties)
            {
                if (pcrProperty.tag == PtPcr.None)
                {
                    continue;
                }

                uint pcrIndex = 0;
                var sb = new StringBuilder();
                sb.AppendFormat("PCR property {0} supported by these registers: ", (PtPcr)pcrProperty.tag);
                sb.AppendLine();
                foreach (byte pcrBitmap in pcrProperty.pcrSelect)
                {
                    for (int i = 0; i < 8; i++)
                    {
                        if ((pcrBitmap & (1 << i)) != 0)
                        {
                            sb.AppendFormat("{0},", pcrIndex);
                        }
                        pcrIndex++;
                    }
                }
                Console.WriteLine(sb);
            }
        }
        static TpmHandle[] GetHandles()
        {
            Console.WriteLine($"\n\n         #### Finding NV Indices ####");
            TpmHandle[] indexes = null;
            try
            {
                ICapabilitiesUnion nvIndices;
                // Step 1: Get a list of all NV indices in the EK certificate handle range
                const uint size = 0xFF;
                var value = tpm.GetCapability(tpm_cap, tpm_ht, size, out nvIndices);
                indexes = ((HandleArray)nvIndices).handle;
                foreach (var index in indexes)
                {
                    Console.WriteLine($"Index : {index.GetIndex():X}  Type : {index.GetType():X} offset: {index.GetOffset():X}");

                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in Getting Handles: " + ex.Message);
            }
            return indexes;
        }
        static void GetProperties()
        {

            Console.WriteLine($"         #### TpmProperties ####");
            try
            {
                ICapabilitiesUnion caps;

                var value = tpm.GetCapability(Cap.TpmProperties, 258, 256, out caps);

                TaggedProperty[] arr = (caps as TaggedTpmPropertyArray).tpmProperty;
                int i = 0;
                foreach (var item in arr)
                {
                    i++;
                    Console.WriteLine($"{i} {item.property}  :  {item.value}");
                }
                Console.WriteLine("Total Properties: " + i);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error occurred in getting properties: " + ex.Message);
            }
        }
        static void GetAlgProperties()
        {

            Console.WriteLine($"\n\n         #### Tpm alg Properties ####");
            try
            {
                ICapabilitiesUnion caps;

                var value = tpm.GetCapability(Cap.First, 0x0, 256, out caps);

                AlgProperty[] arr = (caps as AlgPropertyArray).algProperties;
                foreach (var item in arr)
                {
                    Console.WriteLine($"{item.alg}  :  {item.algProperties}");
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
                var value = tpm.GetCapability(Cap.Commands, 0x11F, 256, out caps);
                CcAttr[] arr = ((CcaArray)caps).commandAttributes;
                foreach (var item in arr)
                {
                    Console.WriteLine($"{item}");
                }
                Console.WriteLine($"         #### Vendor Commands ####");
                value = tpm.GetCapability(Cap.Commands, 0x20000000, 256, out caps);
                arr = ((CcaArray)caps).commandAttributes;
                foreach (CcAttr item in arr)
                {
                    Console.WriteLine($"{item}");

                }

                Console.WriteLine($"         #### Supported commands  ####");
                tpm.GetCapability(Cap.Commands, (uint)TpmCc.First, TpmCc.Last - TpmCc.First + 1, out caps);
                var commands = (CcaArray)caps;
                List<TpmCc> implementedCc = new List<TpmCc>();
                int i = 0; 
                foreach (var attr in commands.commandAttributes)
                {
                    i++;
                    var commandCode = (TpmCc)((uint)attr & 0x0000FFFFU);
                    implementedCc.Add(commandCode);
                    Console.WriteLine(" {0}  {1}", i, commandCode.ToString());
                }
                Console.WriteLine(" {0}  {1}", "Total: ", i);

                
                Console.WriteLine("Commands from spec not implemented:");
                i = 0; 
                foreach (var cc in Enum.GetValues(typeof(TpmCc)))
                {
                    if (!implementedCc.Contains((TpmCc)cc))
                    {
                        i++;
                        Console.WriteLine("  {0} {1}", i, cc.ToString());
                    }
                }
                Console.WriteLine(" {0}  {1}", "Total: ", i);

                Console.WriteLine($"         #### Vendor Commands ####");
                value = tpm.GetCapability(Cap.Commands, 0x20000000, 1024, out caps);
                commands = (CcaArray)caps;
                i = 0; 
                foreach (var attr in commands.commandAttributes)
                {
                    i++;
                    var commandCode = (TpmCc)((uint)attr & 0x0000FFFFU);
                    Console.WriteLine(" {0}  {1}", i, commandCode.ToString());
                }
                Console.WriteLine(" {0}  {1}", "Total: ", i);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error getting commands: " + ex.Message);
            }


        }

        static void GenerateCert(TpmHandle[] indexes)
        {
            Console.WriteLine($"\n\n         #### Generating Certificates ####");
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
        private static void ParseNvName(byte[] nvName)
        {
            if (nvName == null || nvName.Length < 2)
            {
                Console.WriteLine("Invalid nvName.");
                return;
            }

            // Extract Hash Algorithm ID (first 2 bytes)
            ushort hashAlgId = (ushort)((nvName[0] << 8) | nvName[1]);
            Console.WriteLine($"Hash Algorithm ID: 0x{hashAlgId:X4}");

            // Map Hash Algorithm ID to Algorithm Name
            string hashAlgName = hashAlgId switch
            {
                0x0004 => "SHA-1",
                0x000B => "SHA-256",
                0x000C => "SHA-384",
                0x000D => "SHA-512",
                _ => "Unknown"
            };
            Console.WriteLine($"Hash Algorithm: {hashAlgName}");

            // Extract the Hash Digest
            int hashDigestStart = 2;
            byte[] hashDigest = new byte[nvName.Length - hashDigestStart];
            Array.Copy(nvName, hashDigestStart, hashDigest, 0, hashDigest.Length);

            Console.WriteLine($"Hash Digest ({hashDigest.Length} bytes): {BitConverter.ToString(hashDigest).Replace("-", "")}");
        }

    }
}