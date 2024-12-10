using System;
using System.Collections;
using System.Reflection.Metadata;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Tpm2Lib;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Azure.Devices.Shared;
using Microsoft.Azure.Devices.Provisioning.Security;
using System.Reflection;
using System.Diagnostics;
using System.Management.Automation;
using Microsoft.PowerShell.Commands;
using System.Security.Cryptography;



namespace TPMKeyCreationExample
{
    public class PublicKey
    {
        public string Oid { get; set; } =string.Empty;
        public string RawData { get; set; } = string.Empty;
    }

    public class TpmEndorsementKeyInfo
    {
        public PublicKey PublicKey { get; set; }= new PublicKey();
    }

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
        private static uint en_sendrc = 0;
        private static uint en_azuretst = 0;
        private static byte[] sendrawcommand_input;
        
        private static int[] x;
        private static uint en_nvrd = 0;
        private static uint en_nvrdidx = 0;
        private static uint en_pwrshell = 0;
        private static uint certidx = 0xc00002;
        private static uint nvidx = 3001;
        private static uint nvhdl = 3001;
        //private static ushort nvsz = 8;
        private static Tpm2 tpm;
        private static TbsDevice tpmDevice = null;
        static void Main()
        {
            
            try
            {

                // Initialize the TPM device
                tpmDevice = new TbsDevice(false);
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
                    ReadPublicPermanent();
                    ReadPublicPersistant();
                    ushort nvsz = NvReadPublic_();
                    NvRead(nvsz);
                }
                if ((en_rdpcr != 0)&&nvindexes!=null)
                    ReadPcr();
                if (en_getcmd != 0)
                    GetCommands();
                if((en_gencer != 0)&&nvindexes!=null)
                    GenerateCert(nvindexes);
                if (en_getalgpr != 0)
                    GetAlgProperties();
                if(en_azuretst!=0)
                    AzureTest();
                if (en_sendrc != 0)
                    SendRawCommand();
                if (en_nvrdidx != 0)
                    GenerateCertFrmIndex();
                if(en_pwrshell != 0)
                {
                    pwrshell();
                }

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
        static void SendRawCommand()
        {
            Console.WriteLine($"\n         #### Raw Command Send ####");

            CommandModifier active = new CommandModifier();
            active.ActivePriority = TBS_COMMAND_PRIORITY.HIGH;
            byte[] response = null;
            try
            {
                uint sendrawcommand_sz = (uint)sendrawcommand_input.Length;
                byte[] commandSizeBytes = BitConverter.GetBytes(sendrawcommand_sz);
                //byte[] command = ConstructTpmReadPublicCommand(tbsContext);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(commandSizeBytes);
                }
                Array.Copy(commandSizeBytes, 0, sendrawcommand_input, 2, 4);
                tpmDevice.DispatchCommand(active, sendrawcommand_input, out response);
                Console.WriteLine($"TPM Command : {BitConverter.ToString(sendrawcommand_input).Replace("-", " ")}");
                int resultSize = response.Length;
                Console.WriteLine("Result size: " + resultSize);
                for (int i = 0; i < resultSize; i++)
                {
                    if (x.Contains(i))
                    {
                        Console.Write("\n");
                    }
                    Console.Write(response[i].ToString("X2") + " ");
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("An error occurred while sending the raw command: " + ex.Message);
            }   
        } 

        static void AzureTest()
        {
            Console.WriteLine($"\n         #### Azure Test ####");
            using (var securityProviderTpm = new SecurityProviderTpmHsm("1234"))
            {
                try
                {
                    // Get the Endorsement Key (EK)
                    byte[] endorsementKey = securityProviderTpm.GetEndorsementKey();
                    Console.WriteLine($"Endorsement Key (EK): {BitConverter.ToString(endorsementKey).Replace("-", "")}");

                    // Attempt to create an X509Certificate2 from the endorsement key
                    try
                    {
                        var certificate = new X509Certificate2(endorsementKey);
                        var pubKey = certificate.GetPublicKeyString();
                        Console.WriteLine($"Public Key: {pubKey}");

                        string fileName = "_TPM_EK_Cert_Index.crt";
                        byte[] certData = certificate.GetRawCertData();
                        File.WriteAllBytes(fileName, certData);
                        Console.WriteLine($"{fileName} generated successfully.");
                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine("The endorsement key is not a valid certificate.");
                    }

                    // Convert the EK to a readable string (e.g., Base64 or Hex)
                    string ekBase64 = Convert.ToBase64String(endorsementKey);
                    Console.WriteLine($"Endorsement Key (EK) in Base64: {ekBase64}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error retrieving Endorsement Key: {ex.Message}");
                }
            }

        }
        static void readXml()
        {
            try
            {
                XDocument config = XDocument.Load("config.xml");
                XElement handleElement = config.Root.Element("TpmHandleType");
                if (handleElement != null)
                    tpm_ht = Convert.ToUInt32(handleElement.Value, 16);

                XElement capElement = config.Root.Element("TpmCapType");
                if (capElement != null)
                {
                    tpm_cap = (Cap)Convert.ToUInt32(capElement.Value, 16);
                    //Tpm2Lib.Cap cap = (Tpm2Lib.Cap)tpm_cap;

                }

                en_getprop = Convert.ToUInt32(config.Root.Element("getproperties").Value, 16);
                en_getcmd = Convert.ToUInt32(config.Root.Element("getcommands").Value, 16);
                en_rdhdl = Convert.ToUInt32(config.Root.Element("readhandles").Value, 16);
                en_rdpcr = Convert.ToUInt32(config.Root.Element("readpcr").Value, 16);
                en_gencer = Convert.ToUInt32(config.Root.Element("generatecert").Value, 16);
                en_nvrdidx = Convert.ToUInt32(config.Root.Element("GenerateCertFrmIndex").Value, 16);
                certidx = Convert.ToUInt32(config.Root.Element("GenerateCertFrmIndex_id").Value, 16);
                
                en_getalgpr = Convert.ToUInt32(config.Root.Element("GetAlgProperties").Value, 16);
                en_azuretst = Convert.ToUInt32(config.Root.Element("AzureTest").Value, 16);
                en_sendrc = Convert.ToUInt32(config.Root.Element("SendRawCommand").Value, 16);
                //sendrawcommand_sz = uint.Parse(config.Root.Element("SendRawCommand_sz").Value);
                sendrawcommand_input = config.Root.Element("SendRawCommand_input").Value
                                            .Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                                            .Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber))
                                            .ToArray();
                int[] sendrawcommand_opformat = config.Root.Element("SendRawCommand_opformat").Value
                       .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                       .Select(s => int.Parse(s.Trim()))
                       .ToArray();
                x = new int[50];
                int sum = 0;
                for (int i = 0; i < 50; i++)
                {
                    if (i < sendrawcommand_opformat.Length)
                    {
                        sum += sendrawcommand_opformat[i];
                    }
                    else
                    {
                        sum += 4;
                    }
                    x[i] = sum;
                }


                en_pwrshell = Convert.ToUInt32(config.Root.Element("pwrshell").Value, 16);
                en_nvrd = Convert.ToUInt32(config.Root.Element("NvRead").Value, 16);
                nvidx = Convert.ToUInt32(config.Root.Element("NvRead_idx").Value, 16);
                XElement nvhdlElement = config.Root.Element("NvRead_hdl");
                if (nvhdlElement != null)
                {
                    nvhdl = Convert.ToUInt32(nvhdlElement.Value, 16);
                }else
                {
                    nvhdl = nvidx;
                }
                //nvsz = Convert.ToUInt16(config.Root.Element("NvRead_sz").Value, 16);

            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while reading the XML file: " + ex.Message);
            }
        }
        static List<string> ExtractRawData(string jsonInput)
        {
            try
            {
                // Parse the JSON input
                var jsonDoc = JsonDocument.Parse(jsonInput);

                // Navigate to the RawData property
                string rawDataString = jsonDoc.RootElement
                                             .GetProperty("PublicKey")
                                             .GetProperty("RawData")
                                             .GetString();

                // Convert RawData to a list of integers
                string[] rawDataParts = rawDataString.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                List<string> rawDataList = new List<string>();

                foreach (string part in rawDataParts)
                {
                    if (int.TryParse(part, out int value))
                    {
                        rawDataList.Add(value.ToString("X2"));
                    }
                }

                return rawDataList;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return new List<string>();
            }
        }
        private static string executePowerShellCmd(string command)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -Command \"{command}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            string output = null; 
            using (Process powerShellProcess = new Process { StartInfo = psi })
            {
                try
                {
                    powerShellProcess.Start();
                    output = powerShellProcess.StandardOutput.ReadToEnd();
                    powerShellProcess.WaitForExit();
                    string error = powerShellProcess.StandardError.ReadToEnd();
                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        //Console.WriteLine($"PowerShell Error: {error}");
                        output = "ERROR: " + error.Split(new[] { Environment.NewLine }, StringSplitOptions.None)[0]; 
                    }
                }
                catch(Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }   
                
            }
            return output;
        }
        // write a function that converts hex string to byte array
        static byte[] HexStringToByteArray(string hexString)
        {
            

            if (hexString.Length % 2 != 0)
            {
                throw new ArgumentException("Invalid hex string length.");
            }
            byte[] byteArray = new byte[hexString.Length / 2];
            try
            {
                for (int i = 0; i < byteArray.Length; i++)
                {
                    byteArray[i] = byte.Parse(hexString.Substring(i * 2, 2), NumberStyles.HexNumber);
                    //Console.WriteLine(":" + i + hexString.Substring(i * 2, 2));
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }   


            return byteArray;
        }   
        static void pwrshell()
        {

            try
            {
                Console.WriteLine($"\n         #### PowerShell Command  using ProcessStartInfo ####");
                // Define the PowerShell command to retrieve the EK
                //string powerShellCommand = @"Get-CimInstance -Namespace 'Root\CIMv2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' ";
                //string powerShellCommand = @"Get-TpmEndorsementKeyInfo -Hash ""Sha256"" ";
                //string powerShellCommand = @"Get-TpmEndorsementKeyInfo -Hash ""Sha256"" | Select-Object PublicKey | ConvertTo-Json -Depth 1";
                //Get-TpmEndorsementKeyInfo -Hash "Sha256" | Select-Object -ExpandProperty ManufacturerCertificates|Select-Object serialnumber
                //Get-TpmEndorsementKeyInfo -Hash "Sha256" | Select-Object -ExpandProperty ManufacturerCertificates|Select-Object issuer
                //Get-TpmEndorsementKeyInfo -Hash "Sha256" | Select-Object -ExpandProperty ManufacturerCertificates|Select-Object thumbprint
                // Initialize the PowerShell process
                string powerShellCommand = @"(Get-TpmEndorsementKeyInfo -Hash ""Sha256"").ManufacturerCertificates.GetPublicKeyString()";
                string x = executePowerShellCmd(powerShellCommand);
                Console.WriteLine("public key: ");
                Console.WriteLine(x);
                powerShellCommand = @"(Get-TpmEndorsementKeyInfo -Hash ""Sha256"").ManufacturerCertificates.GetRawCertDataString()";
                x = executePowerShellCmd(powerShellCommand);
                Console.WriteLine("Raw Cert Data: ");
                Console.WriteLine(x);
                byte[] certdata = HexStringToByteArray(x.Trim());
                Console.WriteLine(certdata);
                powerShellCommand = @"(Get-TpmEndorsementKeyInfo -Hash ""Sha256"").AdditionalCertificates.GetPublicKeyString()";
                x = executePowerShellCmd(powerShellCommand);
                Console.WriteLine("additional public key Data: ");
                Console.WriteLine(x);
                powerShellCommand = @"(Get-TpmEndorsementKeyInfo -Hash ""Sha256"").AdditionalCertificates.GetRawCertDataString()";
                x = executePowerShellCmd(powerShellCommand);
                Console.WriteLine("additional Raw Cert Data: ");
                Console.WriteLine(x);


                return;
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"{powerShellCommand}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process powerShellProcess = new Process { StartInfo = psi })
                {
                    // Start the process
                    powerShellProcess.Start();

                    // Read the standard output
                    string output = powerShellProcess.StandardOutput.ReadToEnd();

                    // Wait for the process to finish
                    powerShellProcess.WaitForExit();

                    // Check for errors
                    string error = powerShellProcess.StandardError.ReadToEnd();
                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        Console.WriteLine($"PowerShell Error: {error}");
                    }
                    else
                    {
                        Console.WriteLine("Endorsement Key (EK):");
                        Console.WriteLine(output);
                        List<string> rawDataList = ExtractRawData(output);
                        Console.WriteLine("RawData as List of Integers: size: "+ rawDataList.Count);
                        rawDataList.ForEach(i => Console.Write(i ));
                    }
                }
                powerShellCommand = @"Get-TpmEndorsementKeyInfo -Hash ""Sha256"" | Select-Object -ExpandProperty ManufacturerCertificates|Select-Object serialnumber";
                psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"{powerShellCommand}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (Process powerShellProcess = new Process { StartInfo = psi })
                {
                    // Start the process
                    powerShellProcess.Start();

                    // Read the standard output
                    string output = powerShellProcess.StandardOutput.ReadToEnd();

                    // Wait for the process to finish
                    powerShellProcess.WaitForExit();

                    // Check for errors
                    string error = powerShellProcess.StandardError.ReadToEnd();
                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        Console.WriteLine($"PowerShell Error: {error}");
                    }
                    else
                    {
                        Console.WriteLine("Endorsement Key (Serial NO):");
                        Console.WriteLine(output);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            try
            {
                Console.WriteLine($"\n         #### PowerShell Command  using ProcessStartInfo ####");
                Console.WriteLine("                 It requires system.management.automation and many more \n");
                using (PowerShell powerShell = PowerShell.Create())
                {
                    powerShell.AddScript(@"
                Get-TpmEndorsementKeyInfo -Hash 'Sha256' |
                Select-Object PublicKey |
                ConvertTo-Json -Depth 1
            ");

                    // Execute the PowerShell script
                    var results = powerShell.Invoke();

                    if (results.Count > 0)
                    {
                        // Parse the JSON output
                        string jsonOutput = results[0].ToString();
                        TpmEndorsementKeyInfo ekInfo = JsonSerializer.Deserialize<TpmEndorsementKeyInfo>(jsonOutput);

                        // Output the EK PublicKey
                        Console.WriteLine($"EK PublicKey: {ekInfo.PublicKey.RawData}");
                    }
                    else
                    {
                        Console.WriteLine("No results returned from PowerShell.");
                    }
                }

            }
            catch(Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

        }
        static void NvRead(ushort sz)
        {
            ushort offset = 0;
            ushort remsz = sz;
            try
            {
                /*
                // Correctly start a policy session
                // Step 2: Start a policy session with correct arguments
                byte[] nonceCaller = new byte[20]; // 20 bytes is standard for nonceCaller
                new Random().NextBytes(nonceCaller); // Generate a random nonceCaller
                byte[] encryptedSalt = null;        // No encrypted salt for this session

                // Start the session
                byte[] nonceTPM; // This will hold the TPM-generated nonce
                AuthSession policySession = tpm.StartAuthSession(
                    TpmHandle.RhNull,          // No specific key handle
                    TpmHandle.RhNull,          // No bind handle
                    nonceCaller,               // Caller nonce
                    encryptedSalt,             // Encrypted salt (null for no salt)
                    TpmSe.Policy,              // Session type (Policy session)
                    new SymDef(SymDefObject.NullObject()), // No symmetric encryption
                    TpmAlgId.Sha256,           // SHA-256 as the hash algorithm
                    out nonceTPM               // Out parameter for TPM nonce
                );

                // Assume policySession is already created using StartAuthSession
                byte writtenSet = 0; // Adjust to match the expected written state (0 or 1)

                // Apply the PolicyNvWritten condition
                tpm.PolicyNvWritten(policySession.Handle, writtenSet);

                TpmHandle authHandle = TpmRh.Owner;
                */
                Console.WriteLine($"\n         #### NV Read ####");
                for (int i = 0; i <= sz / 700; i++)
                {
                    ushort cursz = (ushort)((remsz > 700) ? 700 : remsz);
                    TpmHandle nvHandle = TpmHandle.NV(nvhdl);
                    TpmHandle nvIndex = TpmHandle.NV(nvidx);
                    byte[] nvRead = tpm.NvRead(nvIndex, nvIndex, cursz, offset);
                    remsz -= 700;
                    offset += 700;
                    Console.WriteLine($"\nnvRead:{i} {nvRead.Length}  #  {BitConverter.ToString(nvRead).Replace("-", "")}");
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("Error in NvRead: " + ex.Message);
            }
            
        }
        static ushort ReadPublicPermanent()
        {
            //return 0;
            ushort size = 0;
            try
            {
                Console.WriteLine($"\n         ####  Read Public (permanent) ####");
                TpmHandle nvIndex = TpmHandle.RhOwner;
                //nvPublic and nVRead is same
                var tpmPublic = tpm.ReadPublic(nvIndex, out var nvName, out var nvQualifiedname);
                if (tpmPublic != null)
                {
                    Console.WriteLine($"Type: {tpmPublic.type}");
                    Console.WriteLine($"Algorithm: {tpmPublic.parameters}");

                    // Extract RSA Public Key (Modulus)
                    if (tpmPublic.type == TpmAlgId.Rsa)
                    {
                        var rsaPublicKey = tpmPublic.unique as Tpm2bPublicKeyRsa;
                        if (rsaPublicKey != null)
                        {
                            Console.WriteLine("RSA Public Key Modulus:");
                            Console.WriteLine(BitConverter.ToString(rsaPublicKey.buffer));
                        }
                    }

                    // Extract ECC Public Key
                    if (tpmPublic.type == TpmAlgId.Ecc)
                    {
                        var eccPoint = tpmPublic.unique as EccPoint;
                        if (eccPoint != null)
                        {
                            Console.WriteLine("ECC Public Key:");
                            Console.WriteLine($"X: {BitConverter.ToString(eccPoint.x)}");
                            Console.WriteLine($"Y: {BitConverter.ToString(eccPoint.y)}");
                        }
                    }
                }
                ParseNvName(nvName);
                ParseNvName(nvQualifiedname);
                Console.WriteLine($"Read Public: Index({nvidx.ToString("X")})  #  {BitConverter.ToString(tpmPublic)}");
                Console.WriteLine($"\ntpmPublic.attributes :  {tpmPublic.objectAttributes}");
                Console.WriteLine($"tpmPublic.para :    {tpmPublic.parameters}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in NvRead: " + ex.Message);
            }
            return size;

        }
        static ushort ReadPublicPersistant()
        {
            ushort size = 0;
            try
            {
                Console.WriteLine($"\n         ####  Read Public (persistant) ####");
                TpmHandle nvIndex = TpmHandle.Persistent(nvidx);
                //nvPublic and nVRead is same
                var tpmPublic = tpm.ReadPublic(nvIndex, out var nvName,out var nvQualifiedname);
                if (tpmPublic != null)
                {
                    Console.WriteLine($"Type: {tpmPublic.type}");
                    Console.WriteLine($"Algorithm: {tpmPublic.parameters}");
                    
                    // Extract RSA Public Key (Modulus)
                    if (tpmPublic.type == TpmAlgId.Rsa)
                    {
                        var rsaPublicKey = tpmPublic.unique as Tpm2bPublicKeyRsa;
                        if (rsaPublicKey != null)
                        {
                            Console.WriteLine("RSA Public Key Modulus:");
                            Console.WriteLine(BitConverter.ToString(rsaPublicKey.buffer));
                        }
                        else
                        {
                            Console.WriteLine("The public key is not an RSA public key.");
                        }
                    }

                    // Extract ECC Public Key
                    if (tpmPublic.type == TpmAlgId.Ecc)
                    {
                        var eccPoint = tpmPublic.unique as EccPoint;
                        if (eccPoint != null)
                        {
                            Console.WriteLine("ECC Public Key:");
                            Console.WriteLine($"X: {BitConverter.ToString(eccPoint.x)}");
                            Console.WriteLine($"Y: {BitConverter.ToString(eccPoint.y)}");
                        }
                    }
                }
                ParseNvName(nvName);
                ParseNvName(nvQualifiedname);
                Console.WriteLine($"Read Public: Index({nvidx.ToString("X")})  #  {BitConverter.ToString(tpmPublic)}");
                Console.WriteLine($"\ntpmPublic.attributes :  {tpmPublic.objectAttributes}");
                Console.WriteLine($"tpmPublic.para :    {tpmPublic.parameters}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in NvRead: " + ex.Message);
            }
            return size;

        }
        static ushort NvReadPublic_()
        {
            ushort size = 0; 
            try
            { 
                Console.WriteLine($"\n         #### NV Read Public ####");
                TpmHandle nvIndex = TpmHandle.NV(nvidx);
                //nvPublic and nVRead is same
                var nvPublic = tpm.NvReadPublic(nvIndex, out var nvName);
                ParseNvName(nvName);
                Console.WriteLine($"nvRead Public: Index({nvidx.ToString("X")})  #  {BitConverter.ToString(nvPublic)}");
                Console.WriteLine($"\nnvPublic.attributes :  {nvPublic.attributes}");
                Console.WriteLine($"nvPublic.dataSize :    {nvPublic.dataSize}");
                size = nvPublic.dataSize;
                Console.WriteLine($"nvPublic.nameAlg :     {nvPublic.nameAlg}");
            }
            catch(Exception ex)
            {
                Console.WriteLine("Error in NvRead: " + ex.Message);
            }
            return size;
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
                //var value = tpm.GetCapability(tpm_cap, tpm_ht, size, out nvIndices);
                var value = tpm.GetCapability(Cap., tpm_ht, size, out nvIndices);
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

                var value = tpm.GetCapability(Cap.TpmProperties, 0, 256, out caps);

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
        static void GenerateCertFrmIndex()
        {
            var index = TpmHandle.NV(certidx);
            Console.WriteLine($"\n\n         #### Generating Certificates ####");
            try
            {
                uint nvIndex = index.GetIndex();
                //bool isLowRange = nvIndex >= 0x01C00002 && nvIndex <= 0x01C0000C;
                //bool isHighRange = nvIndex >= 0x01C00012 && nvIndex <= ekCertHandleRangeEnd;

                // Step 3: Read the NV index using TPM2_NV_ReadPublic() and TPM2_NV_Read()
                var nvPublic = tpm.NvReadPublic(index, out var nvName);
                var nvData = GetEkCertificateContent(nvPublic, index, tpm);
                var certificate = new X509Certificate2(nvData);
                if (certificate != null && certificate.PublicKey != null)
                {
                    // Certificate is valid and has a private key (if applicable)
                    //Console.WriteLine("Certificate is valid");
                    //var cert = new X509Certificate2(nvData);
                    var pubKey = certificate?.GetPublicKeyString();
                    Console.WriteLine($"Public Key: {pubKey.GetHashCode()}");
                    var fileName = $"_TPM_EK_Cert_Index_{index.GetIndex():X}.crt";
                    byte[]? certData = certificate?.GetRawCertData();
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

        static void GenerateCert(TpmHandle[] indexes)
        {
            Console.WriteLine($"\n\n         #### Generating Certificates ####");
            foreach (var index in indexes)
            {
                try
                {
                    uint nvIndex = index.GetIndex();
                    //bool isLowRange = nvIndex >= 0x01C00002 && nvIndex <= 0x01C0000C;
                    //bool isHighRange = nvIndex >= 0x01C00012 && nvIndex <= ekCertHandleRangeEnd;

                    // Step 3: Read the NV index using TPM2_NV_ReadPublic() and TPM2_NV_Read()
                    var nvPublic = tpm.NvReadPublic(index, out var nvName);
                    var nvData = GetEkCertificateContent(nvPublic, index, tpm);
                    //print byte[]
                    

                    
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
                Console.WriteLine($"nvPublic: #  {BitConverter.ToString(nvPublic).Replace("-", "")}");

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
                Console.WriteLine($"nvData: {ekCert.Length}  #  {BitConverter.ToString(ekCert).Replace("-", "")}");
                
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