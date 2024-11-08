using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Xml.Schema;
using System.Security.Cryptography;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

using System.Linq.Expressions;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Reflection.Metadata;
namespace FTPMDetection
{
    public class FtpmPoc
    {
         
        public void getBiosInfo()
        {
            try
            {
                // Create a searcher to find the BIOS information
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");

                foreach (ManagementObject bios in searcher.Get())
                {
                    Console.WriteLine("BIOS related all information: ");
                    foreach (var property in bios.Properties)
                    {
                        Console.WriteLine($"{property.Name}: {property.Value}");
                    }
                    Console.WriteLine("\n Selected information:  ");
                    Console.WriteLine("BIOS Version: " + bios["Version"]);
                    Console.WriteLine("Manufacturer: " + bios["Manufacturer"]);
                    Console.WriteLine("Release Date: " + bios["ReleaseDate"]);
                    Console.WriteLine("SMBIOS Version: " + bios["SMBIOSBIOSVersion"]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }
        public void getTPMInfo() // not working
        {
            try
            {
                ManagementClass managementClass = new ManagementClass("root\\CIMV2:__Class");
                bool classExists = false;

                foreach (ManagementObject obj in managementClass.GetInstances())
                {
                    if (obj["__CLASS"].ToString() == "Win32_Tpm")
                    {
                        classExists = true;
                        break;
                    }
                }

                if (!classExists)
                {
                    Console.WriteLine("The Win32_Tpm class is not available on this system.");
                    return;
                }
                // Create a searcher to find the TPM information
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Tpm");

                ManagementObjectCollection tpmCollection;
                try
                {
                    tpmCollection = searcher.Get();
                }
                catch (ManagementException me)
                {
                    if (me.Message.Contains("Invalid class"))
                    {
                        Console.WriteLine("The Win32_Tpm class is not available on this system.");
                        return;
                    }
                    else
                    {
                        throw;
                    }
                }

                // Create a searcher to find the BIOS information
                //ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Tpm");
                //ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Tpm");


                // Alternative way to get the TPM information using the Get-WmiObject cmdlet in PowerShell
                if (tpmCollection.Count == 0)
                {
                    Console.WriteLine("No TPM found on this device.");
                    return;
                }
                // Get-WmiObject -Namespace "Root\CIMv2" -Class Win32_Tpm
                foreach (ManagementObject tpm in tpmCollection)
                {
                    // Get the Manufacturer ID
                    string manufacturerId = tpm["ManufacturerID"]?.ToString();
                    // Get the Spec Version
                    string specVersion = tpm["SpecVersion"]?.ToString();
                    // Get the Firmware Version
                    string firmwareVersion = tpm["FirmwareVersion"]?.ToString();
                    // Get the Manufacturer Version
                    string manufacturerVersion = tpm["ManufacturerVersion"]?.ToString();
                    // Get the Physical Presence Version Info
                    string physicalPresenceVersionInfo = tpm["PhysicalPresenceVersionInfo"]?.ToString();

                    Console.WriteLine($"TPM Manufacturer ID: {manufacturerId}");
                    Console.WriteLine($"TPM Spec Version: {specVersion}");
                    Console.WriteLine($"TPM Firmware Version: {firmwareVersion}");
                    Console.WriteLine($"TPM Manufacturer Version: {manufacturerVersion}");
                    Console.WriteLine($"TPM Physical Presence Version Info: {physicalPresenceVersionInfo}");
                }
            }
            catch (ManagementException me)
            {
                Console.WriteLine("An error occurred while querying for WMI data: " + me.Message);
            }
            catch (UnauthorizedAccessException uae)
            {
                Console.WriteLine("You do not have the necessary permissions to access this information: " + uae.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("An unexpected error occurred: " + ex.Message);
            }
        }

        public void getTPMInfo0()
        {
            bool classExists = false;
            try
            {
                var sessionOptions = new DComSessionOptions
                {
                    Timeout = TimeSpan.FromSeconds(30)
                };
                var cimSession = CimSession.Create("localhost", sessionOptions);

                var tpmInstances = cimSession.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_Tpm");

                if (tpmInstances == null || !tpmInstances.Any())
                {
                    Console.WriteLine("No TPM found on this device.");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception0: " + ex.Message);
                Console.WriteLine("Stack Trace0: " + ex.StackTrace);
            }
            try { 
                ManagementClass managementClass = new ManagementClass("root\\CIMV2:__Class");
                

                foreach (ManagementObject obj in managementClass.GetInstances())
                {
                    if (obj["__CLASS"].ToString() == "Win32_Tpm")
                    {
                        classExists = true;
                        break;
                    }
                }

                if (!classExists)
                {
                    Console.WriteLine("The Win32_Tpm class is not available on this system.");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception1: " + ex.Message);
                Console.WriteLine("Stack Trace1: " + ex.StackTrace);
            }
            try
            {
                // Create a searcher to find the TPM information
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Tpm");

                // Attempt to get the TPM collection
                ManagementObjectCollection tpmCollection = searcher.Get();

                // Check if any TPM objects are found
                if (tpmCollection != null && tpmCollection.Count > 0)
                {
                    Console.WriteLine("TPM information found.");
                }
                else
                {
                    Console.WriteLine("No TPM found on this device.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception2: " + ex.Message);
                Console.WriteLine("Stack Trace2: " + ex.StackTrace);
            }
        }
        //these are the functions that are used to get the TPM information
        // Define the necessary P/Invoke signatures
        [DllImport("Tbs.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern uint Tbsi_Context_Create(ref TBS_CONTEXT_PARAMS contextParams, out IntPtr context);

        [DllImport("Tbs.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern uint Tbsi_GetDeviceInfo(IntPtr context, ref TBS_DEVICE_INFO deviceInfo);

        [DllImport("Tbs.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern uint Tbsip_Submit_Command(IntPtr context, uint locality, uint priority, byte[] command, uint commandSize, byte[] result, ref uint resultSize);

        [DllImport("Tbs.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern void Tbsip_Context_Close(IntPtr context);

        // Define the necessary structures
        [StructLayout(LayoutKind.Sequential)]
        public struct TBS_CONTEXT_PARAMS
        {
            public uint version;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TBS_DEVICE_INFO
        {
            public uint structVersion;
            public uint tpmVersion;
            public uint tpmInterfaceType;
            public uint tpmImpRevision;
        }

        // this method is not working but it has the correct implementation
        public void getTPMInfo1()
        {
            IntPtr context = IntPtr.Zero;
            try
            {
                // Create a TBS context
                TBS_CONTEXT_PARAMS contextParams = new TBS_CONTEXT_PARAMS { version = 1 };
                uint result = Tbsi_Context_Create(ref contextParams, out context);
                bool P = false;
                if (result == 0)
                {
                    Console.WriteLine("Successfully create TBS context. Error code: " + result);
                    P = true;
                    
                }
                else if(result == 2150121474)
                {
                    Console.WriteLine("One or more parameter values are not valid. Error code: " + result);
                }
                else if (result == 2150121473)
                {
                    Console.WriteLine("An internal software error occurred.. Error code: " + result);
                }
                else if (result == 2150121479)
                {
                    Console.WriteLine("A context parameter that is not valid was passed when attempting to create a TBS context.. Error code: " + result);
                }
                else if (result == 2150121475)
                {
                    Console.WriteLine("A specified output pointer is not valid. Error code: " + result);
                }
                else if (result == 2150121488)
                {
                    Console.WriteLine("The TBS service is not running and could not be started. Error code: " + result);
                }
                else if (result == 2150121483)
                {
                    Console.WriteLine("The TBS service has been started but is not yet running. Error code: " + result);
                }
                else if (result == 2150121481)
                {
                    Console.WriteLine("A new context could not be created because there are too many open contexts. Error code: " + result);
                }
                else if (result == 2150121487)
                {
                    Console.WriteLine("A compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer. Error code: " + result);
                }
                else 
                {
                    Console.WriteLine("An unknown error.. Error code: " + result);
                }
                if (!P)
                {
                    return;
                }

                // Get TPM device info
                TBS_DEVICE_INFO deviceInfo = new TBS_DEVICE_INFO { structVersion = 1 };
                result = Tbsi_GetDeviceInfo(context, ref deviceInfo);
                if (result != 0)
                {
                    Console.WriteLine("Failed to get TPM device info. Error code: " + result);
                    return;
                }

                // Prepare the command to get the EK public key
                byte[] command = new byte[] { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7A, 0x00, 0x00 };
                byte[] resultBuffer = new byte[4096];
                uint resultSize = (uint)resultBuffer.Length;

                // Submit the command
                result = Tbsip_Submit_Command(context, 0, 1, command, (uint)command.Length, resultBuffer, ref resultSize);
                if (result != 0)
                {
                    Console.WriteLine("Failed to submit command to TPM. Error code: " + result);
                    return;
                }

                // Print the EK public key
                Console.WriteLine("Endorsement Key (EK) Public Key:");
                for (int i = 0; i < resultSize; i++)
                {
                    Console.Write(resultBuffer[i].ToString("X2") + " ");
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error retrieving TPM information: " + ex.Message);
            }
            finally
            {
                // Clean up
                if (context != IntPtr.Zero)
                {
                    Tbsip_Context_Close(context);
                }
            }
        }
        //##################     WORKS      ###################
        public void getTPMInfo01()
        {
            try
            {
                // Initialize the management object searcher for the Win32_Tpm class
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\cimv2\\Security\\MicrosoftTpm", "SELECT * FROM Win32_Tpm");

                foreach (ManagementObject tpm in searcher.Get())
                {
                    // Retrieve and print all properties
                    Console.WriteLine("TPM Properties:");
                    foreach (PropertyData property in tpm.Properties)
                    {
                        Console.WriteLine($"{property.Name}: {property.Value}");
                    }

                    // Retrieve and print the Endorsement Key (EK) data
                    var ekCertificate = tpm["EndorsementKeyCertificate"]?.ToString();
                    if (!string.IsNullOrEmpty(ekCertificate))
                    {
                        Console.WriteLine("Endorsement Key Certificate: " + ekCertificate);
                    }
                    else
                    {
                        Console.WriteLine("Endorsement Key Certificate not found.");
                    }

                    // Retrieve and print the Endorsement Key (EK) data if available
                    var ekPublicKey = tpm["EndorsementKey"]?.ToString();
                    if (!string.IsNullOrEmpty(ekPublicKey))
                    {
                        Console.WriteLine("Endorsement Key: " + ekPublicKey);
                    }
                    else
                    {
                        Console.WriteLine("Endorsement Key not found.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error retrieving TPM information: " + ex.Message);
            }
        }


        private const int TBS_SUCCESS = 0;

        /*
        [DllImport("tbs.dll", SetLastError = true)]
        public static extern int Tbsi_Is_Tpm_Present(out int present);
        [DllImport("tbs.dll", SetLastError = true)]
        private static extern int Tbsi_Context_Create(uint version, out IntPtr context);
        
        [DllImport("tbs.dll", SetLastError = true)]
        public static extern int Tbsi_GetDeviceInfo(out TBS_DEVICE_INFO deviceInfo);

        [DllImport("tbs.dll", SetLastError = true)]
        private static extern int Tbsip_GetTPMProperties(IntPtr context, out IntPtr properties);

        [DllImport("tbs.dll", SetLastError = true)]
        private static extern void Tbsip_FreeTPMProperties(IntPtr properties);

        [DllImport("tbs.dll", SetLastError = true)]
        private static extern int Tbsip_CloseContext(IntPtr context);
        [StructLayout(LayoutKind.Sequential)]
        public struct TBS_DEVICE_INFO
        {
            public uint dwSize;
            public uint dwProtocolVersion;
            public uint dwTpmVersion;
            public uint dwManufacturerID;
            public uint dwManufacturerVersion;
            public uint dwTpmType;
            // Add other fields as necessary
        }
        */
        // Structure to hold TPM properties
        [StructLayout(LayoutKind.Sequential)]
        public struct TBS_TPM_PROPERTIES
        {
            public uint dwSize;
            public uint dwVersion;
            public uint dwManufacturerID;
            public uint dwManufacturerVersion;
            public uint dwSpecVersion;
            public uint dwFirmwareVersion;
            public uint dwTPMType;
        }
        //write function equivalent to the powershell command get-tpm

        public void getTPMInfo2()
        {
            IntPtr context = IntPtr.Zero;
            IntPtr propertiesPtr = IntPtr.Zero;
            /*
            int present;
        int result = Tbsi_Is_Tpm_Present(out present);
        if (result == TBS_SUCCESS)
        {
            Console.WriteLine("TPM is present."+present);
        }
        else
        {
                // Even though this shows TPM is not present powershell command get-tpm returns the TPM information

            Console.WriteLine("TPM is not present."+present);
        }
        TBS_DEVICE_INFO deviceInfo = new TBS_DEVICE_INFO();
        deviceInfo.dwSize = (uint)Marshal.SizeOf(typeof(TBS_DEVICE_INFO)); // Set the size of the structure

        // Call the Tbsi_GetDeviceInfo function
        result = Tbsi_GetDeviceInfo(out deviceInfo);
        // Create a TBS context
        //result = Tbsi_Context_Create(1, out context);
        if (result == TBS_SUCCESS)
        {
            Console.WriteLine("getdevice successfully."+deviceInfo);
            // Get TPM properties
            result = Tbsip_GetTPMProperties(context, out propertiesPtr);
            if (result == TBS_SUCCESS)
            {
                TBS_TPM_PROPERTIES tpmProperties = Marshal.PtrToStructure<TBS_TPM_PROPERTIES>(propertiesPtr);
                Console.WriteLine($"TPM Manufacturer ID: {tpmProperties.dwManufacturerID}");
                Console.WriteLine($"TPM Manufacturer Version: {tpmProperties.dwManufacturerVersion}");
                Console.WriteLine($"TPM Spec Version: {tpmProperties.dwSpecVersion}");
                Console.WriteLine($"TPM Firmware Version: {tpmProperties.dwFirmwareVersion}");
                Console.WriteLine($"TPM Type: {tpmProperties.dwTPMType}");

                // Free the TPM properties structure
                Tbsip_FreeTPMProperties(propertiesPtr);
            }
            else
            {
                Console.WriteLine($"Failed to get TPM properties. Error code: {result}");
            }

            // Close the TBS context
            Tbsip_CloseContext(context);
        }
        else
        {
            Console.WriteLine($"Failed to create TBS context. Error code: {result}");
        }
            */
        }
    
        public void gettpminfo3()
        {
            try
            {
                // Check if TPM is present
                /*
                if (CryptographicEngine.IsTpmPresent())
                {
                    Console.WriteLine("TPM is present.");
                    // Here you can add more detailed TPM interactions or checks
                }
                else
                {
                    Console.WriteLine("TPM is not present.");
                }
                */
                // You can access more TPM-related functionalities if needed
                // Note: More detailed interactions may require deeper access to TPM APIs
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }

}
