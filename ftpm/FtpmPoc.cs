using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Xml.Schema;
using System.Security.Cryptography;

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
                // Create a searcher to find the BIOS information
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Tpm");


                // Alternative way to get the TPM information using the Get-WmiObject cmdlet in PowerShell
                // Get-WmiObject -Namespace "Root\CIMv2" -Class Win32_Tpm

                foreach (ManagementObject tpm in searcher.Get())
                {
                    if (tpm != null)
                    {
                        // Get the Manufacturer ID
                        string manufacturerId = tpm["ManufacturerID"]?.ToString();
                        // Get the Spec Version
                        string specVersion = tpm["SpecVersion"]?.ToString();
                        // Get the Firmware Version
                        string firmwareVersion = tpm["FirmwareVersion"]?.ToString();

                        Console.WriteLine($"TPM Manufacturer ID: {manufacturerId}");
                        Console.WriteLine($"TPM Spec Version: {specVersion}");
                        Console.WriteLine($"TPM Firmware Version: {firmwareVersion}");
                    }
                    else
                    {
                        Console.WriteLine("No TPM found on this device.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred to find: " + ex.Message);
            }
        }


        //these are the functions that are used to get the TPM information
        // TBS return codes
        private const int TBS_SUCCESS = 0;

        /*
        [DllImport("tbs.dll", SetLastError = true)]
        private static extern int Tbsi_Context_Create(uint version, out IntPtr context);
        [DllImport("tbs.dll", SetLastError = true)]

        public static extern int Tbsi_Is_Tpm_Present(out int present);

        [DllImport("tbs.dll", SetLastError = true)]
        public static extern int Tbsi_GetDeviceInfo(out TBS_DEVICE_INFO deviceInfo);

        [DllImport("tbs.dll", SetLastError = true)]
        private static extern int Tbsip_GetTPMProperties(IntPtr context, out IntPtr properties);

        [DllImport("tbs.dll", SetLastError = true)]
        private static extern void Tbsip_FreeTPMProperties(IntPtr properties);

        [DllImport("tbs.dll", SetLastError = true)]
        private static extern int Tbsip_CloseContext(IntPtr context);
        */
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
        public void getTPMInfo2()
        {
            IntPtr context = IntPtr.Zero;
            IntPtr propertiesPtr = IntPtr.Zero;
            int present;
            /*
        int result = Tbsi_Is_Tpm_Present(out present);
        if (result == TBS_SUCCESS)
        {
            Console.WriteLine("TPM is present."+present);
        }
        else
        {
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
