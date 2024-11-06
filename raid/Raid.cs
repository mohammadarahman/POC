using System;
using System.Management;

namespace RAIDDetection
{
    public class Raid
    {
        //static void Main(string[] args)
        // give a list of all the RAID controllers and disk drives
        //suggest a method name that is more descriptive
        public void GetRaidControllersAndDiskDrives()
        {
            try
            {
                // Create a ManagementObjectSearcher to query WMI
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_DiskDrive");

                foreach (ManagementObject queryObj in searcher.Get())
                {
                    Console.WriteLine("Disk Drive: {0}", queryObj["Caption"]);
                    Console.WriteLine("Model: {0}", queryObj["Model"]);
                    Console.WriteLine("InterfaceType: {0}", queryObj["InterfaceType"]);
                    Console.WriteLine("MediaType: {0}", queryObj["MediaType"]);
                    Console.WriteLine("SerialNumber: {0}", queryObj["SerialNumber"]);
                    Console.WriteLine("Partitions: {0}", queryObj["Partitions"]);
                    Console.WriteLine("Size: {0}", queryObj["Size"]);
                    Console.WriteLine();
                }

                // Check for RAID controllers
                searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_IDEController");

                foreach (ManagementObject queryObj in searcher.Get())
                {
                    Console.WriteLine("IDE Controller: {0}", queryObj["Caption"]);
                    Console.WriteLine("Manufacturer: {0}", queryObj["Manufacturer"]);
                    Console.WriteLine();
                }

                searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_SCSIController");

                foreach (ManagementObject queryObj in searcher.Get())
                {
                    Console.WriteLine("SCSI Controller: {0}", queryObj["Caption"]);
                    Console.WriteLine("Manufacturer: {0}", queryObj["Manufacturer"]);
                    Console.WriteLine();
                }
            }
            catch (ManagementException e)
            {
                Console.WriteLine("An error occurred while querying WMI: " + e.Message);
            }
        }
    }
}
