using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management; // For WMI queries

namespace FtpmPOC2
{
    public sealed class TpmChecker
    {
        public bool IsTpmPresent()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Tpm"))
                {
                    foreach (var tpm in searcher.Get())
                    {
                        return true; // TPM is present
                    }
                }
            }
            catch (Exception)
            {
                // Handle exceptions if needed
            }
            return false; // TPM is not present
        }
    }
}
