using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using System;
using System.Linq;


//using tbs_test;
namespace tbs_test
{

    class Program
    {
        // Define constants
        private const int TBS_SUCCESS = 0;
        private static byte[] command;
        private static uint commandSize = 0;
        private static int[] x;
        static void Main()
        {
            readconfigxml();
            ExecuteCommandToTPM();
        }

        private static void readconfigxml()
        {
            XDocument config = XDocument.Load("config.xml");
            commandSize = uint.Parse(config.Root.Element("commandSize").Value);
            command = config.Root.Element("command").Value
                                        .Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                                        .Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber))
                                        .ToArray();
            int[] xarr = config.Root.Element("XArray").Value
                   .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                   .Select(s => int.Parse(s.Trim()))
                   .ToArray();
            x = new int[50];
            int sum = 0; 
            for(int i =0; i < 50; i++)
            {
                if(i < xarr.Length)
                {
                    sum += xarr[i];
                }
                else
                {
                    sum += 4;
                }
                x[i] = sum;
            }
        }

        private static void ExecuteCommandToTPM()
        {
           
            // Step 1: Create a TBS context
            TbsWrapper.TBS_CONTEXT_PARAMS contextParams;
            contextParams.Version = TbsWrapper.TBS_CONTEXT_VERSION.TWO;
            contextParams.Flags = TbsWrapper.TBS_CONTEXT_CREATE_FLAGS.IncludeTpm20;
            UIntPtr tbsContext = UIntPtr.Zero;
            TbsWrapper.TBS_RESULT result = TbsWrapper.NativeMethods
                                    .Tbsi_Context_Create(ref contextParams, ref tbsContext);

            if (result != TBS_SUCCESS)
            {
                Console.WriteLine("Failed to create TBS context. Error code: " + result);
                return;
            }

            try
            {
                // Step 2: Get TPM device info (this step might be for debugging or verification)
                TBS_DEVICE_INFO deviceInfo = new TBS_DEVICE_INFO();
                result = TbsWrapper.NativeMethods.Tbsi_GetDeviceInfo(tbsContext, ref deviceInfo);
                if (result == TBS_SUCCESS)
                {
                    Console.WriteLine($"TPM Version: {deviceInfo.tpmVersion}");
                    Console.WriteLine($"TPM Interface Type: {deviceInfo.tpmInterfaceType}");
                    Console.WriteLine($"TPM Revision: {deviceInfo.tpmImpRevision}");
                }
                else
                {
                    Console.WriteLine("Failed to get device info. Error code: " + result);
                    return;
                }

                // Step 3: Retrieve Endorsement Key Info
                // This usually involves submitting a TPM command and receiving the EK data
                // Here we assume that the TPM is responsive and provide a basic setup for the command

                byte[] resultBuffer = new byte[512]; // Buffer to store the result
                uint resultSize = (uint)resultBuffer.Length;
                CommandModifier active = new CommandModifier();
                byte[] commandSizeBytes = BitConverter.GetBytes(commandSize);
                //byte[] command = ConstructTpmReadPublicCommand(tbsContext);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(commandSizeBytes);
                }
                // Copy the commandSizeBytes to the command array starting at position 2
                Array.Copy(commandSizeBytes, 0, command, 2, 4);
                //working command
                /*
                var command = new byte[]{
                            0x80, 0x01,             // TPM_ST_NO_SESSIONS
                            0, 0, 0, 0x0C,          // length 12 here
                            0, 0, 0x01, 0x7B,       // TPM_CC_GetRandom
                            0, 0x08                 // Command parameter - num random bytes to generate
                    };
                var command = new byte[]{
                            0x80, 0x01,             // TPM_ST_NO_SESSIONS
                            0, 0, 0, 0x0A,          // length 12 here
                            0, 0, 0x01, 0x5A       // TPM_CC_ReadPublic
                                             // Command parameter - num random bytes to generate
                    };
                            uint commandSize = 22;
                var command = new byte[]{
                    0x80, 0x01,             // TPM_ST_NO_SESSIONS
                    0, 0, 0, 0,             // Placeholder for length
                    0, 0, 0x01, 0x7A,       // TPM_CC_GetCapability
                    0, 0,0,0x01,                 // Command parameter - num random bytes to generate
                    0x01, 0x0C, 0, 0x02,          
                    0, 0, 0x00, 0xFF       
                };
                */
                result = TbsWrapper.NativeMethods.Tbsip_Submit_Command(tbsContext, (TbsWrapper.TBS_COMMAND_LOCALITY)active.ActiveLocality, active.ActivePriority, command, (uint)command.Length, resultBuffer, ref resultSize);

                byte[] newBuffer = new byte[resultSize];
                Array.Copy(resultBuffer, newBuffer, resultSize);
                if (result == TBS_SUCCESS)
                {
                    //int[] x = { 2, 6, 10,14,15,19,23,27,31,35,39,43,47 };
                    //Console.WriteLine("Result size: " + resultSize);
                    Console.WriteLine("Command:\n" + BitConverter.ToString(command));
                    Console.WriteLine("Result size: " + resultSize);
                    for(int i = 0; i < resultSize; i++)
                    {
                        if(x.Contains(i))
                        {
                            Console.Write("\n");
                        }
                        Console.Write(newBuffer[i].ToString("X2") + " ");
                    }
                    //Console.WriteLine("Result:\n" + BitConverter.ToString(newBuffer));

                    //Console.WriteLine("Endorsement Key (EK) information retrieved successfully.");
                    // Optionally, process the resultBuffer to extract the EK
                }
                else
                {
                    Console.WriteLine("Failed to submit command. Error code: " + result);
                }
            }
            finally
            {
                // Clean up by closing the context
                TbsWrapper.NativeMethods.Tbsip_Context_Close(tbsContext);
            }
        }
        /*
        public static byte[] ConstructTpmReadPublicCommand(nuint ekHandle)
        {
            // TPM2 command header
            byte[] command = new byte[4];  // Minimal size for the ReadPublic command (adjust as needed)
            int offset = 0;

            // TPM2 Command Code: TPM2_CC_ReadPublic (0x0000015A)
            BitConverter.GetBytes(0x0000015A).CopyTo(command, offset);  // Command code
            offset += 4;

            // TPM Handle (EK handle, 4 bytes)
            //BitConverter.GetBytes(0x00000001).CopyTo(command, offset);  // Handle of the EK key
            //offset += 4;

            return command;
        }
        */

    }

}
