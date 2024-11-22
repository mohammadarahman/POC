using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using System;
using System.Linq;

using static Program;
public class CommandModifier
{
    public byte ActiveLocality = 0;
    public TBS_COMMAND_PRIORITY ActivePriority = TBS_COMMAND_PRIORITY.NORMAL;
}
[SuppressMessageAttribute("Microsoft.Design", "CA1008:EnumsShouldHaveZeroValue")]
public enum TBS_COMMAND_PRIORITY : uint
{
    LOW = 100,
    NORMAL = 200,
    HIGH = 300,
    SYSTEM = 400,
    MAX = 0x80000000
}

public enum TBS_AUTH_TYPE : uint
{
    LOCKOUT = 1,        // TBS_OWNERAUTH_TYPE_FULL
    ENDORSEMENT = 12,   // TBS_OWNERAUTH_TYPE_ENDORSEMENT_20
    OWNER = 13          // TBS_OWNERAUTH_TYPE_STORAGE_20
}

internal class TbsWrapper
{
    public class NativeMethods
    {
        // Note that code gen adds error code than can be returned by TBS API
        // to the TpmRc enum.

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TBS_RESULT
        Tbsi_Context_Create(
            ref TBS_CONTEXT_PARAMS ContextParams,
            ref UIntPtr Context
        );

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TBS_RESULT
        Tbsi_Get_OwnerAuth(
            UIntPtr hContext,
            uint ownerAuthType,
            [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), Out]
                byte[]                  OutBuf,
            ref uint OutBufLen
            );

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TBS_RESULT
        Tbsip_Context_Close(
            UIntPtr Context
        );

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TBS_RESULT
        Tbsip_Submit_Command(
            UIntPtr Context,
            TBS_COMMAND_LOCALITY Locality,
            TBS_COMMAND_PRIORITY Priority,
            [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4), In]
                byte[]                  InBuffer,
            uint InBufferSize,
            [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6), Out]
                byte[]                  OutBuf,
            ref uint OutBufLen
        );


        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TBS_RESULT
        Tbsi_GetDeviceInfo(
            UIntPtr Context,
            ref TBS_DEVICE_INFO deviceInfo
        );


        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TBS_RESULT
        Tbsip_Cancel_Commands(
            UIntPtr Context
        );

    }

    public enum TBS_RESULT : uint
    {
        SUCCESS = 0,
        OWNERAUTH_NOT_FOUND = 0x80284015,
        BAD_PARAMETER = 0x80284002
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TBS_CONTEXT_PARAMS
    {
        public TBS_CONTEXT_VERSION Version;
        public TBS_CONTEXT_CREATE_FLAGS Flags;
    }

    public enum TBS_COMMAND_LOCALITY : uint
    {
        ZERO = 0,
        ONE = 1,
        TWO = 2,
        THREE = 3,
        FOUR = 4
    }

    public enum TBS_CONTEXT_VERSION : uint
    {
        ONE = 1,
        TWO = 2
    }

    public enum TBS_TPM_VERSION : uint
    {
        Invalid = 0,
        V1_2 = 1,
        V2 = 2
    }

    public enum TBS_CONTEXT_CREATE_FLAGS : uint
    {
        RequestRaw = 0x00000001,
        IncludeTpm12 = 0x00000002,
        IncludeTpm20 = 0x00000004
    }
} // class TbsWrapper

class Program
{
    // Define constants
    private const int TBS_SUCCESS = 0;
    private const int TBS_ERROR = -1;

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
    public struct TBS_CONTEXT_PARAMS2
    {
        public uint version;         // Version of the context parameters
        public uint asUINT32;        // Raw access to the union
        public bool requestRaw;      // Flag to request raw data
        public bool includeTpm12;    // Flag to include TPM 1.2 support
        public bool includeTpm20;    // Flag to include TPM 2.0 support
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct TBS_DEVICE_INFO
    {
        public uint structVersion;
        public uint tpmVersion;
        public uint tpmInterfaceType;
        public uint tpmImpRevision;
    }

    // Struct to represent TPM properties
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

    static void Main()
    {
        GetTpmEndorsementKeyInfo();
    }
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

    private static void GetTpmEndorsementKeyInfo()
    {
        XDocument config = XDocument.Load("config.xml");
        uint commandSize = uint.Parse(config.Root.Element("commandSize").Value);
        //byte[] command = config.Root.Element("command").Value.Split(' ').Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber)).ToArray();
        byte[] command = config.Root.Element("command").Value
    .Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
    .Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber))
    .ToArray();
        TbsWrapper.TBS_CONTEXT_PARAMS contextParams;

        UIntPtr tbsContext = UIntPtr.Zero;
        contextParams.Version = TbsWrapper.TBS_CONTEXT_VERSION.TWO;
        contextParams.Flags = TbsWrapper.TBS_CONTEXT_CREATE_FLAGS.IncludeTpm20;
        TbsWrapper.TBS_RESULT result = TbsWrapper.NativeMethods
                                .Tbsi_Context_Create(ref contextParams, ref tbsContext);



        //IntPtr context = IntPtr.Zero;
        IntPtr propertiesPtr = IntPtr.Zero;
        IntPtr ekInfoPtr = IntPtr.Zero;

        // Step 1: Create a TBS context
        //TBS_CONTEXT_PARAMS contextParams = new TBS_CONTEXT_PARAMS { version = 2};
        //uint result = Tbsi_Context_Create(ref contextParams, out context);
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
            //uint commandSize = 14;
            //var command = new byte[]{
            //    0x80, 0x01,             // TPM_ST_NO_SESSIONS
            //    0, 0, 0, 0,             // Placeholder for length
            //    0, 0, 0x01, 0x9e,       // TPM_CC_GetCapability
            //    0x81,0x00,0x00,0x09
            //    //0,0,0,0x01,             //TPM_CAP_HANDLES               
            //    //0x81,0x00,0x0,0x0,      //property
            //    //0,0,0,0xff                        //property count
            //};
            //BitConverter.GetBytes(commandSize).CopyTo(command, 2); // Set the command size
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
            var command = new byte[] {
                0,0xc0, // command 2 bytes? 
               0,0,0,0x0a,  // lenght (size of the command) 10 here
               0,0,0,0x50
            };
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
                Console.WriteLine("Command executed successfully");
                Console.WriteLine("Result size: " + resultSize);
                Console.WriteLine("Command buffer: " + BitConverter.ToString(command));
                Console.WriteLine("Result buffer: " + BitConverter.ToString(newBuffer));
                //Console.WriteLine("Endorsement Key (EK) information retrieved successfully.");
                // Optionally, process the resultBuffer to extract the EK
            }
            else
            {
                Console.WriteLine("Failed to submit command for EK info. Error code: " + result);
            }
        }
        finally
        {
            // Clean up by closing the context
            TbsWrapper.NativeMethods.Tbsip_Context_Close(tbsContext);
        }
    }
}
