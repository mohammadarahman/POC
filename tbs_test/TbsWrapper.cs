using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace tbs_test
{

    [StructLayout(LayoutKind.Sequential)]
    public struct TBS_DEVICE_INFO
    {
        public uint structVersion;
        public uint tpmVersion;
        public uint tpmInterfaceType;
        public uint tpmImpRevision;
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
        // Define the necessary structures
        

        public struct TBS_CONTEXT_PARAMS2
        {
            public uint version;         // Version of the context parameters
            public uint asUINT32;        // Raw access to the union
            public bool requestRaw;      // Flag to request raw data
            public bool includeTpm12;    // Flag to include TPM 1.2 support
            public bool includeTpm20;    // Flag to include TPM 2.0 support
        }


        // Struct to represent TPM properties
        //[StructLayout(LayoutKind.Sequential)]
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

        public enum TBS_AUTH_TYPE : uint
        {
            LOCKOUT = 1,        // TBS_OWNERAUTH_TYPE_FULL
            ENDORSEMENT = 12,   // TBS_OWNERAUTH_TYPE_ENDORSEMENT_20
            OWNER = 13          // TBS_OWNERAUTH_TYPE_STORAGE_20
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

    } // class TbsWrapper
    internal class CommandModifier
    {
        internal byte ActiveLocality = 0;
        internal TbsWrapper.TBS_COMMAND_PRIORITY ActivePriority = TbsWrapper.TBS_COMMAND_PRIORITY.NORMAL;
    }

}
