using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

namespace ProtonMail.Srp
{
    public static class Srp
    {
        /// <summary>
        /// Go related part.
        /// </summary>
        static Srp()
        {
            Environment.SetEnvironmentVariable("GODEBUG", "cgocheck=0"); //must have and must be the first call
        }
        // attention to length of 32bit and 64bit. the golib we only use 32 bit so it should be ok.
        // when changed to 64bit those objects are the tricky part.
        public struct GoString
        {
            public IntPtr p;
            public int n;

            public void Free()
            {
                Marshal.FreeHGlobal(p);
            }
        }

        public struct GoSlice
        {
            public IntPtr data;
            public int len;
            public int cap;
        }

        public static string ConvertToString(this GoString goStr)
        {
            // becarefull the encoding. use utf8 for now but maybe ascii better
            byte[] bytes = new byte[goStr.n];
            for (int i = 0; i < goStr.n; i++)
                bytes[i] = Marshal.ReadByte(goStr.p, i);
            string s = Encoding.UTF8.GetString(bytes);
            return s;
        }

        public static byte[] ConvertToBytes(this GoSlice goBytes)
        {
            byte[] bytes = new byte[goBytes.len];
            for (int i = 0; i < goBytes.len; i++)
                bytes[i] = Marshal.ReadByte(goBytes.data, i);
            return bytes;
        }

        public static GoString ToGoString(this string str)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(str); // not null terminated
            //Array.Resize(ref buffer, buffer.Length + 1);
            //buffer[buffer.Length - 1] = 0; // terminating 0
            IntPtr nativeUtf8 = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, nativeUtf8, buffer.Length);
            GoString goStr = new GoString
            {
                p = nativeUtf8,
                n = buffer.Length
            };
            return goStr;
        }

        public static GoSlice ToGoSlice(this byte[] buffer)
        {
            IntPtr nativeUtf8 = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, nativeUtf8, buffer.Length);
            GoSlice goSlice = new GoSlice
            {
                data = nativeUtf8,
                len = buffer.Length,
                cap = buffer.Length
                
            };
            return goSlice;
        }

        public class GoProofs
        {
            public byte[] ClientProof;
            public byte[] ClientEphemeral;
            public byte[] ExpectedServerProof;
        }

        public static string GetModulusKey()
        {
            return NativeGetModulusKey().ConvertToString();
        }

        public static GoProofs GenerateProofs(int version, string username, string password, string salt, string signedModulus, string serverEphemeral, int bitLength = 2048)
        {
            GoString goUsername = username.ToGoString();
            GoString goPassword = password.ToGoString();
            GoString goSalt = salt.ToGoString();
            GoString goModulus = signedModulus.ToGoString();
            GoString goEphemeral = serverEphemeral.ToGoString();
            GoSlice outBytes = NativeGenerateProofs(version, goUsername, goPassword, goSalt, goModulus, goEphemeral, bitLength);
            byte[] bytes = outBytes.ConvertToBytes();
            using (MemoryStream memStream = new MemoryStream(bytes))
            {
                BinaryReader reader = new BinaryReader(memStream);
                byte v = reader.ReadByte();
                byte type = reader.ReadByte();

                if (type == 0)
                {
                    UInt16 size = reader.ReadUInt16();
                    byte[] bmsg = reader.ReadBytes(size);
                    string result = Encoding.UTF8.GetString(bmsg);
                    throw new Exception("go-srp: " + result);
                }
                else if (type == 1)
                {
                    UInt16 size = reader.ReadUInt16();
                    byte[] clientProof = reader.ReadBytes(size);
                    size = reader.ReadUInt16();
                    byte[] clientEphemeral = reader.ReadBytes(size);
                    size = reader.ReadUInt16();
                    byte[] expectedServerProof = reader.ReadBytes(size);

                    GoProofs proofs = new GoProofs
                    {
                        ClientProof = clientProof,
                        ClientEphemeral = clientEphemeral,
                        ExpectedServerProof = expectedServerProof
                    };
                    return proofs;

                }
            }

            return null;
        }



        public static byte[] GenerateVerifier( string password, string signedModulus, byte[] rawSalt, int bitLength = 2048)
        {
            GoString goPassword = password.ToGoString();
            GoString goSignedModulus = signedModulus.ToGoString();
            GoSlice goRawSalt = rawSalt.ToGoSlice();
            GoSlice outBytes = NativeGenerateVerifier(goPassword, goSignedModulus, goRawSalt, bitLength);
            byte[] bytes = outBytes.ConvertToBytes();
            using (MemoryStream memStream = new MemoryStream(bytes))
            {
                BinaryReader reader = new BinaryReader(memStream);
                byte v = reader.ReadByte();
                byte type = reader.ReadByte();

                if (type == 0)
                {
                    UInt16 size = reader.ReadUInt16();
                    byte[] bmsg = reader.ReadBytes(size);
                    string result = Encoding.UTF8.GetString(bmsg);
                    throw new Exception("go-srp: " + result);
                }
                else if (type == 1)
                {
                    UInt16 size = reader.ReadUInt16();
                    byte[] verifier = reader.ReadBytes(size);
                    return verifier;
                }

                return null;
            }
        }

        //
        [DllImport("GoSrp", EntryPoint = "GenerateProofs", CallingConvention = CallingConvention.Cdecl)]
        private static extern GoSlice NativeGenerateProofs(int version, GoString username, GoString password, GoString salt, GoString signedModulus, GoString serverEphemeral, int bits);
        //
        [DllImport("GoSrp", EntryPoint = "GenerateVerifier", CallingConvention = CallingConvention.Cdecl)]
        private static extern GoSlice NativeGenerateVerifier(GoString password, GoString signedModulus, GoSlice rawSalt, int bits);
        //
        [DllImport("GoSrp", EntryPoint = "GetModulusKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern GoString NativeGetModulusKey();

        //
        [DllImport("GoSrp", EntryPoint = "SetTest", CallingConvention = CallingConvention.Cdecl)]
        public static extern void SetUnitTest();
    }
}