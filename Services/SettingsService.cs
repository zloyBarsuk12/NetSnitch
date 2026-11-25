using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class SettingsService
{
    private static readonly string ConfigDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSnitch");

    private static readonly string ConfigPath = Path.Combine(ConfigDir, "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            }
        }
        catch { }
        return new AppSettings();
    }

    public static void Save(AppSettings settings)
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(ConfigPath, json);
        }
        catch { }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn, string? szDataDescr, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static string ProtectString(string plain)
    {
        if (string.IsNullOrEmpty(plain)) return "";
        byte[] input = Encoding.UTF8.GetBytes(plain);
        DATA_BLOB inBlob = new() { cbData = input.Length, pbData = Marshal.AllocHGlobal(input.Length) };
        DATA_BLOB outBlob = new();
        try
        {
            Marshal.Copy(input, 0, inBlob.pbData, input.Length);
            if (CryptProtectData(ref inBlob, "NetSnitch", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, ref outBlob))
            {
                byte[] output = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, output, 0, outBlob.cbData);
                return Convert.ToBase64String(output);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(inBlob.pbData);
            if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
        }
        return "";
    }

    public static string UnprotectString(string encryptedBase64)
    {
        if (string.IsNullOrEmpty(encryptedBase64)) return "";
        try
        {
            byte[] input = Convert.FromBase64String(encryptedBase64);
            DATA_BLOB inBlob = new() { cbData = input.Length, pbData = Marshal.AllocHGlobal(input.Length) };
            DATA_BLOB outBlob = new();
            try
            {
                Marshal.Copy(input, 0, inBlob.pbData, input.Length);
                if (CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, ref outBlob))
                {
                    byte[] output = new byte[outBlob.cbData];
                    Marshal.Copy(outBlob.pbData, output, 0, outBlob.cbData);
                    return Encoding.UTF8.GetString(output);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(inBlob.pbData);
                if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
            }
        }
        catch { }
        return "";
    }
}
