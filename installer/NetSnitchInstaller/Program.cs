using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Windows;
using Microsoft.Win32;

namespace NetSnitchInstaller;

public static class Program
{
    private const string AppName = "NetSnitch Combine";
    private const string AppVersion = "1.1.0";
    private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\NetSnitchCombine";

    [STAThread]
    public static void Main(string[] args)
    {
        bool silent = args.Any(a => a.Equals("/S", StringComparison.OrdinalIgnoreCase) ||
                                    a.Equals("--silent", StringComparison.OrdinalIgnoreCase));
        bool uninstall = args.Any(a => a.Equals("--uninstall", StringComparison.OrdinalIgnoreCase));

        string installDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs", "NetSnitch");

        if (uninstall)
        {
            RunUninstall(installDir, silent);
            return;
        }

        if (!silent)
        {
            var confirm = MessageBox.Show(
                $"Установить {AppName} v{AppVersion}?\n\nПапка установки:\n{installDir}\n\nБудут созданы ярлыки на рабочем столе и в меню «Пуск».",
                $"Установка {AppName}",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;
        }

        try
        {
            // Close running instance if any
            foreach (var p in Process.GetProcessesByName("NetSnitch"))
            {
                try { p.Kill(); p.WaitForExit(2000); } catch { }
            }

            Directory.CreateDirectory(installDir);

            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("NetSnitchInstaller.payload.zip")
                ?? throw new InvalidOperationException("Встроенный архив payload.zip не найден.");

            string tempZip = Path.Combine(Path.GetTempPath(), $"netsnitch_payload_{Environment.ProcessId}.zip");
            using (var fs = File.Create(tempZip))
                stream.CopyTo(fs);

            ZipFile.ExtractToDirectory(tempZip, installDir, overwriteFiles: true);
            File.Delete(tempZip);

            // Copy self as uninstaller
            string selfExe = Process.GetCurrentProcess().MainModule?.FileName ?? "";
            string uninstallerPath = Path.Combine(installDir, "Uninstall.exe");
            if (File.Exists(selfExe))
                File.Copy(selfExe, uninstallerPath, overwrite: true);

            string exePath = Path.Combine(installDir, "NetSnitch.exe");
            CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), $"{AppName}.lnk"), exePath, installDir);

            string startMenuDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), AppName);
            Directory.CreateDirectory(startMenuDir);
            CreateShortcut(Path.Combine(startMenuDir, $"{AppName}.lnk"), exePath, installDir);
            CreateShortcut(Path.Combine(startMenuDir, $"Удалить {AppName}.lnk"), uninstallerPath, installDir, "--uninstall");

            using (var key = Registry.CurrentUser.CreateSubKey(UninstallKey))
            {
                key.SetValue("DisplayName", AppName);
                key.SetValue("DisplayVersion", AppVersion);
                key.SetValue("Publisher", "zloyBarsuk12");
                key.SetValue("InstallLocation", installDir);
                key.SetValue("DisplayIcon", exePath);
                key.SetValue("UninstallString", $"\"{uninstallerPath}\" --uninstall");
                key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }

            if (!silent)
            {
                var launch = MessageBox.Show(
                    $"{AppName} успешно установлен!\n\nЗапустить приложение сейчас?",
                    "Установка завершена",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);
                if (launch == MessageBoxResult.Yes && File.Exists(exePath))
                    Process.Start(new ProcessStartInfo(exePath) { UseShellExecute = true });
            }
        }
        catch (Exception ex)
        {
            if (!silent)
                MessageBox.Show($"Ошибка установки: {ex.Message}", AppName, MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static void RunUninstall(string installDir, bool silent)
    {
        if (!silent)
        {
            var confirm = MessageBox.Show($"Удалить {AppName} с компьютера?", $"Удаление {AppName}",
                MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;
        }

        foreach (var p in Process.GetProcessesByName("NetSnitch"))
        {
            try { p.Kill(); p.WaitForExit(2000); } catch { }
        }

        try { Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false); } catch { }
        try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), $"{AppName}.lnk")); } catch { }
        try
        {
            string startMenuDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), AppName);
            if (Directory.Exists(startMenuDir)) Directory.Delete(startMenuDir, true);
        }
        catch { }

        // Self-delete install directory via hidden PowerShell after exit
        string ps = $"Start-Sleep -Milliseconds 700; Remove-Item -LiteralPath '{installDir}' -Recurse -Force -ErrorAction SilentlyContinue";
        Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -WindowStyle Hidden -Command \"{ps}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false
        });

        if (!silent)
            MessageBox.Show($"{AppName} удалён.", AppName, MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string workDir, string args = "")
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null) return;
        dynamic? shell = Activator.CreateInstance(shellType);
        if (shell == null) return;
        dynamic shortcut = shell.CreateShortcut(shortcutPath);
        shortcut.TargetPath = targetPath;
        shortcut.WorkingDirectory = workDir;
        shortcut.Arguments = args;
        shortcut.Save();
    }
}
