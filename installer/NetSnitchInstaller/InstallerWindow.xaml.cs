using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Windows;
using Microsoft.Win32;

namespace NetSnitchInstaller;

public partial class InstallerWindow : Window
{
    private readonly bool _isUninstall;
    private bool _finished;

    public InstallerWindow(bool isUninstall = false)
    {
        InitializeComponent();
        _isUninstall = isUninstall;
        InstallPathBox.Text = InstallerLogic.DefaultInstallDir;

        if (_isUninstall)
        {
            Title = "Удаление NetSnitch Combine";
            SubtitleText.Text = "Удаление приложения с компьютера";
            InstallOptionsPanel.Visibility = Visibility.Collapsed;
            StatusText.Text = "Нажмите «Удалить», чтобы удалить NetSnitch Combine и его ярлыки.";
            ActionBtn.Content = "Удалить";
            ActionBtn.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 38, 38));
        }
    }

    private void BrowseBtn_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Выберите папку для установки NetSnitch Combine",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        };
        if (dlg.ShowDialog() == true)
            InstallPathBox.Text = Path.Combine(dlg.FolderName, "NetSnitch");
    }

    private void CancelBtn_Click(object sender, RoutedEventArgs e) => Close();

    private async void ActionBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_finished)
        {
            Close();
            return;
        }

        ActionBtn.IsEnabled = false;
        CancelBtn.IsEnabled = false;
        BrowseBtn.IsEnabled = false;

        if (_isUninstall)
        {
            StatusText.Text = "Удаление файлов и ярлыков...";
            InstallProgress.Value = 50;
            await Task.Run(() => InstallerLogic.Uninstall(InstallPathBox.Text.Trim(), silent: false));
            InstallProgress.Value = 100;
            StatusText.Text = "NetSnitch Combine удалён.";
            _finished = true;
            ActionBtn.Content = "Готово";
            ActionBtn.IsEnabled = true;
            return;
        }

        string targetDir = InstallPathBox.Text.Trim();
        bool desktop = DesktopShortcutCheck.IsChecked == true;
        bool startMenu = StartMenuShortcutCheck.IsChecked == true;
        bool launch = LaunchAfterCheck.IsChecked == true;

        try
        {
            await InstallerLogic.InstallAsync(targetDir, desktop, startMenu, launch, (pct, msg) =>
            {
                Dispatcher.Invoke(() =>
                {
                    InstallProgress.Value = pct;
                    StatusText.Text = msg;
                });
            });

            _finished = true;
            ActionBtn.Content = "Готово";
            ActionBtn.IsEnabled = true;
            if (launch) Close();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Ошибка: {ex.Message}";
            ActionBtn.IsEnabled = true;
            CancelBtn.IsEnabled = true;
            BrowseBtn.IsEnabled = true;
        }
    }
}

public static class InstallerLogic
{
    private const string AppName = "NetSnitch Combine";
    private const string AppVersion = "1.1.1";
    private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\NetSnitchCombine";

    public static string DefaultInstallDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Programs", "NetSnitch");

    public static async Task InstallAsync(
        string installDir,
        bool createDesktopShortcut,
        bool createStartMenuShortcut,
        bool launchAfter,
        Action<int, string>? progress)
    {
        await Task.Run(() =>
        {
            progress?.Invoke(10, "Закрытие запущенных процессов...");
            foreach (var p in Process.GetProcessesByName("NetSnitch"))
            {
                try { p.Kill(); p.WaitForExit(2000); } catch { }
            }

            Directory.CreateDirectory(installDir);

            progress?.Invoke(30, "Распаковка файлов приложения...");
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("NetSnitchInstaller.payload.zip")
                ?? throw new InvalidOperationException("Встроенный архив payload.zip не найден.");

            string tempZip = Path.Combine(Path.GetTempPath(), $"netsnitch_payload_{Environment.ProcessId}.zip");
            using (var fs = File.Create(tempZip))
                stream.CopyTo(fs);

            ZipFile.ExtractToDirectory(tempZip, installDir, overwriteFiles: true);
            File.Delete(tempZip);

            // Save standalone icon file in install dir for shortcut icons
            string icoFile = Path.Combine(installDir, "NetSnitch.ico");
            var icoInfo = Application.GetResourceStream(new Uri("pack://application:,,,/NetSnitch.ico"));
            if (icoInfo != null)
            {
                using var icoOut = File.Create(icoFile);
                icoInfo.Stream.CopyTo(icoOut);
            }

            progress?.Invoke(65, "Копирование деинсталлятора...");
            string selfExe = Process.GetCurrentProcess().MainModule?.FileName ?? "";
            string uninstallerPath = Path.Combine(installDir, "Uninstall.exe");
            if (File.Exists(selfExe))
                File.Copy(selfExe, uninstallerPath, overwrite: true);

            string exePath = Path.Combine(installDir, "NetSnitch.exe");
            string iconLoc = File.Exists(icoFile) ? $"{icoFile},0" : $"{exePath},0";

            progress?.Invoke(80, "Создание ярлыков...");
            if (createDesktopShortcut)
            {
                CreateShortcut(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), $"{AppName}.lnk"),
                    exePath, installDir, iconLoc);
            }

            if (createStartMenuShortcut)
            {
                string startMenuDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), AppName);
                Directory.CreateDirectory(startMenuDir);
                CreateShortcut(Path.Combine(startMenuDir, $"{AppName}.lnk"), exePath, installDir, iconLoc);
                CreateShortcut(Path.Combine(startMenuDir, $"Удалить {AppName}.lnk"), uninstallerPath, installDir, iconLoc, "--uninstall");
            }

            progress?.Invoke(92, "Регистрация в Windows...");
            using (var key = Registry.CurrentUser.CreateSubKey(UninstallKey))
            {
                key.SetValue("DisplayName", AppName);
                key.SetValue("DisplayVersion", AppVersion);
                key.SetValue("Publisher", "zloyBarsuk12");
                key.SetValue("InstallLocation", installDir);
                key.SetValue("DisplayIcon", File.Exists(icoFile) ? icoFile : exePath);
                key.SetValue("UninstallString", $"\"{uninstallerPath}\" --uninstall");
                key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }

            progress?.Invoke(100, "Установка успешно завершена!");
            if (launchAfter && File.Exists(exePath))
                Process.Start(new ProcessStartInfo(exePath) { UseShellExecute = true });
        });
    }

    public static void Uninstall(string installDir, bool silent)
    {
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

        string ps = $"Start-Sleep -Milliseconds 700; Remove-Item -LiteralPath '{installDir}' -Recurse -Force -ErrorAction SilentlyContinue";
        Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -WindowStyle Hidden -Command \"{ps}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false
        });
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string workDir, string iconLocation, string args = "")
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null) return;
        dynamic? shell = Activator.CreateInstance(shellType);
        if (shell == null) return;
        dynamic shortcut = shell.CreateShortcut(shortcutPath);
        shortcut.TargetPath = targetPath;
        shortcut.WorkingDirectory = workDir;
        shortcut.IconLocation = iconLocation;
        shortcut.Arguments = args;
        shortcut.Save();
    }
}
