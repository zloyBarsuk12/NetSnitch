using System.Windows;

namespace NetSnitchInstaller;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        bool silent = e.Args.Any(a => a.Equals("/S", StringComparison.OrdinalIgnoreCase) ||
                                      a.Equals("--silent", StringComparison.OrdinalIgnoreCase));
        bool uninstall = e.Args.Any(a => a.Equals("--uninstall", StringComparison.OrdinalIgnoreCase));

        if (silent)
        {
            if (uninstall)
                InstallerLogic.Uninstall(InstallerLogic.DefaultInstallDir, silent: true);
            else
                InstallerLogic.InstallAsync(InstallerLogic.DefaultInstallDir, true, true, false, null).GetAwaiter().GetResult();
            Shutdown();
            return;
        }

        var win = new InstallerWindow(uninstall);
        win.Show();
    }
}
