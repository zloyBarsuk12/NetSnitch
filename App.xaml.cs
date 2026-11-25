using System.Windows;

namespace NetSnitch;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show($"Ошибка приложения: {args.Exception.Message}", "NetSnitch",
                MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
    }
}
