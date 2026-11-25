using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using Microsoft.Win32;
using NetSnitch.Models;
using NetSnitch.Services;

namespace NetSnitch;

public partial class MainWindow : Window
{
    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
    private readonly TrafficMonitorService _trafficService = new();
    private readonly DispatcherTimer _pollTimer = new();

    private readonly ObservableCollection<ProcessSummary> _processes = [];
    private readonly ObservableCollection<ConnectionEntry> _filteredConnections = [];
    private readonly ObservableCollection<TrafficEventEntry> _events = [];
    private readonly ObservableCollection<DnsLogEntry> _dnsLogs = [];
    private readonly ObservableCollection<MtrHopEntry> _traceHops = [];
    private readonly ObservableCollection<SubnetHostEntry> _subnetHosts = [];
    private readonly List<SubnetHostEntry> _allSubnetHosts = [];
    private readonly ObservableCollection<MacHardwareInfo> _macInventory = [];
    private readonly ObservableCollection<PortScanResult> _portResults = [];
    private readonly ObservableCollection<DigRecordEntry> _digResults = [];
    private readonly ObservableCollection<ListeningPortEntry> _listeningPorts = [];
    private readonly ObservableCollection<MtrHopEntry> _mtrHops = [];
    private readonly ObservableCollection<FirewallRuleEntry> _firewallRules = [];

    private List<ConnectionEntry> _allConnections = [];
    private string? _selectedProcess;
    private AppSettings _settings = new();
    private UpdateCheckResult? _pendingUpdate;

    private CancellationTokenSource? _subnetCts;
    private CancellationTokenSource? _portCts;
    private CancellationTokenSource? _mtrCts;

    public MainWindow()
    {
        InitializeComponent();

        ProcessListBox.ItemsSource = _processes;
        ConnectionsGrid.ItemsSource = _filteredConnections;
        TrafficEventsGrid.ItemsSource = _events;
        DnsLogsGrid.ItemsSource = _dnsLogs;
        TraceGrid.ItemsSource = _traceHops;
        SubnetGrid.ItemsSource = _subnetHosts;
        MacInventoryGrid.ItemsSource = _macInventory;
        PortGrid.ItemsSource = _portResults;
        DigGrid.ItemsSource = _digResults;
        ListeningGrid.ItemsSource = _listeningPorts;
        MtrGrid.ItemsSource = _mtrHops;
        FirewallGrid.ItemsSource = _firewallRules;

        DigTypeCombo.ItemsSource = DigService.RecordTypes;
        DigTypeCombo.SelectedIndex = 0;

        foreach (var cidr in SubnetScannerService.GetLocalSubnets())
            SubnetCidrCombo.Items.Add(cidr);
        if (SubnetCidrCombo.Items.Count > 0)
            SubnetCidrCombo.SelectedIndex = 0;
        else
            SubnetCidrCombo.Text = "192.168.1.0/24";

        LoadSettingsToUi();
        SourceInitialized += (_, _) => ApplyTheme(_settings.Theme);

        _pollTimer.Interval = TimeSpan.FromMilliseconds(Math.Max(500, _settings.PollingIntervalMs));
        _pollTimer.Tick += (_, _) => PollTraffic();
        _pollTimer.Start();
        PollTraffic();

        Loaded += async (_, _) => await RunSilentStartupUpdateCheckAsync();
    }

    private void LoadSettingsToUi()
    {
        _settings = SettingsService.Load();
        SettingOwnerBox.Text = _settings.GitHubOwner;
        SettingRepoBox.Text = _settings.GitHubRepo;
        SettingIntervalBox.Text = _settings.PollingIntervalMs.ToString();
        SettingSilentUpdateCheck.IsChecked = _settings.SilentAutoUpdate;
        SettingMacUserBox.Text = _settings.MacUsername;
        MacSshUserBox.Text = _settings.MacUsername;
        string decPass = SettingsService.UnprotectString(_settings.MacPasswordEncrypted);
        SettingMacPassBox.Password = decPass;
        MacSshPassBox.Password = decPass;
        VersionBadgeText.Text = $"v{AutoUpdateService.GetCurrentVersionString()}";
        KpiCredsText.Text = string.IsNullOrWhiteSpace(_settings.MacUsername) ? "Не заданы" : $"🔒 {_settings.MacUsername}";
        ApplyTheme(_settings.Theme);
    }

    private void ApplyTheme(string theme)
    {
        string normalized = theme?.ToLowerInvariant() switch
        {
            "light" => "Light",
            "raycast" => "Raycast",
            _ => "Dark"
        };

        string uri = normalized switch
        {
            "Light" => "Themes/LightTheme.xaml",
            "Raycast" => "Themes/RaycastTheme.xaml",
            _ => "Themes/DarkTheme.xaml"
        };

        var dicts = Application.Current.Resources.MergedDictionaries;
        if (dicts.Count > 0)
            dicts[0] = new ResourceDictionary { Source = new Uri(uri, UriKind.Relative) };

        ThemeToggleBtn.Content = normalized switch
        {
            "Dark" => "☀️ Светлая",
            "Light" => "⚡ Raycast",
            _ => "🌙 Чёрная"
        };

        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd != IntPtr.Zero)
        {
            int darkVal = normalized == "Light" ? 0 : 1;
            _ = DwmSetWindowAttribute(hwnd, 20, ref darkVal, sizeof(int));
        }
    }

    private void ThemeToggleBtn_Click(object sender, RoutedEventArgs e)
    {
        _settings.Theme = _settings.Theme?.ToLowerInvariant() switch
        {
            "dark" => "Light",
            "light" => "Raycast",
            _ => "Dark"
        };
        ApplyTheme(_settings.Theme);
        SettingsService.Save(_settings);
    }

    #region Command Palette (Ctrl+K)
    private static readonly string[] DefaultPaletteCommands =
    [
        "📡 Монитор трафика",
        "🌐 Сканер подсетей",
        "🍎 Инвентаризация Mac (SSH)",
        "🔓 Сканер портов",
        "🔍 Dig / DNS",
        "🎧 Слушающие порты",
        "📈 Ping / WinMTR",
        "🛡 WHOIS / TLS / HTTP",
        "🧱 Фаервол",
        "⚙ Настройки и обновления",
        "theme dark — Чёрная тема (Fluent)",
        "theme light — Светлая тема (Fluent)",
        "theme raycast — Minimalist / Raycast тема"
    ];

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.K && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
        {
            OpenCommandPalette();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && CommandPaletteOverlay.Visibility == Visibility.Visible)
        {
            CommandPaletteOverlay.Visibility = Visibility.Collapsed;
            e.Handled = true;
        }
    }

    private void CmdPaletteBtn_Click(object sender, RoutedEventArgs e) => OpenCommandPalette();

    private void OpenCommandPalette()
    {
        CommandPaletteBox.Text = "";
        CommandPaletteList.ItemsSource = DefaultPaletteCommands;
        CommandPaletteList.SelectedIndex = 0;
        CommandPaletteOverlay.Visibility = Visibility.Visible;
        CommandPaletteBox.Focus();
    }

    private void CommandPaletteOverlay_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        => CommandPaletteOverlay.Visibility = Visibility.Collapsed;

    private void CommandPaletteCard_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        => e.Handled = true;

    private void CommandPaletteBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        string q = CommandPaletteBox.Text.Trim();
        if (string.IsNullOrEmpty(q))
        {
            CommandPaletteList.ItemsSource = DefaultPaletteCommands;
            CommandPaletteList.SelectedIndex = 0;
            return;
        }

        var list = DefaultPaletteCommands
            .Where(c => c.Contains(q, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (q.StartsWith("ard ", StringComparison.OrdinalIgnoreCase))
            list.Insert(0, $"🖥 Подключиться по ARD: {q[4..].Trim()}");
        else if (q.StartsWith("scan ", StringComparison.OrdinalIgnoreCase))
            list.Insert(0, $"🌐 Сканировать подсеть: {q[5..].Trim()}");

        CommandPaletteList.ItemsSource = list;
        if (list.Count > 0) CommandPaletteList.SelectedIndex = 0;
    }

    private void CommandPaletteBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Down && CommandPaletteList.Items.Count > 0)
        {
            CommandPaletteList.SelectedIndex = Math.Min(CommandPaletteList.Items.Count - 1, CommandPaletteList.SelectedIndex + 1);
            e.Handled = true;
        }
        else if (e.Key == Key.Up && CommandPaletteList.Items.Count > 0)
        {
            CommandPaletteList.SelectedIndex = Math.Max(0, CommandPaletteList.SelectedIndex - 1);
            e.Handled = true;
        }
        else if (e.Key == Key.Enter)
        {
            string? selected = CommandPaletteList.SelectedItem?.ToString() ?? CommandPaletteBox.Text.Trim();
            ExecutePaletteCommand(selected);
            e.Handled = true;
        }
    }

    private void CommandPaletteList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (CommandPaletteList.SelectedItem is string cmd)
            ExecutePaletteCommand(cmd);
    }

    private void ExecutePaletteCommand(string? cmd)
    {
        CommandPaletteOverlay.Visibility = Visibility.Collapsed;
        if (string.IsNullOrWhiteSpace(cmd)) return;

        if (cmd.StartsWith("🖥 Подключиться по ARD:"))
        {
            string ip = cmd.Split(':', 2)[1].Trim();
            string pass = SettingsService.UnprotectString(_settings.MacPasswordEncrypted);
            new ArdViewerWindow(ip, 5900, _settings.MacUsername, pass) { Owner = this }.Show();
            return;
        }
        if (cmd.StartsWith("🌐 Сканировать подсеть:"))
        {
            SubnetCidrCombo.Text = cmd.Split(':', 2)[1].Trim();
            NavSubnet.IsChecked = true;
            SubnetScanBtn_Click(this, new RoutedEventArgs());
            return;
        }

        if (cmd.Contains("theme dark", StringComparison.OrdinalIgnoreCase)) { _settings.Theme = "Dark"; ApplyTheme("Dark"); SettingsService.Save(_settings); return; }
        if (cmd.Contains("theme light", StringComparison.OrdinalIgnoreCase)) { _settings.Theme = "Light"; ApplyTheme("Light"); SettingsService.Save(_settings); return; }
        if (cmd.Contains("theme raycast", StringComparison.OrdinalIgnoreCase)) { _settings.Theme = "Raycast"; ApplyTheme("Raycast"); SettingsService.Save(_settings); return; }

        if (cmd.Contains("Монитор трафика")) NavTraffic.IsChecked = true;
        else if (cmd.Contains("Сканер подсетей")) NavSubnet.IsChecked = true;
        else if (cmd.Contains("Инвентаризация Mac")) NavMacInventory.IsChecked = true;
        else if (cmd.Contains("Сканер портов")) NavPorts.IsChecked = true;
        else if (cmd.Contains("Dig")) NavDig.IsChecked = true;
        else if (cmd.Contains("Слушающие")) NavListening.IsChecked = true;
        else if (cmd.Contains("Ping")) NavMtr.IsChecked = true;
        else if (cmd.Contains("WHOIS")) NavInspect.IsChecked = true;
        else if (cmd.Contains("Фаервол")) NavFirewall.IsChecked = true;
        else if (cmd.Contains("Настройки")) NavSettings.IsChecked = true;
    }
    #endregion

    private async Task RunSilentStartupUpdateCheckAsync()
    {
        if (Environment.GetCommandLineArgs().Any(a => a.Equals("--updated", StringComparison.OrdinalIgnoreCase)))
            return;

        if (!_settings.SilentAutoUpdate || string.IsNullOrWhiteSpace(_settings.GitHubOwner))
            return;

        var res = await AutoUpdateService.CheckForUpdateAsync(_settings.GitHubOwner, _settings.GitHubRepo);
        if (res.UpdateAvailable)
        {
            _pendingUpdate = res;
            FooterStatusText.Text = $"Тихое обновление до v{res.LatestVersion}...";
            await AutoUpdateService.DownloadAndApplySilentAsync(res, relaunch: true);
        }
    }

    #region Navigation
    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (PanelTraffic == null) return;
        PanelTraffic.Visibility = NavTraffic.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelSubnet.Visibility = NavSubnet.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelMacInventory.Visibility = NavMacInventory.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelPorts.Visibility = NavPorts.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelDig.Visibility = NavDig.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelListening.Visibility = NavListening.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelMtr.Visibility = NavMtr.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelInspect.Visibility = NavInspect.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelFirewall.Visibility = NavFirewall.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelSettings.Visibility = NavSettings.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

        if (NavListening.IsChecked == true && _listeningPorts.Count == 0)
            RefreshListeningPorts();
        if (NavFirewall.IsChecked == true && _firewallRules.Count == 0)
            _ = RefreshFirewallRulesAsync();
    }
    #endregion

    #region Traffic Monitor
    private void PollTraffic()
    {
        var snap = _trafficService.Poll();
        if (!_trafficService.IsPaused)
        {
            _allConnections = snap.Connections;

            foreach (var ev in snap.NewEvents)
            {
                _events.Insert(0, ev);
                if (_events.Count > 500) _events.RemoveAt(_events.Count - 1);
            }

            foreach (var dns in snap.NewDnsLogs)
            {
                _dnsLogs.Insert(0, dns);
                if (_dnsLogs.Count > 500) _dnsLogs.RemoveAt(_dnsLogs.Count - 1);
            }

            UpdateProcessList(snap.Processes, snap.TotalHosts, snap.TotalEvents);
            ApplyConnectionFilter();
            StatsPillText.Text = $"{snap.TotalHosts} хостов • {snap.TotalEvents} событий";
        }
    }

    private void UpdateProcessList(List<ProcessSummary> incoming, int totalHosts, int totalEvents)
    {
        var allItem = _processes.FirstOrDefault(p => p.IsAllProcesses);
        if (allItem == null)
        {
            allItem = new ProcessSummary { ProcessName = $"Все приложения ({incoming.Count})", IsAllProcesses = true };
            _processes.Insert(0, allItem);
        }
        else
        {
            allItem.ProcessName = $"Все приложения ({incoming.Count})";
        }
        allItem.HostCount = totalHosts;
        allItem.HitCount = totalEvents;

        var existingMap = _processes.Where(p => !p.IsAllProcesses).ToDictionary(p => p.ProcessName);
        foreach (var proc in incoming)
        {
            if (existingMap.TryGetValue(proc.ProcessName, out var ex))
            {
                ex.PidCount = proc.PidCount;
                ex.HostCount = proc.HostCount;
                ex.HitCount = proc.HitCount;
                ex.RefreshSubtitle();
            }
            else
            {
                _processes.Add(proc);
            }
        }
    }

    private void ApplyConnectionFilter()
    {
        string search = GlobalSearchBox.Text.Trim();
        var filtered = _allConnections.Where(c =>
            (string.IsNullOrEmpty(_selectedProcess) || c.ProcessName.Equals(_selectedProcess, StringComparison.OrdinalIgnoreCase)) &&
            (string.IsNullOrEmpty(search) ||
             c.ProcessName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
             c.Domain.Contains(search, StringComparison.OrdinalIgnoreCase) ||
             c.RemoteIp.Contains(search, StringComparison.OrdinalIgnoreCase) ||
             c.RemotePort.ToString().Contains(search) ||
             c.Organization.Contains(search, StringComparison.OrdinalIgnoreCase))
        ).ToList();

        _filteredConnections.Clear();
        foreach (var item in filtered)
            _filteredConnections.Add(item);
    }

    private void ProcessListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ProcessListBox.SelectedItem is ProcessSummary ps)
        {
            _selectedProcess = ps.IsAllProcesses ? null : ps.ProcessName;
            ApplyConnectionFilter();
        }
    }

    private void ResetProcessFilter_Click(object sender, RoutedEventArgs e)
    {
        ProcessListBox.SelectedIndex = 0;
        _selectedProcess = null;
        ApplyConnectionFilter();
    }

    private void GlobalSearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyConnectionFilter();

    private void PauseBtn_Click(object sender, RoutedEventArgs e)
    {
        _trafficService.IsPaused = !_trafficService.IsPaused;
        PauseBtn.Content = _trafficService.IsPaused ? "▶ Продолжить" : "⏸ Пауза";
        FooterStatusText.Text = _trafficService.IsPaused ? "Мониторинг на паузе" : "Мониторинг активен";
    }

    private void ClearBtn_Click(object sender, RoutedEventArgs e)
    {
        _trafficService.Clear();
        _allConnections.Clear();
        _filteredConnections.Clear();
        _events.Clear();
        _dnsLogs.Clear();
        _processes.Clear();
        StatsPillText.Text = "0 хостов • 0 событий";
    }

    private void ExportBtn_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Filter = "CSV файл (*.csv)|*.csv|Текстовый файл (*.txt)|*.txt",
            FileName = $"netsnitch_export_{DateTime.Now:yyyyMMdd_HHmmss}"
        };
        if (dlg.ShowDialog() != true) return;

        var sb = new StringBuilder();
        sb.AppendLine("Process,Domain,IP,Port,Protocol,Organization,Status,Hits,LastSeen");
        foreach (var c in _filteredConnections)
            sb.AppendLine($"\"{c.ProcessName}\",\"{c.Domain}\",\"{c.RemoteIp}\",{c.RemotePort},{c.Protocol},\"{c.Organization}\",{c.Status},{c.Hits},{c.LastSeen}");

        File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
        FooterStatusText.Text = $"Экспортировано: {dlg.FileName}";
    }

    private async void RowTrace_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is ConnectionEntry entry)
        {
            TraceTargetBox.Text = entry.RemoteIp;
            TrafficSubTabs.SelectedIndex = 3;
            await RunTracerouteAsync(entry.RemoteIp);
        }
    }

    private async void RowBlockIp_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is ConnectionEntry entry)
        {
            var (ok, msg) = await FirewallService.BlockIpAsync(entry.RemoteIp);
            FooterStatusText.Text = msg;
            if (!ok)
                MessageBox.Show(msg, "Windows Firewall", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
    #endregion

    #region Traceroute
    private async void TraceRunBtn_Click(object sender, RoutedEventArgs e)
    {
        await RunTracerouteAsync(TraceTargetBox.Text.Trim());
    }

    private async Task RunTracerouteAsync(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return;
        _traceHops.Clear();
        TraceStatusText.Text = $"Трассировка {target}...";
        TraceRunBtn.IsEnabled = false;
        try
        {
            await DiagnosticsService.TracerouteAsync(target, 30,
                hop => Dispatcher.Invoke(() => _traceHops.Add(hop)),
                CancellationToken.None);
            TraceStatusText.Text = $"Завершено ({_traceHops.Count} хопов)";
        }
        catch (Exception ex)
        {
            TraceStatusText.Text = $"Ошибка: {ex.Message}";
        }
        finally
        {
            TraceRunBtn.IsEnabled = true;
        }
    }
    #endregion

    #region Subnet Scanner
    private void ApplySubnetFilter()
    {
        bool onlyMac = OnlyMacCheck.IsChecked == true;
        _subnetHosts.Clear();
        foreach (var h in _allSubnetHosts)
        {
            if (!onlyMac || h.IsMac || h.IsApple)
                _subnetHosts.Add(h);
        }
    }

    private void OnlyMacCheck_Changed(object sender, RoutedEventArgs e) => ApplySubnetFilter();

    private async void SubnetScanBtn_Click(object sender, RoutedEventArgs e)
    {
        string cidr = SubnetCidrCombo.Text.Trim();
        if (string.IsNullOrWhiteSpace(cidr)) return;

        _allSubnetHosts.Clear();
        _subnetHosts.Clear();
        _subnetCts = new CancellationTokenSource();
        SubnetScanBtn.IsEnabled = false;
        SubnetStopBtn.IsEnabled = true;
        KpiSubnetText.Text = cidr;
        KpiMacCountText.Text = "0";
        KpiTotalHostsText.Text = "0";
        SubnetStatusText.Text = "Сканирование (Ping + ARP + TCP + mDNS)...";

        try
        {
            await SubnetScannerService.ScanSubnetAsync(
                cidr,
                host => Dispatcher.Invoke(() =>
                {
                    _allSubnetHosts.Add(host);
                    if (OnlyMacCheck.IsChecked != true || host.IsMac || host.IsApple)
                        _subnetHosts.Add(host);
                    KpiTotalHostsText.Text = _allSubnetHosts.Count.ToString();
                    KpiMacCountText.Text = _allSubnetHosts.Count(h => h.IsMac).ToString();
                }),
                (done, total) => Dispatcher.Invoke(() =>
                {
                    int macs = _allSubnetHosts.Count(h => h.IsMac);
                    SubnetStatusText.Text = $"Проверено {done}/{total} • Всего: {_allSubnetHosts.Count} • 🍎 Mac: {macs}";
                }),
                _subnetCts.Token);
            int totalMacs = _allSubnetHosts.Count(h => h.IsMac);
            SubnetStatusText.Text = $"Готово • Устройств: {_allSubnetHosts.Count} • 🍎 Mac найдено: {totalMacs}";
        }
        catch (OperationCanceledException)
        {
            int macs = _allSubnetHosts.Count(h => h.IsMac);
            SubnetStatusText.Text = $"Остановлено • Устройств: {_allSubnetHosts.Count} • 🍎 Mac: {macs}";
        }
        catch (Exception ex)
        {
            SubnetStatusText.Text = $"Ошибка: {ex.Message}";
        }
        finally
        {
            SubnetScanBtn.IsEnabled = true;
            SubnetStopBtn.IsEnabled = false;
        }
    }

    private void SubnetStopBtn_Click(object sender, RoutedEventArgs e) => _subnetCts?.Cancel();

    private void SubnetArd_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is SubnetHostEntry host)
        {
            string pass = SettingsService.UnprotectString(_settings.MacPasswordEncrypted);
            var viewer = new ArdViewerWindow(host.IpAddress, 5900, _settings.MacUsername, pass) { Owner = this };
            viewer.Show();
        }
    }

    private async void SubnetCollectMacHw_Click(object sender, RoutedEventArgs e)
    {
        LoadMacsFromScanner();
        NavMacInventory.IsChecked = true;
        if (!string.IsNullOrWhiteSpace(MacTargetsBox.Text))
            await CollectMacInventoryAsync();
    }

    private void SubnetScanPorts_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is SubnetHostEntry host)
        {
            PortHostBox.Text = host.IpAddress;
            NavPorts.IsChecked = true;
        }
    }

    private async void SubnetWol_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is SubnetHostEntry host)
        {
            try
            {
                await DiagnosticsService.SendWakeOnLanAsync(host.MacAddress);
                FooterStatusText.Text = $"Wake-on-LAN пакет отправлен на {host.MacAddress}";
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Wake-on-LAN", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }
    #endregion

    #region Port Scanner
    private void PortProfileCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PortRangeBox != null)
            PortRangeBox.Visibility = PortProfileCombo.SelectedIndex == 3 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void PortScanBtn_Click(object sender, RoutedEventArgs e)
    {
        string host = PortHostBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(host)) return;

        List<int> ports = PortProfileCombo.SelectedIndex switch
        {
            0 => [.. PortScannerService.TopPorts],
            1 => [.. PortScannerService.WebDbPorts],
            2 => Enumerable.Range(1, 1024).ToList(),
            _ => PortScannerService.ParsePortRange(PortRangeBox.Text)
        };

        if (ports.Count == 0)
        {
            PortStatusText.Text = "Укажите корректный диапазон портов.";
            return;
        }

        _portResults.Clear();
        _portCts = new CancellationTokenSource();
        PortScanBtn.IsEnabled = false;
        PortStopBtn.IsEnabled = true;
        bool grab = BannerGrabCheck.IsChecked == true;

        try
        {
            await PortScannerService.ScanAsync(
                host, ports, 700, grab,
                res => Dispatcher.Invoke(() => _portResults.Add(res)),
                (done, total) => Dispatcher.Invoke(() =>
                    PortStatusText.Text = $"Порты: {done}/{total} • Открыто: {_portResults.Count}"),
                _portCts.Token);
            PortStatusText.Text = $"Готово • Открыто портов: {_portResults.Count}";
        }
        catch (OperationCanceledException)
        {
            PortStatusText.Text = $"Остановлено • Открыто: {_portResults.Count}";
        }
        catch (Exception ex)
        {
            PortStatusText.Text = $"Ошибка: {ex.Message}";
        }
        finally
        {
            PortScanBtn.IsEnabled = true;
            PortStopBtn.IsEnabled = false;
        }
    }

    private void PortStopBtn_Click(object sender, RoutedEventArgs e) => _portCts?.Cancel();
    #endregion

    #region Dig / DNS
    private async void DigRunBtn_Click(object sender, RoutedEventArgs e)
    {
        string domain = DigDomainBox.Text.Trim();
        string rtype = DigTypeCombo.SelectedItem?.ToString() ?? "A";
        string resolver = DigResolverCombo.Text.Trim();
        if (string.IsNullOrWhiteSpace(domain)) return;

        _digResults.Clear();
        DigStatusText.Text = "Запрос...";
        try
        {
            var res = await DigService.QueryAsync(domain, rtype, resolver);
            foreach (var r in res) _digResults.Add(r);
            DigStatusText.Text = $"Записей: {res.Count}";
        }
        catch (Exception ex)
        {
            DigStatusText.Text = $"Ошибка: {ex.Message}";
        }
    }

    private async void DigCompareBtn_Click(object sender, RoutedEventArgs e)
    {
        string domain = DigDomainBox.Text.Trim();
        string rtype = DigTypeCombo.SelectedItem?.ToString() ?? "A";
        if (string.IsNullOrWhiteSpace(domain)) return;

        _digResults.Clear();
        DigStatusText.Text = "Сравнение 1.1.1.1 / 8.8.8.8 / 9.9.9.9 / 77.88.8.8...";
        try
        {
            var res = await DigService.CompareResolversAsync(domain, rtype);
            foreach (var r in res) _digResults.Add(r);
            DigStatusText.Text = $"Всего записей: {res.Count}";
        }
        catch (Exception ex)
        {
            DigStatusText.Text = $"Ошибка: {ex.Message}";
        }
    }
    #endregion

    #region Listening Ports
    private void RefreshListeningBtn_Click(object sender, RoutedEventArgs e) => RefreshListeningPorts();

    private void RefreshListeningPorts()
    {
        _listeningPorts.Clear();
        var list = TrafficMonitorService.GetListeningPorts();
        foreach (var item in list) _listeningPorts.Add(item);
        ListeningStatusText.Text = $"Найдено слушающих сокетов: {list.Count}";
    }
    #endregion

    #region Ping / WinMTR
    private async void MtrStartBtn_Click(object sender, RoutedEventArgs e)
    {
        string target = MtrTargetBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(target)) return;

        _mtrHops.Clear();
        _mtrCts = new CancellationTokenSource();
        MtrStartBtn.IsEnabled = false;
        MtrStopBtn.IsEnabled = true;
        MtrStatusText.Text = $"Мониторинг маршрута до {target}...";

        try
        {
            await DiagnosticsService.RunMtrLoopAsync(
                target,
                _mtrHops,
                () => Dispatcher.Invoke(() => MtrGrid.Items.Refresh()),
                _mtrCts.Token);
        }
        catch (OperationCanceledException)
        {
            MtrStatusText.Text = "MTR остановлен";
        }
        catch (Exception ex)
        {
            MtrStatusText.Text = $"Ошибка: {ex.Message}";
        }
        finally
        {
            MtrStartBtn.IsEnabled = true;
            MtrStopBtn.IsEnabled = false;
        }
    }

    private void MtrStopBtn_Click(object sender, RoutedEventArgs e) => _mtrCts?.Cancel();
    #endregion

    #region WHOIS / TLS / HTTP
    private async void InspectWhois_Click(object sender, RoutedEventArgs e)
    {
        string target = InspectTargetBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(target)) return;
        InspectOutputBox.Text = "Запрос WHOIS + GeoIP...";
        try
        {
            var geo = await GeoIpService.LookupAsync(target);
            string whois = await DiagnosticsService.WhoisQueryAsync(target);
            InspectOutputBox.Text = $"GeoIP/ASN: {geo.Display}\r\n\r\n{whois}";
        }
        catch (Exception ex)
        {
            InspectOutputBox.Text = $"Ошибка WHOIS: {ex.Message}";
        }
    }

    private async void InspectTls_Click(object sender, RoutedEventArgs e)
    {
        string raw = InspectTargetBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(raw)) return;

        string host = raw.Replace("https://", "").Replace("http://", "").Split('/')[0];
        int port = 443;
        if (host.Contains(':'))
        {
            var parts = host.Split(':', 2);
            host = parts[0];
            int.TryParse(parts[1], out port);
        }

        InspectOutputBox.Text = $"Проверка TLS {host}:{port}...";
        try
        {
            var cert = await DiagnosticsService.InspectTlsAsync(host, port);
            InspectOutputBox.Text =
                $"Хост:           {cert.Host}:{cert.Port}\r\n" +
                $"Протокол:       {cert.Protocol}\r\n" +
                $"Шифр:           {cert.CipherSuite}\r\n" +
                $"Статус цепочки: {cert.ChainStatus}\r\n" +
                $"Выдан (Subject):{cert.Subject}\r\n" +
                $"Кем (Issuer):   {cert.Issuer}\r\n" +
                $"Действует с:    {cert.NotBefore:yyyy-MM-dd HH:mm}\r\n" +
                $"Истекает:       {cert.NotAfter:yyyy-MM-dd HH:mm} (осталось {cert.DaysRemaining} дн.)\r\n" +
                $"Отпечаток:      {cert.Thumbprint}\r\n" +
                $"SAN:\r\n{cert.Sans}";
        }
        catch (Exception ex)
        {
            InspectOutputBox.Text = $"Ошибка TLS: {ex.Message}";
        }
    }

    private async void InspectHttp_Click(object sender, RoutedEventArgs e)
    {
        string target = InspectTargetBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(target)) return;
        InspectOutputBox.Text = $"HTTP запрос к {target}...";
        try
        {
            var res = await DiagnosticsService.ProbeHttpAsync(target);
            InspectOutputBox.Text =
                $"URL:        {res.FinalUrl}\r\n" +
                $"Статус:     {res.StatusCode} {res.StatusText}\r\n" +
                $"Время:      {res.ElapsedMs} ms\r\n\r\n" +
                $"=== Заголовки ===\r\n{res.Headers}\r\n\r\n" +
                $"=== Тело (превью) ===\r\n{res.BodyPreview}";
        }
        catch (Exception ex)
        {
            InspectOutputBox.Text = $"Ошибка HTTP: {ex.Message}";
        }
    }
    #endregion

    #region Firewall Manager
    private async void RefreshFirewallBtn_Click(object sender, RoutedEventArgs e) => await RefreshFirewallRulesAsync();

    private async Task RefreshFirewallRulesAsync()
    {
        _firewallRules.Clear();
        var rules = await FirewallService.GetNetSnitchRulesAsync();
        foreach (var r in rules) _firewallRules.Add(r);
        FooterStatusText.Text = $"Правил NetSnitch в фаерволе: {rules.Count}";
    }

    private async void DeleteFirewallRule_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is FirewallRuleEntry rule)
        {
            var (ok, msg) = await FirewallService.DeleteRuleAsync(rule.RuleName);
            FooterStatusText.Text = msg;
            if (ok) _firewallRules.Remove(rule);
        }
    }
    #endregion

    #region Settings & Auto-Update
    private void VersionBadge_Click(object sender, MouseButtonEventArgs e) => NavSettings.IsChecked = true;

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        _settings.GitHubOwner = SettingOwnerBox.Text.Trim();
        _settings.GitHubRepo = SettingRepoBox.Text.Trim();
        _settings.SilentAutoUpdate = SettingSilentUpdateCheck.IsChecked == true;
        _settings.MacUsername = SettingMacUserBox.Text.Trim();
        _settings.MacPasswordEncrypted = SettingsService.ProtectString(SettingMacPassBox.Password);
        MacSshUserBox.Text = _settings.MacUsername;
        MacSshPassBox.Password = SettingMacPassBox.Password;
        if (int.TryParse(SettingIntervalBox.Text.Trim(), out int ms) && ms >= 500)
        {
            _settings.PollingIntervalMs = ms;
            _pollTimer.Interval = TimeSpan.FromMilliseconds(ms);
        }
        SettingsService.Save(_settings);
        KpiCredsText.Text = string.IsNullOrWhiteSpace(_settings.MacUsername) ? "Не заданы" : $"🔒 {_settings.MacUsername}";
        UpdateStatusText.Text = "Настройки и учётные данные сохранены.";
    }

    #region Mac Inventory (SSH)
    private void SaveMacCreds_Click(object sender, RoutedEventArgs e)
    {
        _settings.MacUsername = MacSshUserBox.Text.Trim();
        _settings.MacPasswordEncrypted = SettingsService.ProtectString(MacSshPassBox.Password);
        SettingMacUserBox.Text = _settings.MacUsername;
        SettingMacPassBox.Password = MacSshPassBox.Password;
        SettingsService.Save(_settings);
        KpiCredsText.Text = string.IsNullOrWhiteSpace(_settings.MacUsername) ? "Не заданы" : $"🔒 {_settings.MacUsername}";
        MacInventoryStatusText.Text = "Учётные данные сохранены (DPAPI).";
    }

    private void LoadMacsFromScanner()
    {
        var macIps = _allSubnetHosts.Where(h => h.IsMac).Select(h => h.IpAddress).ToList();
        if (macIps.Count == 0)
            macIps = _allSubnetHosts.Select(h => h.IpAddress).ToList();
        MacTargetsBox.Text = string.Join(", ", macIps);
    }

    private void LoadMacsFromScanner_Click(object sender, RoutedEventArgs e) => LoadMacsFromScanner();

    private async void MacCollectBtn_Click(object sender, RoutedEventArgs e) => await CollectMacInventoryAsync();

    private async Task CollectMacInventoryAsync()
    {
        var ips = MacTargetsBox.Text
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct()
            .ToList();

        if (ips.Count == 0)
        {
            MacInventoryStatusText.Text = "Укажите IP-адреса Mac.";
            return;
        }

        string user = MacSshUserBox.Text.Trim();
        string pass = MacSshPassBox.Password;
        if (string.IsNullOrWhiteSpace(user))
        {
            MacInventoryStatusText.Text = "Укажите логин Mac (можно сохранить кнопкой «Запомнить»).";
            return;
        }

        _macInventory.Clear();
        MacCollectBtn.IsEnabled = false;
        MacInventoryStatusText.Text = $"Сбор данных с {ips.Count} хостов по SSH...";

        using var gate = new SemaphoreSlim(8, 8);
        int done = 0;

        try
        {
            var tasks = ips.Select(async ip =>
            {
                await gate.WaitAsync();
                try
                {
                    var res = await MacInventoryService.CollectAsync(ip, user, pass, CancellationToken.None);
                    Dispatcher.Invoke(() =>
                    {
                        _macInventory.Add(res);
                        done++;
                        MacInventoryStatusText.Text = $"Обработано {done}/{ips.Count}";
                    });
                }
                finally { gate.Release(); }
            });
            await Task.WhenAll(tasks);
            MacInventoryStatusText.Text = $"Готово • Собрано: {_macInventory.Count}";
        }
        finally
        {
            MacCollectBtn.IsEnabled = true;
        }
    }

    private void ExportMacCsv_Click(object sender, RoutedEventArgs e)
    {
        if (_macInventory.Count == 0) return;
        var dlg = new SaveFileDialog
        {
            Filter = "CSV файл (*.csv)|*.csv",
            FileName = $"mac_inventory_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };
        if (dlg.ShowDialog() != true) return;

        var sb = new StringBuilder();
        sb.AppendLine("IP,Hostname,Model,CPU,RAM,Disk,macOS,SerialNumber,Status");
        foreach (var m in _macInventory)
            sb.AppendLine($"\"{m.IpAddress}\",\"{m.Hostname}\",\"{m.Model}\",\"{m.Cpu}\",\"{m.Ram}\",\"{m.Disk}\",\"{m.MacOs}\",\"{m.SerialNumber}\",\"{m.Status}\"");
        File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
        MacInventoryStatusText.Text = $"Экспортировано: {dlg.FileName}";
    }
    #endregion

    private async void CheckUpdateBtn_Click(object sender, RoutedEventArgs e)
    {
        SaveSettings_Click(sender, e);
        UpdateStatusText.Text = "Проверка релизов на GitHub...";
        var res = await AutoUpdateService.CheckForUpdateAsync(_settings.GitHubOwner, _settings.GitHubRepo);
        if (!string.IsNullOrEmpty(res.Error))
        {
            UpdateStatusText.Text = $"Ошибка: {res.Error}";
            ApplyUpdateBtn.Visibility = Visibility.Collapsed;
            return;
        }

        if (res.UpdateAvailable)
        {
            _pendingUpdate = res;
            UpdateStatusText.Text = $"Доступна новая версия v{res.LatestVersion} (текущая v{res.CurrentVersion}).\nФайл: {res.AssetName}";
            ApplyUpdateBtn.Visibility = Visibility.Visible;
        }
        else
        {
            UpdateStatusText.Text = $"У вас актуальная версия v{res.CurrentVersion}.";
            ApplyUpdateBtn.Visibility = Visibility.Collapsed;
        }
    }

    private async void ApplyUpdateBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdate == null) return;
        UpdateStatusText.Text = "Скачивание и тихое обновление...";
        var (_, msg) = await AutoUpdateService.DownloadAndApplySilentAsync(_pendingUpdate, relaunch: true);
        UpdateStatusText.Text = msg;
    }
    #endregion
}
