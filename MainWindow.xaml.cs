using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using NetSnitch.Models;
using NetSnitch.Services;

namespace NetSnitch;

public partial class MainWindow : Window
{
    private readonly TrafficMonitorService _trafficService = new();
    private readonly DispatcherTimer _pollTimer = new();

    private readonly ObservableCollection<ProcessSummary> _processes = [];
    private readonly ObservableCollection<ConnectionEntry> _filteredConnections = [];
    private readonly ObservableCollection<TrafficEventEntry> _events = [];
    private readonly ObservableCollection<DnsLogEntry> _dnsLogs = [];
    private readonly ObservableCollection<MtrHopEntry> _traceHops = [];
    private readonly ObservableCollection<SubnetHostEntry> _subnetHosts = [];
    private readonly List<SubnetHostEntry> _allSubnetHosts = [];
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
        VersionBadgeText.Text = $"v{AutoUpdateService.GetCurrentVersionString()}";
    }

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
        SubnetStatusText.Text = "Сканирование (Ping + ARP + mDNS)...";

        try
        {
            await SubnetScannerService.ScanSubnetAsync(
                cidr,
                host => Dispatcher.Invoke(() =>
                {
                    _allSubnetHosts.Add(host);
                    if (OnlyMacCheck.IsChecked != true || host.IsMac || host.IsApple)
                        _subnetHosts.Add(host);
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
            var viewer = new ArdViewerWindow(host.IpAddress, 5900) { Owner = this };
            viewer.Show();
        }
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
        if (int.TryParse(SettingIntervalBox.Text.Trim(), out int ms) && ms >= 500)
        {
            _settings.PollingIntervalMs = ms;
            _pollTimer.Interval = TimeSpan.FromMilliseconds(ms);
        }
        SettingsService.Save(_settings);
        UpdateStatusText.Text = "Настройки сохранены.";
    }

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
