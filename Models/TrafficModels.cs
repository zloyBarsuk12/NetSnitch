using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace NetSnitch.Models;

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}

public class ProcessSummary : ObservableObject
{
    private int _pidCount;
    private int _hostCount;
    private int _hitCount;

    public string ProcessName { get; set; } = string.Empty;
    public bool IsAllProcesses { get; set; }

    public int PidCount { get => _pidCount; set => SetProperty(ref _pidCount, value); }
    public int HostCount { get => _hostCount; set => SetProperty(ref _hostCount, value); }
    public int HitCount { get => _hitCount; set => SetProperty(ref _hitCount, value); }

    public string Subtitle => IsAllProcesses
        ? "Общий обзор трафика"
        : $"{PidCount} PID • {HostCount} хостов • {HitCount} хитов";

    public void RefreshSubtitle() => OnPropertyChanged(nameof(Subtitle));
}

public class ConnectionEntry : ObservableObject
{
    private string _domain = "—";
    private string _organization = "Определение...";
    private string _status = "ESTABLISHED";
    private long _sentBytes;
    private long _receivedBytes;
    private int _hits = 1;
    private string _lastSeen = string.Empty;
    private bool _isBlocked;

    public string Key { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string RemoteIp { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public int LocalPort { get; set; }
    public string Protocol { get; set; } = "TCP";

    public string Domain { get => _domain; set => SetProperty(ref _domain, value); }
    public string IpPort => $"{RemoteIp}:{RemotePort}" + (PortLabel is { Length: > 0 } l ? $" ({l})" : "");
    public string PortLabel => RemotePort switch
    {
        443 => "HTTPS",
        80 => "HTTP",
        53 => "DNS",
        22 => "SSH",
        21 => "FTP",
        25 or 587 or 465 => "SMTP",
        3389 => "RDP",
        5228 => "Google Push",
        8080 => "HTTP-Alt",
        _ => ""
    };

    public string Organization { get => _organization; set => SetProperty(ref _organization, value); }
    public string Status { get => _status; set => SetProperty(ref _status, value); }
    public long SentBytes { get => _sentBytes; set { if (SetProperty(ref _sentBytes, value)) OnPropertyChanged(nameof(SentDisplay)); } }
    public long ReceivedBytes { get => _receivedBytes; set { if (SetProperty(ref _receivedBytes, value)) OnPropertyChanged(nameof(ReceivedDisplay)); } }
    public int Hits { get => _hits; set => SetProperty(ref _hits, value); }
    public string LastSeen { get => _lastSeen; set => SetProperty(ref _lastSeen, value); }
    public bool IsBlocked { get => _isBlocked; set => SetProperty(ref _isBlocked, value); }

    public string SentDisplay => FormatBytes(SentBytes);
    public string ReceivedDisplay => FormatBytes(ReceivedBytes);

    public static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = ["B", "KB", "MB", "GB"];
        double val = bytes;
        int idx = 0;
        while (val >= 1024 && idx < units.Length - 1)
        {
            val /= 1024;
            idx++;
        }
        return idx == 0 ? $"{val:0} B" : $"{val:0.0} {units[idx]}";
    }
}

public class TrafficEventEntry
{
    public string Time { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string RemoteEndpoint { get; set; } = string.Empty;
    public string Domain { get; set; } = "—";
    public string EventType { get; set; } = "CONNECT";
    public string Organization { get; set; } = "—";
}

public class DnsLogEntry
{
    public string Time { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string ResolvedIp { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string Source { get; set; } = "PTR / Cache";
}

public class ListeningPortEntry
{
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = "0.0.0.0";
    public int LocalPort { get; set; }
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public string State { get; set; } = "LISTEN";
}

public class FirewallRuleEntry
{
    public string RuleName { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public string Direction { get; set; } = "Outbound";
    public string Action { get; set; } = "Block";
    public string Enabled { get; set; } = "Yes";
}
