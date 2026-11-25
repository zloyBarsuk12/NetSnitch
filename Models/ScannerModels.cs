namespace NetSnitch.Models;

public class SubnetHostEntry : ObservableObject
{
    private string _hostname = "—";
    private string _macAddress = "—";
    private string _vendor = "—";
    private string _deviceType = "—";
    private string _rttMs = "—";
    private string _status = "Online";

    public string IpAddress { get; set; } = string.Empty;
    public string Hostname { get => _hostname; set => SetProperty(ref _hostname, value); }
    public string MacAddress { get => _macAddress; set => SetProperty(ref _macAddress, value); }
    public string Vendor { get => _vendor; set => SetProperty(ref _vendor, value); }
    public string DeviceType { get => _deviceType; set => SetProperty(ref _deviceType, value); }
    public bool IsApple { get; set; }
    public bool IsMac { get; set; }
    public string RttMs { get => _rttMs; set => SetProperty(ref _rttMs, value); }
    public string Status { get => _status; set => SetProperty(ref _status, value); }
}

public class PortScanResult
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string State { get; set; } = "OPEN";
    public string Service { get; set; } = string.Empty;
    public string Banner { get; set; } = string.Empty;
    public long LatencyMs { get; set; }
}

public class DigRecordEntry
{
    public string Resolver { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string RecordType { get; set; } = string.Empty;
    public uint Ttl { get; set; }
    public string Value { get; set; } = string.Empty;
    public long QueryTimeMs { get; set; }
}

public class MtrHopEntry : ObservableObject
{
    private string _ipAddress = "*";
    private string _hostname = "—";
    private string _organization = "—";
    private int _sent;
    private int _lost;
    private double _lastMs;
    private double _avgMs;
    private double _bestMs = double.MaxValue;
    private double _worstMs;

    public int Hop { get; set; }
    public string IpAddress { get => _ipAddress; set => SetProperty(ref _ipAddress, value); }
    public string Hostname { get => _hostname; set => SetProperty(ref _hostname, value); }
    public string Organization { get => _organization; set => SetProperty(ref _organization, value); }
    public int Sent { get => _sent; set { if (SetProperty(ref _sent, value)) OnPropertyChanged(nameof(LossDisplay)); } }
    public int Lost { get => _lost; set { if (SetProperty(ref _lost, value)) OnPropertyChanged(nameof(LossDisplay)); } }
    public double LastMs { get => _lastMs; set { if (SetProperty(ref _lastMs, value)) OnPropertyChanged(nameof(LastDisplay)); } }
    public double AvgMs { get => _avgMs; set { if (SetProperty(ref _avgMs, value)) OnPropertyChanged(nameof(AvgDisplay)); } }
    public double BestMs { get => _bestMs; set { if (SetProperty(ref _bestMs, value)) OnPropertyChanged(nameof(BestDisplay)); } }
    public double WorstMs { get => _worstMs; set { if (SetProperty(ref _worstMs, value)) OnPropertyChanged(nameof(WorstDisplay)); } }

    public string LossDisplay => Sent == 0 ? "0%" : $"{(Lost * 100.0 / Sent):0.0}%";
    public string LastDisplay => LastMs <= 0 ? "*" : $"{LastMs:0.0} ms";
    public string AvgDisplay => Sent - Lost <= 0 ? "*" : $"{AvgMs:0.0} ms";
    public string BestDisplay => BestMs == double.MaxValue ? "*" : $"{BestMs:0.0} ms";
    public string WorstDisplay => WorstMs <= 0 ? "*" : $"{WorstMs:0.0} ms";
}

public class GeoAsnInfo
{
    public string Ip { get; set; } = string.Empty;
    public string CountryCode { get; set; } = "";
    public string Org { get; set; } = "";
    public string Display => string.IsNullOrWhiteSpace(Org)
        ? (string.IsNullOrWhiteSpace(CountryCode) ? "—" : CountryCode)
        : (string.IsNullOrWhiteSpace(CountryCode) ? Org : $"{Org} ({CountryCode})");
}

public class TlsCertInfo
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public int DaysRemaining { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string CipherSuite { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public string Sans { get; set; } = string.Empty;
    public string ChainStatus { get; set; } = string.Empty;
}

public class HttpProbeResult
{
    public string Url { get; set; } = string.Empty;
    public int StatusCode { get; set; }
    public string StatusText { get; set; } = string.Empty;
    public long ElapsedMs { get; set; }
    public string FinalUrl { get; set; } = string.Empty;
    public string Headers { get; set; } = string.Empty;
    public string BodyPreview { get; set; } = string.Empty;
}

public class UpdateCheckResult
{
    public bool UpdateAvailable { get; set; }
    public string CurrentVersion { get; set; } = "1.0.0";
    public string LatestVersion { get; set; } = "1.0.0";
    public string ReleaseNotes { get; set; } = string.Empty;
    public string DownloadUrl { get; set; } = string.Empty;
    public string AssetName { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
}

public class MacHardwareInfo
{
    public string IpAddress { get; set; } = string.Empty;
    public string Hostname { get; set; } = "—";
    public string Model { get; set; } = "—";
    public string Cpu { get; set; } = "—";
    public string Ram { get; set; } = "—";
    public string Disk { get; set; } = "—";
    public string MacOs { get; set; } = "—";
    public string SerialNumber { get; set; } = "—";
    public string Status { get; set; } = "OK";
}

public class AppSettings
{
    public string GitHubOwner { get; set; } = "zloyBarsuk12";
    public string GitHubRepo { get; set; } = "NetSnitch";
    public bool SilentAutoUpdate { get; set; } = true;
    public int PollingIntervalMs { get; set; } = 1000;
    public string MacUsername { get; set; } = "";
    public string MacPasswordEncrypted { get; set; } = "";
}
