using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class PortScannerService
{
    public static readonly int[] TopPorts =
    [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
        1433, 1521, 1723, 2049, 2181, 2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432,
        5672, 5900, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
        9200, 9300, 11211, 27017
    ];

    public static readonly int[] WebDbPorts =
    [
        80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9000, 9200, 11211, 27017, 1433, 1521
    ];

    public static List<int> ParsePortRange(string spec)
    {
        var ports = new HashSet<int>();
        foreach (var part in spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Contains('-'))
            {
                var bounds = part.Split('-', 2);
                if (int.TryParse(bounds[0], out int start) && int.TryParse(bounds[1], out int end))
                {
                    start = Math.Clamp(start, 1, 65535);
                    end = Math.Clamp(end, 1, 65535);
                    for (int p = Math.Min(start, end); p <= Math.Max(start, end); p++)
                        ports.Add(p);
                }
            }
            else if (int.TryParse(part, out int single) && single is >= 1 and <= 65535)
            {
                ports.Add(single);
            }
        }
        return ports.OrderBy(p => p).ToList();
    }

    public static string GuessService(int port) => port switch
    {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        587 => "Submission",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        2375 or 2376 => "Docker",
        3000 => "Node/Grafana",
        3306 => "MySQL",
        3389 => "RDP",
        5000 => "Flask/Registry",
        5432 => "PostgreSQL",
        5672 => "RabbitMQ",
        5900 => "VNC",
        6379 => "Redis",
        6443 => "Kubernetes API",
        8000 or 8008 or 8080 or 8081 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        9000 => "Sonar/Portainer",
        9090 => "Prometheus",
        9200 => "Elasticsearch",
        11211 => "Memcached",
        27017 => "MongoDB",
        _ => "Unknown"
    };

    public static async Task ScanAsync(
        string host,
        List<int> ports,
        int timeoutMs,
        bool grabBanner,
        Action<PortScanResult> onOpenPort,
        Action<int, int> onProgress,
        CancellationToken ct)
    {
        int total = ports.Count;
        int done = 0;
        using var gate = new SemaphoreSlim(128, 128);

        var tasks = ports.Select(async port =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                using var client = new TcpClient();
                var sw = Stopwatch.StartNew();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);

                try
                {
                    await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
                    sw.Stop();

                    string banner = "";
                    if (grabBanner)
                    {
                        banner = await TryGrabBannerAsync(client, port, host, cts.Token).ConfigureAwait(false);
                    }

                    onOpenPort(new PortScanResult
                    {
                        Host = host,
                        Port = port,
                        Protocol = "TCP",
                        State = "OPEN",
                        Service = GuessService(port),
                        Banner = banner,
                        LatencyMs = sw.ElapsedMilliseconds
                    });
                }
                catch
                {
                    // Closed or filtered
                }
            }
            finally
            {
                int current = Interlocked.Increment(ref done);
                onProgress(current, total);
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private static async Task<string> TryGrabBannerAsync(TcpClient client, int port, string host, CancellationToken ct)
    {
        try
        {
            var stream = client.GetStream();
            stream.ReadTimeout = 600;
            stream.WriteTimeout = 600;

            if (port is 80 or 8000 or 8008 or 8080 or 8081 or 3000 or 5000 or 9000)
            {
                byte[] req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n");
                await stream.WriteAsync(req, ct).ConfigureAwait(false);
            }

            byte[] buf = new byte[512];
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(600);
            int read = await stream.ReadAsync(buf, readCts.Token).ConfigureAwait(false);
            if (read <= 0) return "";

            string text = Encoding.ASCII.GetString(buf, 0, read)
                .Replace("\r", " ")
                .Replace("\n", " ")
                .Trim();
            return text.Length > 100 ? text[..100] + "..." : text;
        }
        catch
        {
            return "";
        }
    }
}
