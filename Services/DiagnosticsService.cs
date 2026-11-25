using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class DiagnosticsService
{
    public static async Task<List<MtrHopEntry>> TracerouteAsync(
        string target,
        int maxHops,
        Action<MtrHopEntry>? onHop,
        CancellationToken ct)
    {
        var hops = new List<MtrHopEntry>();
        var ips = await Dns.GetHostAddressesAsync(target, ct).ConfigureAwait(false);
        var dest = ips.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetwork) ?? ips.First();

        using var ping = new Ping();
        byte[] payload = Encoding.ASCII.GetBytes("NetSnitchTrace");

        for (int ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            var opts = new PingOptions(ttl, true);
            var sw = Stopwatch.StartNew();
            var reply = await ping.SendPingAsync(dest, 1500, payload, opts).ConfigureAwait(false);
            sw.Stop();

            var hop = new MtrHopEntry { Hop = ttl, Sent = 1 };
            if (reply.Status is IPStatus.Success or IPStatus.TtlExpired && reply.Address != null)
            {
                hop.IpAddress = reply.Address.ToString();
                hop.LastMs = sw.Elapsed.TotalMilliseconds;
                hop.AvgMs = hop.LastMs;
                hop.BestMs = hop.LastMs;
                hop.WorstMs = hop.LastMs;

                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(reply.Address).WaitAsync(TimeSpan.FromMilliseconds(500), ct).ConfigureAwait(false);
                    hop.Hostname = hostEntry.HostName;
                }
                catch { }

                var geo = await GeoIpService.LookupAsync(hop.IpAddress).ConfigureAwait(false);
                hop.Organization = geo.Display;
            }
            else
            {
                hop.Lost = 1;
            }

            hops.Add(hop);
            onHop?.Invoke(hop);

            if (reply.Status == IPStatus.Success)
                break;
        }

        return hops;
    }

    public static async Task RunMtrLoopAsync(
        string target,
        IList<MtrHopEntry> hopTable,
        Action refreshUi,
        CancellationToken ct)
    {
        // Initial discovery
        var initial = await TracerouteAsync(target, 25, h =>
        {
            hopTable.Add(h);
            refreshUi();
        }, ct).ConfigureAwait(false);

        if (initial.Count == 0) return;

        var ips = await Dns.GetHostAddressesAsync(target, ct).ConfigureAwait(false);
        var dest = ips.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetwork) ?? ips.First();
        byte[] payload = Encoding.ASCII.GetBytes("NetSnitchMTR");

        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(1000, ct).ConfigureAwait(false);
            using var ping = new Ping();
            foreach (var hop in hopTable.ToList())
            {
                ct.ThrowIfCancellationRequested();
                var opts = new PingOptions(hop.Hop, true);
                var sw = Stopwatch.StartNew();
                var reply = await ping.SendPingAsync(dest, 1000, payload, opts).ConfigureAwait(false);
                sw.Stop();

                hop.Sent++;
                if (reply.Status is IPStatus.Success or IPStatus.TtlExpired && reply.Address != null)
                {
                    if (hop.IpAddress == "*") hop.IpAddress = reply.Address.ToString();
                    double ms = sw.Elapsed.TotalMilliseconds;
                    int okCount = hop.Sent - hop.Lost;
                    hop.LastMs = ms;
                    hop.AvgMs = okCount <= 1 ? ms : ((hop.AvgMs * (okCount - 1)) + ms) / okCount;
                    if (ms < hop.BestMs) hop.BestMs = ms;
                    if (ms > hop.WorstMs) hop.WorstMs = ms;
                }
                else
                {
                    hop.Lost++;
                }
                refreshUi();
            }
        }
    }

    public static async Task<string> WhoisQueryAsync(string target)
    {
        target = target.Trim();
        string raw = await QueryWhoisServerAsync("whois.iana.org", target).ConfigureAwait(false);

        string? refer = raw.Split('\n')
            .Select(l => l.Trim())
            .FirstOrDefault(l => l.StartsWith("refer:", StringComparison.OrdinalIgnoreCase))
            ?.Split(':', 2)[1].Trim();

        if (!string.IsNullOrWhiteSpace(refer))
        {
            string detailed = await QueryWhoisServerAsync(refer, target).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(detailed))
                return $"=== {refer} ===\r\n{detailed}\r\n=== whois.iana.org ===\r\n{raw}";
        }

        return raw;
    }

    private static async Task<string> QueryWhoisServerAsync(string server, string query)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server, 43).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        using var stream = tcp.GetStream();
        byte[] req = Encoding.ASCII.GetBytes(query + "\r\n");
        await stream.WriteAsync(req).ConfigureAwait(false);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
    }

    public static async Task<TlsCertInfo> InspectTlsAsync(string host, int port = 443)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);

        string chainStatus = "Valid";
        X509Certificate2? cert2 = null;

        using var ssl = new SslStream(tcp.GetStream(), false, (_, cert, _, errors) =>
        {
            if (errors != SslPolicyErrors.None)
                chainStatus = errors.ToString();
            if (cert != null)
                cert2 = new X509Certificate2(cert);
            return true;
        });

        await ssl.AuthenticateAsClientAsync(host).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);

        if (cert2 == null && ssl.RemoteCertificate != null)
            cert2 = new X509Certificate2(ssl.RemoteCertificate);

        if (cert2 == null)
            throw new InvalidOperationException("Сервер не предоставил TLS-сертификат.");

        string sans = "";
        foreach (var ext in cert2.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name
                sans = ext.Format(false);
        }

        return new TlsCertInfo
        {
            Host = host,
            Port = port,
            Subject = cert2.Subject,
            Issuer = cert2.Issuer,
            NotBefore = cert2.NotBefore,
            NotAfter = cert2.NotAfter,
            DaysRemaining = (int)(cert2.NotAfter - DateTime.Now).TotalDays,
            Protocol = ssl.SslProtocol.ToString(),
            CipherSuite = ssl.NegotiatedCipherSuite.ToString(),
            Thumbprint = cert2.Thumbprint,
            Sans = sans,
            ChainStatus = chainStatus
        };
    }

    public static async Task<HttpProbeResult> ProbeHttpAsync(string url)
    {
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            url = "https://" + url;
        }

        using var handler = new HttpClientHandler { AllowAutoRedirect = true };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("NetSnitch-Combine/1.0");

        var sw = Stopwatch.StartNew();
        using var resp = await client.GetAsync(url).ConfigureAwait(false);
        string body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
        sw.Stop();

        var sb = new StringBuilder();
        foreach (var h in resp.Headers)
            sb.AppendLine($"{h.Key}: {string.Join(", ", h.Value)}");
        foreach (var h in resp.Content.Headers)
            sb.AppendLine($"{h.Key}: {string.Join(", ", h.Value)}");

        return new HttpProbeResult
        {
            Url = url,
            StatusCode = (int)resp.StatusCode,
            StatusText = resp.ReasonPhrase ?? "",
            ElapsedMs = sw.ElapsedMilliseconds,
            FinalUrl = resp.RequestMessage?.RequestUri?.ToString() ?? url,
            Headers = sb.ToString().TrimEnd(),
            BodyPreview = body.Length > 4000 ? body[..4000] + "\n... [truncated]" : body
        };
    }

    public static async Task SendWakeOnLanAsync(string macAddress)
    {
        string clean = macAddress.Replace(":", "").Replace("-", "").Replace(".", "").Trim();
        if (clean.Length != 12)
            throw new ArgumentException("Некорректный MAC-адрес (нужно 12 hex-символов).");

        byte[] mac = new byte[6];
        for (int i = 0; i < 6; i++)
            mac[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);

        byte[] packet = new byte[6 + 16 * 6];
        for (int i = 0; i < 6; i++) packet[i] = 0xFF;
        for (int i = 1; i <= 16; i++)
            Buffer.BlockCopy(mac, 0, packet, i * 6, 6);

        using var udp = new UdpClient { EnableBroadcast = true };
        await udp.SendAsync(packet, packet.Length, new IPEndPoint(IPAddress.Broadcast, 9)).ConfigureAwait(false);
    }
}
