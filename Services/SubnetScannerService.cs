using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class SubnetScannerService
{
    private static readonly HashSet<string> AppleOuis = new(StringComparer.OrdinalIgnoreCase)
    {
        "00:03:93", "00:05:02", "00:0A:27", "00:0A:95", "00:0D:93", "00:10:FA", "00:11:24", "00:14:51",
        "00:16:CB", "00:17:F2", "00:19:E3", "00:1B:63", "00:1C:B3", "00:1D:4F", "00:1E:52", "00:1E:C2",
        "00:1F:5B", "00:1F:F3", "00:21:E9", "00:22:41", "00:23:12", "00:23:32", "00:23:6C", "00:23:DF",
        "00:24:36", "00:25:00", "00:25:4B", "00:25:BC", "00:26:08", "00:26:4A", "00:26:B0", "00:26:BB",
        "00:30:65", "00:3E:E1", "00:50:E4", "00:56:CD", "00:61:71", "00:6D:52", "00:88:65", "00:B3:62",
        "00:C6:10", "00:CD:FE", "00:DB:70", "00:F4:B9", "00:F7:6F", "04:0C:CE", "04:15:52", "04:26:65",
        "04:4B:ED", "04:54:53", "04:DB:56", "04:E5:36", "04:F1:3E", "04:F7:E4", "08:00:07", "08:66:98",
        "08:6D:41", "08:70:45", "08:F4:AB", "0C:30:21", "0C:3E:9F", "0C:4D:E9", "0C:51:01", "0C:74:C2",
        "0C:BC:9F", "10:1C:0C", "10:40:F3", "10:41:7F", "10:9A:DD", "10:DD:B1", "14:10:9F", "14:20:5E",
        "14:5A:05", "14:8F:C6", "14:99:E2", "18:20:32", "18:34:51", "18:65:90", "18:9E:FC", "18:AF:61",
        "18:AF:8F", "18:E7:F4", "18:F6:43", "1C:1A:C0", "1C:36:BB", "1C:5C:F2", "1C:91:48", "1C:AB:A7",
        "20:3C:AE", "20:78:F0", "20:A2:E4", "20:C9:D0", "24:1E:EB", "24:24:0E", "24:A0:74", "24:A2:E1",
        "24:AB:81", "24:F0:94", "28:0B:5C", "28:37:37", "28:5A:EB", "28:6A:B8", "28:6A:BA", "28:CF:DA",
        "28:CF:E9", "28:E0:2C", "28:E1:4C", "28:ED:6A", "28:F0:76", "2C:1F:23", "2C:33:61", "2C:B4:3A",
        "2C:BE:08", "2C:F0:EE", "30:10:E4", "30:35:AD", "30:63:6B", "30:90:AB", "30:F7:C5", "34:08:BC",
        "34:12:98", "34:15:9E", "34:36:3B", "34:51:C9", "34:A3:95", "34:AB:37", "34:C0:59", "34:E2:FD",
        "38:0F:4A", "38:48:4C", "38:66:F0", "38:71:DE", "38:89:2C", "38:B5:4D", "38:C9:86", "38:CA:DA",
        "3C:07:54", "3C:15:C2", "3C:22:FB", "3C:D0:F8", "40:30:04", "40:33:1A", "40:3C:FC", "40:4D:7F",
        "40:6C:8F", "40:83:1D", "40:98:AD", "40:A6:D9", "40:B3:95", "40:CB:C0", "40:D3:2D", "44:00:10",
        "44:2A:60", "44:4C:0C", "44:D8:84", "44:FB:42", "48:43:7C", "48:60:BC", "48:74:6E", "48:A1:95",
        "48:BF:6B", "48:D7:05", "48:E9:F1", "4C:32:75", "4C:57:CA", "4C:74:BF", "4C:7C:5F", "4C:8D:79",
        "50:32:37", "50:7A:55", "50:82:D5", "50:EA:D6", "54:26:96", "54:4E:90", "54:72:4F", "54:9F:13",
        "54:AE:27", "54:E4:3A", "54:EA:A8", "58:1F:AA", "58:40:4E", "58:55:CA", "58:B0:35", "5C:59:48",
        "5C:8D:4E", "5C:95:AE", "5C:96:9D", "5C:97:F3", "5C:F5:DA", "5C:F9:38", "60:03:08", "60:33:4B",
        "60:69:44", "60:8C:4A", "60:92:17", "60:C5:47", "60:D9:C7", "60:F4:45", "60:F8:1D", "60:FA:CD",
        "60:FB:42", "60:FE:C5", "64:20:0C", "64:76:BA", "64:9A:BE", "64:A3:CB", "64:B0:A6", "64:E6:82",
        "68:09:27", "68:5B:35", "68:64:4B", "68:96:7B", "68:9C:70", "68:A8:6D", "68:AB:1E", "68:AE:20",
        "68:D9:3C", "68:DB:CA", "68:EF:43", "68:FB:7E", "6C:19:C0", "6C:3E:6D", "6C:40:08", "6C:4D:73",
        "6C:70:9F", "6C:72:E7", "6C:8D:C1", "6C:94:F8", "6C:96:CF", "6C:AB:31", "6C:C2:6B", "70:11:24",
        "70:14:A6", "70:3E:AC", "70:48:0F", "70:56:81", "70:73:CB", "70:81:EB", "70:A2:B3", "70:CD:60",
        "70:DE:E2", "70:E7:2C", "70:EC:E4", "70:EF:00", "70:F0:87", "74:1B:B2", "74:81:14", "74:8D:08",
        "74:E1:B6", "74:E2:F5", "78:31:C1", "78:3A:84", "78:4F:43", "78:67:D7", "78:6C:1C", "78:7B:8A",
        "78:88:6D", "78:9F:70", "78:A3:E4", "78:CA:39", "78:D7:5F", "78:FD:94", "7C:01:91", "7C:04:D0",
        "7C:11:BE", "7C:50:49", "7C:6D:62", "7C:6D:F8", "7C:C3:A1", "7C:C5:37", "7C:D1:C3", "7C:E9:D3",
        "7C:F0:5F", "7C:FA:DF", "80:00:6E", "80:49:71", "80:82:23", "80:92:9F", "80:B0:3D", "80:BE:05",
        "80:D6:05", "80:E6:50", "80:EA:96", "80:ED:2C", "84:29:99", "84:38:35", "84:78:8B", "84:85:06",
        "84:89:AD", "84:8E:0C", "84:A1:34", "84:B1:53", "84:FC:FE", "88:19:08", "88:1F:A1", "88:53:95",
        "88:63:DF", "88:66:5A", "88:6B:6E", "88:C6:63", "88:CB:87", "88:E8:7F", "8C:00:6D", "8C:29:37",
        "8C:2D:AA", "8C:58:77", "8C:7B:9D", "8C:7C:92", "8C:85:90", "8C:8E:F2", "8C:FA:BA", "90:27:E4",
        "90:3C:92", "90:60:F1", "90:72:40", "90:84:0D", "90:8D:6C", "90:B0:ED", "90:B2:1F", "90:B9:31",
        "90:FD:61", "94:94:26", "94:BF:2D", "94:E9:6A", "94:F6:A3", "98:01:A7", "98:03:D8", "98:10:E8",
        "98:5A:EB", "98:9E:63", "98:B8:E3", "98:CA:33", "98:D6:BB", "98:E0:D9", "98:F0:AB", "98:FE:94",
        "9C:04:EB", "9C:20:7B", "9C:29:3F", "9C:35:EB", "9C:4F:DA", "9C:84:BF", "9C:8B:A0", "9C:F3:87",
        "9C:F4:8E", "A0:18:28", "A0:3B:E3", "A0:4E:A7", "A0:99:9B", "A0:D7:95", "A0:ED:CD", "A4:31:35",
        "A4:5E:60", "A4:67:06", "A4:83:E7", "A4:B1:97", "A4:B8:05", "A4:C3:61", "A4:D1:8C", "A4:D1:D2",
        "A4:E9:75", "A4:F1:E8", "A8:20:66", "A8:5B:78", "A8:5C:2C", "A8:66:7F", "A8:86:DD", "A8:88:08",
        "A8:8E:24", "A8:96:8A", "A8:BB:CF", "A8:FA:D8", "AC:1F:74", "AC:29:3A", "AC:3C:0B", "AC:61:EA",
        "AC:7F:3E", "AC:87:A3", "AC:BC:32", "AC:CF:5C", "AC:E4:B5", "AC:FD:EC", "B0:19:C6", "B0:34:95",
        "B0:48:1A", "B0:65:BD", "B0:70:2D", "B0:9F:BA", "B0:CA:68", "B4:18:D1", "B4:4B:D2", "B4:8B:19",
        "B4:9C:DF", "B4:F0:AB", "B4:F6:1C", "B8:09:8A", "B8:17:C2", "B8:41:A4", "B8:44:D9", "B8:53:AC",
        "B8:63:4D", "B8:78:2E", "B8:8D:12", "B8:C1:11", "B8:C7:5D", "B8:E8:56", "B8:F6:B1", "B8:FF:61",
        "BC:3B:AF", "BC:4C:C4", "BC:52:B7", "BC:54:36", "BC:67:78", "BC:6C:21", "BC:92:6B", "BC:9F:EF",
        "BC:EC:5D", "BC:FE:D9", "C0:1A:DA", "C0:63:94", "C0:84:7A", "C0:9F:42", "C0:A5:3E", "C0:B6:58",
        "C0:CC:F8", "C0:CE:CD", "C0:D0:12", "C0:F2:FB", "C4:2C:03", "C4:61:8B", "C4:84:66", "C4:98:80",
        "C4:B3:01", "C8:1E:E7", "C8:2A:14", "C8:33:4B", "C8:3C:85", "C8:69:CD", "C8:6F:1D", "C8:85:50",
        "C8:B5:B7", "C8:BC:C8", "C8:D0:83", "C8:E0:EB", "C8:F6:50", "CC:08:8D", "CC:08:E0", "CC:20:E8",
        "CC:25:EF", "CC:29:F5", "CC:44:63", "CC:78:5F", "CC:C7:60", "D0:03:4B", "D0:23:DB", "D0:25:98",
        "D0:33:11", "D0:4F:7E", "D0:81:7A", "D0:A6:37", "D0:C5:F3", "D0:D2:B0", "D0:E1:40", "D4:61:9D",
        "D4:9A:20", "D4:A3:3D", "D4:DC:CD", "D4:F4:6F", "D8:00:4D", "D8:1D:72", "D8:30:62", "D8:8F:76",
        "D8:96:95", "D8:9E:3F", "D8:A2:5E", "D8:BB:2C", "D8:CF:9C", "DC:0C:5C", "DC:2B:2A", "DC:2B:61",
        "DC:37:14", "DC:41:5F", "DC:56:E7", "DC:86:D8", "DC:9B:9C", "DC:A4:CA", "DC:A9:04", "E0:33:8E",
        "E0:5F:45", "E0:66:78", "E0:AC:CB", "E0:B5:2D", "E0:B9:BA", "E0:C7:67", "E0:C9:7A", "E0:F5:C6",
        "E0:F8:47", "E4:25:E7", "E4:8B:7F", "E4:98:D6", "E4:9A:79", "E4:C6:3D", "E4:CE:8F", "E4:E0:A6",
        "E4:E4:AB", "E8:04:0B", "E8:06:88", "E8:80:2E", "E8:8D:28", "EC:35:86", "EC:85:2F", "F0:18:98",
        "F0:24:75", "F0:79:60", "F0:98:9D", "F0:99:BF", "F0:B0:E7", "F0:B4:79", "F0:C1:F1", "F0:CB:A1",
        "F0:D1:A9", "F0:DB:E2", "F0:DB:F8", "F0:DC:E2", "F0:F6:1C", "F4:0F:24", "F4:1B:A1", "F4:31:C3",
        "F4:37:B7", "F4:5C:89", "F4:F1:5A", "F4:F9:51", "F8:03:77", "F8:1E:DF", "F8:27:93", "F8:38:80",
        "F8:4D:89", "F8:62:14", "F8:6F:C1", "F8:95:EA", "FC:25:3F", "FC:D8:48", "FC:E9:98", "FC:FC:48"
    };

    private static readonly Dictionary<string, string> OuiVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["00:50:56"] = "VMware",
        ["00:0C:29"] = "VMware",
        ["00:15:5D"] = "Microsoft Hyper-V",
        ["08:00:27"] = "Oracle VirtualBox",
        ["B8:27:EB"] = "Raspberry Pi",
        ["DC:A6:32"] = "Raspberry Pi",
        ["E4:5F:01"] = "Raspberry Pi",
        ["18:E8:29"] = "Ubiquiti",
        ["74:83:C2"] = "Ubiquiti",
        ["FC:EC:DA"] = "Ubiquiti",
        ["4C:5E:0C"] = "MikroTik",
        ["D4:CA:6D"] = "MikroTik",
        ["C4:AD:34"] = "MikroTik",
        ["50:C7:BF"] = "TP-Link",
        ["C0:25:E9"] = "TP-Link",
        ["B0:BE:76"] = "TP-Link",
        ["04:D4:C4"] = "ASUSTek",
        ["1C:87:2C"] = "ASUSTek",
        ["AC:9E:17"] = "ASUSTek",
        ["3C:D9:2B"] = "HP",
        ["D4:3D:7E"] = "Micro-Star (MSI)",
        ["00:1B:21"] = "Intel",
        ["8C:8D:28"] = "Intel",
        ["A4:4C:C8"] = "Dell",
        ["F8:BC:12"] = "Dell",
        ["64:1C:AE"] = "Samsung",
        ["28:6C:07"] = "Xiaomi",
        ["64:09:80"] = "Xiaomi",
        ["00:E0:4C"] = "Realtek",
        ["52:54:00"] = "QEMU / KVM"
    };

    public static List<string> GetLocalSubnets()
    {
        var list = new List<string>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up ||
                ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                int prefix = ua.PrefixLength;
                if (prefix <= 0 || prefix > 30) prefix = 24;
                uint ipInt = IpToUint(ua.Address);
                uint mask = 0xFFFFFFFF << (32 - prefix);
                uint net = ipInt & mask;
                list.Add($"{UintToIp(net)}/{prefix}");
            }
        }
        return list.Distinct().ToList();
    }

    public static List<IPAddress> ExpandCidr(string cidr, int maxHosts = 4096)
    {
        var parts = cidr.Trim().Split('/');
        if (!IPAddress.TryParse(parts[0], out var baseIp) || baseIp.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Некорректный IPv4 адрес или CIDR.");

        int prefix = 24;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 16 || prefix > 32))
            throw new ArgumentException("Поддерживаются маски от /16 до /32.");

        uint ipInt = IpToUint(baseIp);
        uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
        uint net = ipInt & mask;
        uint bcast = net | ~mask;

        var ips = new List<IPAddress>();
        uint start = prefix >= 31 ? net : net + 1;
        uint end = prefix >= 31 ? bcast : bcast - 1;

        for (uint cur = start; cur <= end && ips.Count < maxHosts; cur++)
            ips.Add(UintToIp(cur));

        return ips;
    }

    public static async Task ScanSubnetAsync(
        string cidr,
        Action<SubnetHostEntry> onHostFound,
        Action<int, int> onProgress,
        CancellationToken ct)
    {
        // Run mDNS discovery in background to catch Mac / Bonjour devices
        var mdnsMap = new ConcurrentDictionary<string, string>();
        var mdnsTask = DiscoverMdnsModelsAsync(mdnsMap, ct);

        var targets = ExpandCidr(cidr);
        int total = targets.Count;
        int done = 0;
        using var gate = new SemaphoreSlim(64, 64);

        var tasks = targets.Select(async ip =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                bool alive = false;
                long rtt = 0;

                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(ip, 600).ConfigureAwait(false);
                    if (reply.Status == IPStatus.Success)
                    {
                        alive = true;
                        rtt = reply.RoundtripTime;
                    }
                }
                catch { }

                string? mac = await Task.Run(() => NativeNetworkApi.ResolveMacViaArp(ip), ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(mac)) alive = true;

                // Fallback TCP discovery for hosts with ICMP blocked (e.g., macOS Stealth Mode or routed VLAN/VPN)
                if (!alive)
                {
                    int[] probePorts = [22, 5900, 548, 3283, 445, 80, 443];
                    var probeTasks = probePorts.Select(p => IsPortOpenAsync(ip.ToString(), p, 400, ct));
                    var probeResults = await Task.WhenAll(probeTasks).ConfigureAwait(false);
                    if (probeResults.Any(open => open))
                        alive = true;
                }

                if (alive)
                {
                    string ipStr = ip.ToString();
                    string hostname = "—";
                    try
                    {
                        var entry = await Dns.GetHostEntryAsync(ip).WaitAsync(TimeSpan.FromMilliseconds(700), ct).ConfigureAwait(false);
                        if (!string.IsNullOrWhiteSpace(entry.HostName) && entry.HostName != ipStr)
                            hostname = entry.HostName;
                    }
                    catch { }

                    if (hostname == "—")
                    {
                        string? mdnsName = await QueryUnicastMdnsPtrAsync(ip, ct).ConfigureAwait(false);
                        if (!string.IsNullOrWhiteSpace(mdnsName))
                            hostname = mdnsName;
                    }

                    string vendor = LookupVendor(mac);
                    mdnsMap.TryGetValue(ipStr, out var mdnsHint);

                    var (deviceType, isApple, isMac) = await ClassifyDeviceAsync(ipStr, hostname, vendor, mdnsHint, ct).ConfigureAwait(false);

                    onHostFound(new SubnetHostEntry
                    {
                        IpAddress = ipStr,
                        Hostname = hostname,
                        MacAddress = mac ?? "—",
                        Vendor = vendor,
                        DeviceType = deviceType,
                        IsApple = isApple,
                        IsMac = isMac,
                        RttMs = rtt > 0 ? $"{rtt} ms" : "TCP",
                        Status = "Online"
                    });
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
        try { await mdnsTask.ConfigureAwait(false); } catch { }
    }

    private static async Task<(string DeviceType, bool IsApple, bool IsMac)> ClassifyDeviceAsync(
        string ip, string hostname, string vendor, string? mdnsHint, CancellationToken ct)
    {
        bool appleOui = vendor == "Apple";
        bool macNameHint = hostname.Contains("mac", StringComparison.OrdinalIgnoreCase) ||
                           hostname.Contains("imac", StringComparison.OrdinalIgnoreCase) ||
                           hostname.Contains("macbook", StringComparison.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(mdnsHint))
        {
            if (mdnsHint.Contains("Mac", StringComparison.OrdinalIgnoreCase))
                return ($"🍎 Mac ({mdnsHint})", true, true);
            if (mdnsHint.Contains("iPhone", StringComparison.OrdinalIgnoreCase) ||
                mdnsHint.Contains("iPad", StringComparison.OrdinalIgnoreCase))
                return ($"📱 Apple ({mdnsHint})", true, false);
            return ($"🍎 Apple ({mdnsHint})", true, false);
        }

        // Probe key OS-identifying ports in parallel (works even across routed subnets without ARP/OUI)
        var t62078 = IsPortOpenAsync(ip, 62078, 250, ct); // iOS Lockdown
        var t548 = IsPortOpenAsync(ip, 548, 250, ct);     // Apple Filing Protocol (AFP)
        var t3283 = IsPortOpenAsync(ip, 3283, 250, ct);   // Apple Remote Desktop
        var t5900 = IsPortOpenAsync(ip, 5900, 250, ct);   // Apple Screen Sharing / VNC
        var t3389 = IsPortOpenAsync(ip, 3389, 200, ct);   // Windows RDP
        var t445 = IsPortOpenAsync(ip, 445, 200, ct);     // SMB
        var t22 = IsPortOpenAsync(ip, 22, 200, ct);       // SSH
        await Task.WhenAll(t62078, t548, t3283, t5900, t3389, t445, t22).ConfigureAwait(false);

        if (t62078.Result)
            return ("📱 iPhone / iPad (iOS)", true, false);

        if (t548.Result || t3283.Result)
            return ("🍎 Mac (macOS)", true, true);

        if (t5900.Result && (appleOui || macNameHint || hostname.EndsWith(".local", StringComparison.OrdinalIgnoreCase) || !t3389.Result))
            return ("🍎 Mac (macOS / Screen Sharing)", true, true);

        if (appleOui || macNameHint || hostname.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
            return ("🍎 Mac (macOS)", true, true);

        if (vendor is "MikroTik" or "Ubiquiti" or "TP-Link" or "ASUSTek")
            return ("🌐 Сетевое устройство", false, false);

        if (t3389.Result || t445.Result)
            return ("🪟 Windows / SMB", false, false);

        if (t22.Result)
            return ("🐧 Linux / Unix (SSH)", false, false);

        return ("💻 Устройство", false, false);
    }

    private static async Task<string?> QueryUnicastMdnsPtrAsync(IPAddress ip, CancellationToken ct)
    {
        try
        {
            string rev = string.Join('.', ip.GetAddressBytes().Reverse()) + ".in-addr.arpa";
            byte[] query = BuildMdnsPtrQuery(rev);
            using var udp = new UdpClient();
            await udp.SendAsync(query, query.Length, new IPEndPoint(ip, 5353)).ConfigureAwait(false);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(300);
            var res = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
            string ascii = Encoding.ASCII.GetString(res.Buffer);
            var m = Regex.Match(ascii, @"([A-Za-z0-9_-]+\.local)");
            return m.Success ? m.Groups[1].Value : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<bool> IsPortOpenAsync(string ip, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await tcp.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task DiscoverMdnsModelsAsync(ConcurrentDictionary<string, string> mdnsMap, CancellationToken ct)
    {
        try
        {
            using var udp = new UdpClient();
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.ReceiveTimeout = 1200;

            byte[] query = BuildMdnsPtrQuery("_device-info._tcp.local");
            await udp.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353)).ConfigureAwait(false);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(1500);
            while (!cts.IsCancellationRequested)
            {
                var res = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                string ascii = Encoding.ASCII.GetString(res.Buffer);
                var m = Regex.Match(ascii, @"model=([A-Za-z0-9,_-]+)");
                if (m.Success)
                {
                    mdnsMap[res.RemoteEndPoint.Address.ToString()] = m.Groups[1].Value;
                }
            }
        }
        catch { }
    }

    private static byte[] BuildMdnsPtrQuery(string service)
    {
        using var ms = new System.IO.MemoryStream();
        ms.Write([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        foreach (var label in service.Split('.'))
        {
            var lb = Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)lb.Length);
            ms.Write(lb);
        }
        ms.Write([0x00, 0x00, 0x0C, 0x00, 0x01]); // PTR IN
        return ms.ToArray();
    }

    private static string LookupVendor(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac) || mac.Length < 8) return "—";
        string oui = mac[..8];
        if (AppleOuis.Contains(oui)) return "Apple";
        return OuiVendors.TryGetValue(oui, out var v) ? v : "—";
    }

    private static uint IpToUint(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static IPAddress UintToIp(uint val) =>
        new([(byte)(val >> 24), (byte)(val >> 16), (byte)(val >> 8), (byte)val]);
}
