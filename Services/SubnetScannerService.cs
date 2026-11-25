using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class SubnetScannerService
{
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
        ["3C:22:FB"] = "Apple",
        ["A4:83:E7"] = "Apple",
        ["F0:18:98"] = "Apple",
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
                    var reply = await ping.SendPingAsync(ip, 500).ConfigureAwait(false);
                    if (reply.Status == IPStatus.Success)
                    {
                        alive = true;
                        rtt = reply.RoundtripTime;
                    }
                }
                catch { }

                string? mac = await Task.Run(() => NativeNetworkApi.ResolveMacViaArp(ip), ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(mac)) alive = true;

                if (alive)
                {
                    string hostname = "—";
                    try
                    {
                        var entry = await Dns.GetHostEntryAsync(ip).WaitAsync(TimeSpan.FromMilliseconds(700), ct).ConfigureAwait(false);
                        if (!string.IsNullOrWhiteSpace(entry.HostName) && entry.HostName != ip.ToString())
                            hostname = entry.HostName;
                    }
                    catch { }

                    string vendor = LookupVendor(mac);
                    onHostFound(new SubnetHostEntry
                    {
                        IpAddress = ip.ToString(),
                        Hostname = hostname,
                        MacAddress = mac ?? "—",
                        Vendor = vendor,
                        RttMs = rtt > 0 ? $"{rtt} ms" : "<1 ms",
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
    }

    private static string LookupVendor(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac) || mac.Length < 8) return "—";
        string oui = mac[..8];
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
