using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class DigService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(5) };

    public static readonly string[] RecordTypes =
        ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA"];

    public static ushort MapRecordType(string type) => type.ToUpperInvariant() switch
    {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "CAA" => 257,
        _ => 1
    };

    public static string MapRecordTypeName(ushort code) => code switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        257 => "CAA",
        _ => $"TYPE{code}"
    };

    public static async Task<List<DigRecordEntry>> QueryAsync(string domain, string recordType, string resolver)
    {
        domain = domain.Trim().TrimEnd('.');
        if (recordType.Equals("PTR", StringComparison.OrdinalIgnoreCase) && IPAddress.TryParse(domain, out var ip))
        {
            domain = ip.AddressFamily == AddressFamily.InterNetwork
                ? string.Join('.', ip.GetAddressBytes().Reverse()) + ".in-addr.arpa"
                : string.Join('.', ip.GetAddressBytes().Reverse().SelectMany(b => new[] { $"{b & 0xF:x}", $"{(b >> 4) & 0xF:x}" })) + ".ip6.arpa";
        }

        if (resolver.StartsWith("DoH:", StringComparison.OrdinalIgnoreCase))
            return await QueryDohAsync(domain, recordType, resolver).ConfigureAwait(false);

        return await QueryUdpAsync(domain, recordType, resolver).ConfigureAwait(false);
    }

    public static async Task<List<DigRecordEntry>> CompareResolversAsync(string domain, string recordType)
    {
        string[] resolvers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "77.88.8.8"];
        var tasks = resolvers.Select(r => QueryAsync(domain, recordType, r));
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.SelectMany(x => x).ToList();
    }

    private static async Task<List<DigRecordEntry>> QueryDohAsync(string domain, string recordType, string resolver)
    {
        var list = new List<DigRecordEntry>();
        var sw = Stopwatch.StartNew();
        string url = resolver.Contains("Google", StringComparison.OrdinalIgnoreCase)
            ? $"https://dns.google/resolve?name={Uri.EscapeDataString(domain)}&type={recordType}"
            : $"https://cloudflare-dns.com/dns-query?name={Uri.EscapeDataString(domain)}&type={recordType}";

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("application/dns-json");
        using var resp = await Http.SendAsync(req).ConfigureAwait(false);
        sw.Stop();
        resp.EnsureSuccessStatusCode();

        var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("Answer", out var ans) && ans.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in ans.EnumerateArray())
            {
                string name = item.TryGetProperty("name", out var n) ? (n.GetString() ?? domain) : domain;
                uint ttl = item.TryGetProperty("TTL", out var t) ? t.GetUInt32() : 0;
                ushort rtype = item.TryGetProperty("type", out var tp) ? tp.GetUInt16() : (ushort)1;
                string data = item.TryGetProperty("data", out var d) ? (d.GetString() ?? "") : "";
                list.Add(new DigRecordEntry
                {
                    Resolver = resolver,
                    Name = name.TrimEnd('.'),
                    RecordType = MapRecordTypeName(rtype),
                    Ttl = ttl,
                    Value = data,
                    QueryTimeMs = sw.ElapsedMilliseconds
                });
            }
        }
        return list;
    }

    private static async Task<List<DigRecordEntry>> QueryUdpAsync(string domain, string recordType, string dnsServer)
    {
        var list = new List<DigRecordEntry>();
        ushort qtype = MapRecordType(recordType);
        byte[] query = BuildDnsQuery(domain, qtype);

        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = 3500;
        var sw = Stopwatch.StartNew();
        await udp.SendAsync(query, query.Length, dnsServer, 53).ConfigureAwait(false);

        using var cts = new CancellationTokenSource(3500);
        var res = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
        sw.Stop();

        byte[] buf = res.Buffer;
        if (buf.Length < 12) return list;

        int qdCount = (buf[4] << 8) | buf[5];
        int anCount = (buf[6] << 8) | buf[7];
        int offset = 12;

        for (int i = 0; i < qdCount; i++)
        {
            _ = ReadDnsName(buf, ref offset);
            offset += 4; // QTYPE + QCLASS
        }

        for (int i = 0; i < anCount && offset < buf.Length; i++)
        {
            string name = ReadDnsName(buf, ref offset);
            if (offset + 10 > buf.Length) break;

            ushort type = (ushort)((buf[offset] << 8) | buf[offset + 1]);
            uint ttl = (uint)((buf[offset + 4] << 24) | (buf[offset + 5] << 16) | (buf[offset + 6] << 8) | buf[offset + 7]);
            ushort rdlen = (ushort)((buf[offset + 8] << 8) | buf[offset + 9]);
            offset += 10;

            if (offset + rdlen > buf.Length) break;
            string value = ParseRdata(buf, offset, rdlen, type);
            offset += rdlen;

            list.Add(new DigRecordEntry
            {
                Resolver = dnsServer,
                Name = name,
                RecordType = MapRecordTypeName(type),
                Ttl = ttl,
                Value = value,
                QueryTimeMs = sw.ElapsedMilliseconds
            });
        }

        return list;
    }

    private static byte[] BuildDnsQuery(string domain, ushort qtype)
    {
        using var ms = new MemoryStream();
        ushort id = (ushort)Random.Shared.Next(1, 65535);
        ms.WriteByte((byte)(id >> 8));
        ms.WriteByte((byte)(id & 0xFF));
        // Flags: RD=1
        ms.Write([0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        foreach (var label in domain.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            byte[] lb = Encoding.UTF8.GetBytes(label);
            ms.WriteByte((byte)lb.Length);
            ms.Write(lb);
        }
        ms.WriteByte(0); // Root

        ms.WriteByte((byte)(qtype >> 8));
        ms.WriteByte((byte)(qtype & 0xFF));
        ms.Write([0x00, 0x01]); // IN class
        return ms.ToArray();
    }

    private static string ReadDnsName(byte[] buf, ref int offset)
    {
        var sb = new StringBuilder();
        int origOffset = offset;
        bool jumped = false;
        int safety = 0;

        while (offset < buf.Length && safety++ < 64)
        {
            byte len = buf[offset];
            if (len == 0)
            {
                if (!jumped) offset++;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                int ptr = ((len & 0x3F) << 8) | buf[offset + 1];
                if (!jumped) origOffset = offset + 2;
                jumped = true;
                offset = ptr;
            }
            else
            {
                offset++;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.UTF8.GetString(buf, offset, len));
                offset += len;
            }
        }

        if (jumped) offset = origOffset;
        return sb.Length == 0 ? "." : sb.ToString();
    }

    private static string ParseRdata(byte[] buf, int offset, int rdlen, ushort type)
    {
        int tmp = offset;
        return type switch
        {
            1 when rdlen == 4 => new IPAddress(buf.AsSpan(offset, 4)).ToString(),
            28 when rdlen == 16 => new IPAddress(buf.AsSpan(offset, 16)).ToString(),
            2 or 5 or 12 => ReadDnsName(buf, ref tmp),
            15 when rdlen >= 3 => $"{(buf[offset] << 8) | buf[offset + 1]} {ReadDnsNameAt(buf, offset + 2)}",
            16 => ParseTxt(buf, offset, rdlen),
            6 => ParseSoa(buf, offset),
            33 when rdlen >= 7 => $"{(buf[offset] << 8) | buf[offset + 1]} {(buf[offset + 2] << 8) | buf[offset + 3]} {(buf[offset + 4] << 8) | buf[offset + 5]} {ReadDnsNameAt(buf, offset + 6)}",
            257 when rdlen >= 2 => ParseCaa(buf, offset, rdlen),
            _ => BitConverter.ToString(buf, offset, rdlen)
        };
    }

    private static string ReadDnsNameAt(byte[] buf, int pos) => ReadDnsName(buf, ref pos);

    private static string ParseTxt(byte[] buf, int offset, int rdlen)
    {
        var sb = new StringBuilder();
        int end = offset + rdlen;
        while (offset < end)
        {
            int len = buf[offset++];
            int take = Math.Min(len, end - offset);
            sb.Append(Encoding.UTF8.GetString(buf, offset, take));
            offset += take;
        }
        return $"\"{sb}\"";
    }

    private static string ParseSoa(byte[] buf, int offset)
    {
        string mname = ReadDnsName(buf, ref offset);
        string rname = ReadDnsName(buf, ref offset);
        if (offset + 20 > buf.Length) return $"{mname} {rname}";
        uint serial = (uint)((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]);
        return $"{mname} {rname} (serial {serial})";
    }

    private static string ParseCaa(byte[] buf, int offset, int rdlen)
    {
        byte flags = buf[offset];
        byte tagLen = buf[offset + 1];
        string tag = Encoding.ASCII.GetString(buf, offset + 2, Math.Min(tagLen, rdlen - 2));
        int valStart = offset + 2 + tagLen;
        int valLen = Math.Max(0, offset + rdlen - valStart);
        string val = Encoding.UTF8.GetString(buf, valStart, valLen);
        return $"{flags} {tag} \"{val}\"";
    }
}
