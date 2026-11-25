using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class GeoIpService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(4) };
    private static readonly ConcurrentDictionary<string, GeoAsnInfo> Cache = new();
    private static readonly SemaphoreSlim RateGate = new(4, 4);

    public static bool IsPrivateOrSpecial(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var ip)) return true;
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            byte[] b = ip.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 0 || b[0] >= 224) return true;
        }
        else if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast)
        {
            return true;
        }
        return false;
    }

    public static async Task<GeoAsnInfo> LookupAsync(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || ip == "*")
            return new GeoAsnInfo { Ip = ip, Org = "—" };

        if (Cache.TryGetValue(ip, out var cached))
            return cached;

        if (IsPrivateOrSpecial(ip))
        {
            var local = new GeoAsnInfo { Ip = ip, Org = "Локальная сеть", CountryCode = "LAN" };
            Cache[ip] = local;
            return local;
        }

        await RateGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (Cache.TryGetValue(ip, out cached))
                return cached;

            using var resp = await Http.GetAsync($"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org,as").ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("status", out var st) && st.GetString() == "success")
                {
                    string cc = root.TryGetProperty("countryCode", out var c) ? (c.GetString() ?? "") : "";
                    string org = root.TryGetProperty("org", out var o) ? (o.GetString() ?? "") : "";
                    if (string.IsNullOrWhiteSpace(org) && root.TryGetProperty("isp", out var isp))
                        org = isp.GetString() ?? "";

                    var info = new GeoAsnInfo { Ip = ip, CountryCode = cc, Org = org };
                    Cache[ip] = info;
                    return info;
                }
            }
        }
        catch
        {
            // Fallback silently on offline/rate-limit
        }
        finally
        {
            RateGate.Release();
        }

        var fallback = new GeoAsnInfo { Ip = ip, Org = "—" };
        Cache[ip] = fallback;
        return fallback;
    }
}
