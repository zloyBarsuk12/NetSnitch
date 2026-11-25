using System.Collections.Concurrent;
using System.Net;
using NetSnitch.Models;

namespace NetSnitch.Services;

public class TrafficSnapshot
{
    public List<ConnectionEntry> Connections { get; init; } = [];
    public List<ProcessSummary> Processes { get; init; } = [];
    public List<TrafficEventEntry> NewEvents { get; init; } = [];
    public List<DnsLogEntry> NewDnsLogs { get; init; } = [];
    public int TotalHosts { get; init; }
    public int TotalEvents { get; init; }
}

public class TrafficMonitorService
{
    private readonly ConcurrentDictionary<string, ConnectionEntry> _connections = new();
    private readonly ConcurrentDictionary<string, string> _reverseDnsCache = new();
    private readonly ConcurrentDictionary<int, (string Name, string Path)> _procCache = new();
    private readonly HashSet<string> _activeKeysLastTick = new();
    private int _totalEvents;

    public bool IsPaused { get; set; }

    public void Clear()
    {
        _connections.Clear();
        _activeKeysLastTick.Clear();
        _totalEvents = 0;
    }

    public TrafficSnapshot Poll()
    {
        if (IsPaused)
        {
            return BuildSnapshot([], []);
        }

        var rawRows = NativeNetworkApi.GetAllSockets();
        var currentActiveKeys = new HashSet<string>();
        var newEvents = new List<TrafficEventEntry>();
        var newDnsLogs = new List<DnsLogEntry>();
        string now = DateTime.Now.ToString("HH:mm:ss");

        foreach (var row in rawRows)
        {
            if (row.State == "LISTEN" || row.RemoteIp is "*" or "0.0.0.0" or "::")
                continue;

            var procInfo = _procCache.GetOrAdd(row.Pid, NativeNetworkApi.GetProcessInfo);
            string key = $"{procInfo.Name}|{row.Protocol}|{row.RemoteIp}|{row.RemotePort}";
            currentActiveKeys.Add(key);

            if (_connections.TryGetValue(key, out var existing))
            {
                bool wasClosed = existing.Status == "CLOSED";
                existing.Status = row.State;
                existing.LastSeen = now;
                if (!_activeKeysLastTick.Contains(key) || wasClosed)
                {
                    existing.Hits++;
                    _totalEvents++;
                    newEvents.Add(new TrafficEventEntry
                    {
                        Time = now,
                        ProcessName = procInfo.Name,
                        Pid = row.Pid,
                        Protocol = row.Protocol,
                        RemoteEndpoint = $"{row.RemoteIp}:{row.RemotePort}",
                        Domain = existing.Domain,
                        EventType = "HIT",
                        Organization = existing.Organization
                    });
                }
            }
            else
            {
                var entry = new ConnectionEntry
                {
                    Key = key,
                    Pid = row.Pid,
                    ProcessName = procInfo.Name,
                    RemoteIp = row.RemoteIp,
                    RemotePort = row.RemotePort,
                    LocalPort = row.LocalPort,
                    Protocol = row.Protocol,
                    Status = row.State,
                    Hits = 1,
                    LastSeen = now
                };
                _connections[key] = entry;
                _totalEvents++;

                newEvents.Add(new TrafficEventEntry
                {
                    Time = now,
                    ProcessName = procInfo.Name,
                    Pid = row.Pid,
                    Protocol = row.Protocol,
                    RemoteEndpoint = $"{row.RemoteIp}:{row.RemotePort}",
                    Domain = "—",
                    EventType = "NEW",
                    Organization = "—"
                });

                // Enrich asynchronously (PTR + GeoIP)
                _ = EnrichConnectionAsync(entry, newDnsLogs, now);
            }
        }

        foreach (var kv in _connections)
        {
            if (!currentActiveKeys.Contains(kv.Key) && kv.Value.Status != "CLOSED")
            {
                kv.Value.Status = "CLOSED";
            }
        }

        _activeKeysLastTick.Clear();
        foreach (var k in currentActiveKeys) _activeKeysLastTick.Add(k);

        return BuildSnapshot(newEvents, newDnsLogs);
    }

    private async Task EnrichConnectionAsync(ConnectionEntry entry, List<DnsLogEntry> dnsLogs, string time)
    {
        var geoTask = GeoIpService.LookupAsync(entry.RemoteIp);
        var dnsTask = ResolvePtrAsync(entry.RemoteIp);
        await Task.WhenAll(geoTask, dnsTask).ConfigureAwait(false);

        var geo = geoTask.Result;
        var ptr = dnsTask.Result;

        entry.Organization = geo.Display;
        if (!string.IsNullOrWhiteSpace(ptr))
        {
            entry.Domain = ptr;
            lock (dnsLogs)
            {
                dnsLogs.Add(new DnsLogEntry
                {
                    Time = time,
                    Domain = ptr,
                    ResolvedIp = entry.RemoteIp,
                    ProcessName = entry.ProcessName,
                    Source = "Reverse PTR"
                });
            }
        }
    }

    private async Task<string> ResolvePtrAsync(string ip)
    {
        if (_reverseDnsCache.TryGetValue(ip, out var cached)) return cached;
        if (GeoIpService.IsPrivateOrSpecial(ip))
        {
            _reverseDnsCache[ip] = "—";
            return "—";
        }

        try
        {
            var host = await Dns.GetHostEntryAsync(ip).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            string name = string.IsNullOrWhiteSpace(host.HostName) || host.HostName == ip ? "—" : host.HostName;
            _reverseDnsCache[ip] = name;
            return name;
        }
        catch
        {
            _reverseDnsCache[ip] = "—";
            return "—";
        }
    }

    private TrafficSnapshot BuildSnapshot(List<TrafficEventEntry> newEvents, List<DnsLogEntry> newDnsLogs)
    {
        var allConns = _connections.Values
            .OrderByDescending(c => c.Status == "ESTABLISHED")
            .ThenByDescending(c => c.LastSeen)
            .ToList();

        var procGroups = allConns
            .GroupBy(c => c.ProcessName)
            .Select(g => new ProcessSummary
            {
                ProcessName = g.Key,
                PidCount = g.Select(x => x.Pid).Distinct().Count(),
                HostCount = g.Select(x => x.RemoteIp).Distinct().Count(),
                HitCount = g.Sum(x => x.Hits)
            })
            .OrderByDescending(p => p.HitCount)
            .ToList();

        return new TrafficSnapshot
        {
            Connections = allConns,
            Processes = procGroups,
            NewEvents = newEvents,
            NewDnsLogs = newDnsLogs,
            TotalHosts = allConns.Select(c => c.RemoteIp).Distinct().Count(),
            TotalEvents = _totalEvents
        };
    }

    public static List<ListeningPortEntry> GetListeningPorts()
    {
        var sockets = NativeNetworkApi.GetAllSockets();
        var procCache = new Dictionary<int, (string Name, string Path)>();
        var list = new List<ListeningPortEntry>();

        foreach (var s in sockets)
        {
            if (s.State != "LISTEN") continue;
            if (!procCache.TryGetValue(s.Pid, out var info))
            {
                info = NativeNetworkApi.GetProcessInfo(s.Pid);
                procCache[s.Pid] = info;
            }
            list.Add(new ListeningPortEntry
            {
                Protocol = s.Protocol,
                LocalAddress = s.LocalIp,
                LocalPort = s.LocalPort,
                Pid = s.Pid,
                ProcessName = info.Name,
                ProcessPath = info.Path,
                State = s.State
            });
        }

        return list.OrderBy(x => x.LocalPort).ThenBy(x => x.Protocol).ToList();
    }
}
