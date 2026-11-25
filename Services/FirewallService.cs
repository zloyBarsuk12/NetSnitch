using System.Diagnostics;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class FirewallService
{
    private const string RulePrefix = "NetSnitch_Block_";

    private static async Task<(int ExitCode, string Output)> RunNetshAsync(string args)
    {
        var psi = new ProcessStartInfo("netsh", args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi)!;
        string output = await p.StandardOutput.ReadToEndAsync();
        string err = await p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        return (p.ExitCode, string.IsNullOrWhiteSpace(output) ? err : output);
    }

    public static async Task<(bool Ok, string Message)> BlockIpAsync(string ip)
    {
        string safeName = RulePrefix + ip.Replace(":", "_");
        string args = $"advfirewall firewall add rule name=\"{safeName}\" dir=out action=block remoteip={ip} enable=yes";
        var (code, outText) = await RunNetshAsync(args);
        if (code == 0) return (true, $"IP {ip} заблокирован в Windows Firewall.");
        return (false, $"Не удалось заблокировать {ip} (нужны права администратора): {outText.Trim()}");
    }

    public static async Task<(bool Ok, string Message)> BlockProgramAsync(string exePath, string appName)
    {
        if (string.IsNullOrWhiteSpace(exePath))
            return (false, "Путь к исполняемому файлу недоступен.");
        string safeName = RulePrefix + "App_" + appName.Replace(" ", "_");
        string args = $"advfirewall firewall add rule name=\"{safeName}\" dir=out action=block program=\"{exePath}\" enable=yes";
        var (code, outText) = await RunNetshAsync(args);
        return code == 0
            ? (true, $"Приложение {appName} заблокировано.")
            : (false, $"Ошибка (нужны права администратора): {outText.Trim()}");
    }

    public static async Task<(bool Ok, string Message)> DeleteRuleAsync(string ruleName)
    {
        string args = $"advfirewall firewall delete rule name=\"{ruleName}\"";
        var (code, outText) = await RunNetshAsync(args);
        return code == 0
            ? (true, $"Правило {ruleName} удалено.")
            : (false, $"Ошибка удаления: {outText.Trim()}");
    }

    public static async Task<List<FirewallRuleEntry>> GetNetSnitchRulesAsync()
    {
        var list = new List<FirewallRuleEntry>();
        var (code, output) = await RunNetshAsync("advfirewall firewall show rule name=all");
        if (code != 0 || string.IsNullOrWhiteSpace(output)) return list;

        var blocks = output.Split(new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var block in blocks)
        {
            string? name = null, dir = null, action = null, enabled = null, remoteIp = null;
            foreach (var line in block.Split('\n'))
            {
                var idx = line.IndexOf(':');
                if (idx <= 0) continue;
                var key = line[..idx].Trim();
                var val = line[(idx + 1)..].Trim();

                if (key.Contains("Rule Name", StringComparison.OrdinalIgnoreCase) || key.Contains("Имя правила", StringComparison.OrdinalIgnoreCase))
                    name = val;
                else if (key.Contains("Direction", StringComparison.OrdinalIgnoreCase) || key.Contains("Направление", StringComparison.OrdinalIgnoreCase))
                    dir = val;
                else if (key.Contains("Action", StringComparison.OrdinalIgnoreCase) || key.Contains("Действие", StringComparison.OrdinalIgnoreCase))
                    action = val;
                else if (key.Contains("Enabled", StringComparison.OrdinalIgnoreCase) || key.Contains("Включено", StringComparison.OrdinalIgnoreCase))
                    enabled = val;
                else if (key.Contains("RemoteIP", StringComparison.OrdinalIgnoreCase) || key.Contains("Удаленный IP", StringComparison.OrdinalIgnoreCase))
                    remoteIp = val;
            }

            if (name != null && name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
            {
                list.Add(new FirewallRuleEntry
                {
                    RuleName = name,
                    Target = remoteIp ?? name.Replace(RulePrefix, ""),
                    Direction = dir ?? "Out",
                    Action = action ?? "Block",
                    Enabled = enabled ?? "Yes"
                });
            }
        }

        return list;
    }
}
