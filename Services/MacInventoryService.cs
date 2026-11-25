using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class MacInventoryService
{
    private const string RemoteCmd =
        "echo '---HW---'; system_profiler SPHardwareDataType 2>/dev/null; " +
        "echo '---OS---'; sw_vers 2>/dev/null; " +
        "echo '---DF---'; df -h / 2>/dev/null; " +
        "echo '---HOST---'; hostname 2>/dev/null";

    public static async Task<MacHardwareInfo> CollectAsync(string ip, string username, string password, CancellationToken ct)
    {
        var info = new MacHardwareInfo { IpAddress = ip };
        if (string.IsNullOrWhiteSpace(username))
        {
            info.Status = "Не указан логин";
            return info;
        }

        string sshExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh.exe");
        if (!File.Exists(sshExe)) sshExe = "ssh.exe";

        string? askPassFile = null;
        try
        {
            var psi = new ProcessStartInfo(sshExe,
                $"-o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 {username}@{ip} \"{RemoteCmd}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            if (!string.IsNullOrEmpty(password))
            {
                askPassFile = Path.Combine(Path.GetTempPath(), $"ns_ask_{Guid.NewGuid():N}.cmd");
                string escaped = password.Replace("%", "%%").Replace("^", "^^").Replace("&", "^&").Replace("|", "^|").Replace("<", "^<").Replace(">", "^>");
                await File.WriteAllTextAsync(askPassFile, $"@echo off\r\necho {escaped}\r\n", ct).ConfigureAwait(false);
                psi.Environment["SSH_ASKPASS"] = askPassFile;
                psi.Environment["SSH_ASKPASS_REQUIRE"] = "force";
                psi.Environment["DISPLAY"] = "dummy:0";
            }

            using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Не удалось запустить ssh.exe");
            proc.StandardInput.Close();

            var outTask = proc.StandardOutput.ReadToEndAsync(ct);
            var errTask = proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);

            string output = await outTask.ConfigureAwait(false);
            string err = await errTask.ConfigureAwait(false);

            if (proc.ExitCode != 0 && string.IsNullOrWhiteSpace(output))
            {
                info.Status = string.IsNullOrWhiteSpace(err)
                    ? $"Ошибка SSH (код {proc.ExitCode})"
                    : err.Trim().Split('\n').Last().Trim();
                return info;
            }

            ParseOutput(output, info);
            info.Status = "OK";
            return info;
        }
        catch (Exception ex)
        {
            info.Status = ex.Message;
            return info;
        }
        finally
        {
            if (askPassFile != null)
            {
                try { File.Delete(askPassFile); } catch { }
            }
        }
    }

    private static void ParseOutput(string text, MacHardwareInfo info)
    {
        string modelName = MatchValue(text, @"Model Name:\s*(.+)");
        string modelId = MatchValue(text, @"Model Identifier:\s*(.+)");
        info.Model = string.IsNullOrEmpty(modelId) ? modelName : $"{modelName} ({modelId})";
        if (string.IsNullOrWhiteSpace(info.Model)) info.Model = "—";

        string chip = MatchValue(text, @"Chip:\s*(.+)");
        if (string.IsNullOrEmpty(chip))
            chip = MatchValue(text, @"Processor Name:\s*(.+)");
        string cores = MatchValue(text, @"Total Number of Cores:\s*(.+)");
        info.Cpu = string.IsNullOrEmpty(cores) ? chip : $"{chip} ({cores})";
        if (string.IsNullOrWhiteSpace(info.Cpu)) info.Cpu = "—";

        string mem = MatchValue(text, @"Memory:\s*(.+)");
        info.Ram = string.IsNullOrEmpty(mem) ? "—" : mem;

        string serial = MatchValue(text, @"Serial Number \(system\):\s*(.+)");
        info.SerialNumber = string.IsNullOrEmpty(serial) ? "—" : serial;

        string osVer = MatchValue(text, @"ProductVersion:\s*(.+)");
        string osBuild = MatchValue(text, @"BuildVersion:\s*(.+)");
        info.MacOs = string.IsNullOrEmpty(osVer) ? "—" : (string.IsNullOrEmpty(osBuild) ? osVer : $"{osVer} ({osBuild})");

        var dfLines = text.Split('\n').Select(l => l.Trim()).ToList();
        int dfIdx = dfLines.FindIndex(l => l == "---DF---");
        if (dfIdx >= 0 && dfIdx + 2 < dfLines.Count)
        {
            var cols = Regex.Split(dfLines[dfIdx + 2], @"\s+");
            if (cols.Length >= 4)
                info.Disk = $"{cols[1]} всего / {cols[3]} своб.";
        }

        int hostIdx = dfLines.FindIndex(l => l == "---HOST---");
        if (hostIdx >= 0 && hostIdx + 1 < dfLines.Count && !string.IsNullOrWhiteSpace(dfLines[hostIdx + 1]))
            info.Hostname = dfLines[hostIdx + 1];
    }

    private static string MatchValue(string text, string pattern)
    {
        var m = Regex.Match(text, pattern, RegexOptions.Multiline);
        return m.Success ? m.Groups[1].Value.Trim() : "";
    }
}
