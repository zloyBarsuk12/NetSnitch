using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using NetSnitch.Models;

namespace NetSnitch.Services;

public static class AutoUpdateService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    static AutoUpdateService()
    {
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("NetSnitch-AutoUpdater/1.0");
    }

    public static Version GetCurrentVersion()
    {
        return Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 0, 0);
    }

    public static string GetCurrentVersionString()
    {
        var v = GetCurrentVersion();
        return $"{v.Major}.{v.Minor}.{Math.Max(0, v.Build)}";
    }

    public static async Task<UpdateCheckResult> CheckForUpdateAsync(string owner, string repo)
    {
        string currentStr = GetCurrentVersionString();
        if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(repo))
        {
            return new UpdateCheckResult
            {
                CurrentVersion = currentStr,
                LatestVersion = currentStr,
                Error = "Не указан GitHub Owner/Repo в настройках."
            };
        }

        try
        {
            // Use github.com/releases/latest redirect first to avoid api.github.com 60 req/hr rate limit
            using var noRedirectHandler = new HttpClientHandler { AllowAutoRedirect = false };
            using var webClient = new HttpClient(noRedirectHandler) { Timeout = TimeSpan.FromSeconds(10) };
            webClient.DefaultRequestHeaders.UserAgent.ParseAdd("NetSnitch-AutoUpdater/1.0");

            string webLatestUrl = $"https://github.com/{owner.Trim()}/{repo.Trim()}/releases/latest";
            using var webResp = await webClient.GetAsync(webLatestUrl).ConfigureAwait(false);
            string? location = webResp.Headers.Location?.ToString();
            if (!string.IsNullOrEmpty(location) && location.Contains("/releases/tag/", StringComparison.OrdinalIgnoreCase))
            {
                string webTag = location.Split("/releases/tag/").Last().Trim('/');
                string cleanWebTag = webTag.TrimStart('v', 'V');
                string dlUrl = $"https://github.com/{owner.Trim()}/{repo.Trim()}/releases/download/{webTag}/NetSnitch-win-x64.zip";

                bool isNewerWeb = Version.TryParse(cleanWebTag, out var latestWebVer) &&
                                  latestWebVer > new Version(GetCurrentVersion().Major, GetCurrentVersion().Minor, Math.Max(0, GetCurrentVersion().Build));

                return new UpdateCheckResult
                {
                    UpdateAvailable = isNewerWeb,
                    CurrentVersion = currentStr,
                    LatestVersion = cleanWebTag,
                    DownloadUrl = dlUrl,
                    AssetName = "NetSnitch-win-x64.zip"
                };
            }

            string url = $"https://api.github.com/repos/{owner.Trim()}/{repo.Trim()}/releases/latest";
            using var resp = await Http.GetAsync(url).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                return new UpdateCheckResult
                {
                    CurrentVersion = currentStr,
                    LatestVersion = currentStr,
                    Error = $"GitHub API: {(int)resp.StatusCode} {resp.ReasonPhrase}"
                };
            }

            string json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string tag = root.TryGetProperty("tag_name", out var t) ? (t.GetString() ?? "1.0.0") : "1.0.0";
            string cleanTag = tag.TrimStart('v', 'V');
            string body = root.TryGetProperty("body", out var b) ? (b.GetString() ?? "") : "";

            string downloadUrl = "";
            string assetName = "";
            if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
            {
                // Prefer .zip archive over installer .exe
                foreach (var a in assets.EnumerateArray())
                {
                    string name = a.TryGetProperty("name", out var n) ? (n.GetString() ?? "") : "";
                    string dl = a.TryGetProperty("browser_download_url", out var u) ? (u.GetString() ?? "") : "";
                    if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                    {
                        assetName = name;
                        downloadUrl = dl;
                        break;
                    }
                }

                if (string.IsNullOrEmpty(downloadUrl))
                {
                    foreach (var a in assets.EnumerateArray())
                    {
                        string name = a.TryGetProperty("name", out var n) ? (n.GetString() ?? "") : "";
                        string dl = a.TryGetProperty("browser_download_url", out var u) ? (u.GetString() ?? "") : "";
                        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                            !name.Contains("Setup", StringComparison.OrdinalIgnoreCase))
                        {
                            assetName = name;
                            downloadUrl = dl;
                            break;
                        }
                    }
                }
            }

            bool isNewer = Version.TryParse(cleanTag, out var latestVer) &&
                           latestVer > new Version(GetCurrentVersion().Major, GetCurrentVersion().Minor, Math.Max(0, GetCurrentVersion().Build));

            return new UpdateCheckResult
            {
                UpdateAvailable = isNewer && !string.IsNullOrEmpty(downloadUrl),
                CurrentVersion = currentStr,
                LatestVersion = cleanTag,
                ReleaseNotes = body,
                DownloadUrl = downloadUrl,
                AssetName = assetName
            };
        }
        catch (Exception ex)
        {
            return new UpdateCheckResult
            {
                CurrentVersion = currentStr,
                LatestVersion = currentStr,
                Error = ex.Message
            };
        }
    }

    public static async Task<(bool Ok, string Message)> DownloadAndApplySilentAsync(UpdateCheckResult update, bool relaunch = true)
    {
        if (!update.UpdateAvailable || string.IsNullOrWhiteSpace(update.DownloadUrl))
            return (false, "Нет доступного файла обновления.");

        try
        {
            string updateRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NetSnitch", "Updates");
            if (Directory.Exists(updateRoot))
                Directory.Delete(updateRoot, true);
            Directory.CreateDirectory(updateRoot);

            string downloadPath = Path.Combine(updateRoot, update.AssetName);
            using (var stream = await Http.GetStreamAsync(update.DownloadUrl).ConfigureAwait(false))
            using (var fs = File.Create(downloadPath))
            {
                await stream.CopyToAsync(fs).ConfigureAwait(false);
            }

            string sourceDir = updateRoot;
            if (update.AssetName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                string extractDir = Path.Combine(updateRoot, "extracted");
                ZipFile.ExtractToDirectory(downloadPath, extractDir, overwriteFiles: true);
                File.Delete(downloadPath);
                sourceDir = extractDir;
            }

            string appDir = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? Path.Combine(appDir, "NetSnitch.exe");
            int pid = Environment.ProcessId;

            string scriptPath = Path.Combine(Path.GetTempPath(), $"netsnitch_update_{pid}.ps1");
            string relaunchLine = relaunch ? $"Start-Process -FilePath '{exePath}' -ArgumentList '--updated'" : "";

            string psScript = $@"
$ErrorActionPreference = 'SilentlyContinue'
Wait-Process -Id {pid} -Timeout 15
for ($i = 0; $i -lt 20; $i++) {{
    try {{
        $s = [System.IO.File]::Open('{exePath}', 'Open', 'ReadWrite', 'None')
        $s.Close()
        break
    }} catch {{
        Start-Sleep -Milliseconds 250
    }}
}}
Copy-Item -Path '{sourceDir}\*' -Destination '{appDir}' -Recurse -Force
{relaunchLine}
Remove-Item -Path '{scriptPath}' -Force
";
            await File.WriteAllTextAsync(scriptPath, psScript).ConfigureAwait(false);

            Process.Start(new ProcessStartInfo("powershell.exe",
                $"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{scriptPath}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            });

            Application.Current.Dispatcher.Invoke(() => Application.Current.Shutdown());
            return (true, "Обновление загружено и применяется...");
        }
        catch (Exception ex)
        {
            return (false, $"Ошибка обновления: {ex.Message}");
        }
    }
}
