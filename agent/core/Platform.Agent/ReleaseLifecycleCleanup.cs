using System.Diagnostics;

static class ReleaseLifecycleCleanup
{
    static readonly string[] RemovableDirectories =
    [
        "process-queue", "file-queue", "registry-queue", "network-queue", "dns-queue",
        "module-queue", "persistence-queue", "identity-queue", "execution-queue",
        "file-hash-work", "update-stage", "update-backup", "agent-installation",
        "forensic-collection-work"
    ];

    public static async Task<int> RunAsync()
    {
        if (!OperatingSystem.IsWindows()) return 2;
        var data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OpenSecurityPlatform", "Agent", "data");
        foreach (var name in RemovableDirectories)
        {
            var path = Path.GetFullPath(Path.Combine(data, name));
            if (path.StartsWith(Path.GetFullPath(data) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) && Directory.Exists(path))
                Directory.Delete(path, true);
        }
        foreach (var name in new[] { "state.dat", "state.json", "agent-update-journal.json", "isolation-state.json" })
        {
            var path = Path.Combine(data, name);
            if (File.Exists(path)) File.Delete(path);
        }
        var start = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-NoProfile"); start.ArgumentList.Add("-NonInteractive"); start.ArgumentList.Add("-Command");
        start.ArgumentList.Add("Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object Group -Like 'OpenSecurityPlatform-Isolation-*' | Remove-NetFirewallRule -ErrorAction Stop");
        using var process = Process.Start(start); if (process is null) return 3;
        await process.WaitForExitAsync();
        return process.ExitCode;
    }
}
