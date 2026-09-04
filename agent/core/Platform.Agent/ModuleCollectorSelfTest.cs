using System.Runtime.InteropServices;
using System.Text.Json;

static class ModuleCollectorSelfTest
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    public static async Task<int> RunAsync(string dataDirectory, string? output)
    {
        Directory.CreateDirectory(dataDirectory);
        var elevated = OperatingSystem.IsWindows() && new System.Security.Principal.WindowsPrincipal(
            System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        if (!OperatingSystem.IsWindows() || !elevated)
        {
            await Write(output, new { passed = false, elevated, blocker = "Elevated Windows is required for kernel image ETW qualification." });
            return 5;
        }
        await using var collector = new WindowsKernelImageCollector(dataDirectory, standalone: true);
        await collector.StartAsync(default);
        await Task.Delay(500);
        var source = Path.Combine(Environment.SystemDirectory, "version.dll");
        var probe = Path.Combine(Path.GetTempPath(), $"osp-module-probe-{Guid.NewGuid():N}.dll");
        nint handle = 0;
        try
        {
            File.Copy(source, probe);
            handle = NativeLibrary.Load(probe);
            await Task.Delay(1000);
            NativeLibrary.Free(handle); handle = 0;
            await Task.Delay(500);
            var events = await collector.PollAsync(default);
            var matching = events.Where(x => string.Equals(Path.GetFullPath(x.Path), Path.GetFullPath(probe), StringComparison.OrdinalIgnoreCase)
                || x.Path.EndsWith(Path.GetFileName(probe), StringComparison.OrdinalIgnoreCase)).ToArray();
            var load = matching.Any(x => x.Kind == OpenSecurityPlatform.Foundation.ModuleEventKind.ImageLoaded);
            var unload = matching.Any(x => x.Kind == OpenSecurityPlatform.Foundation.ModuleEventKind.ImageUnloaded);
            var passed = collector.State == "healthy" && load && collector.LostEvents == 0;
            await Write(output, new { passed, elevated, collector = collector.Type, collector.State, collector.Error, loadObserved = load, unloadObserved = unload, matchingEvents = matching.Length, sourceLosses = collector.LostEvents, session = WindowsKernelImageCollector.SessionName, probe });
            return passed ? 0 : 4;
        }
        finally
        {
            if (handle != 0) NativeLibrary.Free(handle);
            try { File.Delete(probe); } catch (IOException) { }
        }
    }

    static Task Write(string? path, object result)
    {
        var json = JsonSerializer.Serialize(result, Json);
        if (string.IsNullOrWhiteSpace(path)) Console.WriteLine(json);
        else { Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!); File.WriteAllText(path, json); }
        return Task.CompletedTask;
    }
}
