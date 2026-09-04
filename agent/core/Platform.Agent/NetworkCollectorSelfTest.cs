using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Session;
using OpenSecurityPlatform.Foundation;

static class NetworkCollectorSelfTest
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static async Task<int> RunAsync(string dataDirectory, string? output)
    {
        var elevated = OperatingSystem.IsWindows() && IsElevated();
        if (!OperatingSystem.IsWindows() || !elevated) return await Write(output, new { schema = "platform.network-native-self-test.v1", executedAt = DateTimeOffset.UtcNow, platform = Environment.OSVersion.ToString(), elevated, passed = false, blocker = "elevated-windows-required" }, 2);
        await using var collector = new WindowsEtwNetworkCollector(dataDirectory);
        await collector.StartAsync(default);
        if (collector.State != "healthy") return await Write(output, new { schema = "platform.network-native-self-test.v1", executedAt = DateTimeOffset.UtcNow, elevated, collector = collector.Type, collectorState = collector.State, collectorError = collector.Error, passed = false }, 3);

        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accept = listener.AcceptTcpClientAsync();
        using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, port);
        using var accepted = await accept; await client.GetStream().WriteAsync(new byte[] { 1 });
        client.Close(); accepted.Close(); listener.Stop();

        using var udpReceiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var udpSender = new UdpClient(); var udpPort = ((IPEndPoint)udpReceiver.Client.LocalEndPoint!).Port;
        await udpSender.SendAsync(new byte[] { 1 }, new IPEndPoint(IPAddress.Loopback, udpPort));
        _ = await udpReceiver.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5));
        try { using var failed = new TcpClient(); await failed.ConnectAsync(IPAddress.Loopback, port).WaitAsync(TimeSpan.FromSeconds(2)); } catch (Exception e) when (e is SocketException or TimeoutException) { }
        await Task.Delay(2000);
        var events = await collector.PollAsync(default);
        var relevant = events.Where(x => x.LocalAddress == IPAddress.Loopback.ToString() || x.RemoteAddress == IPAddress.Loopback.ToString()).ToArray();
        var tcp = relevant.Where(x => x.Protocol == "TCP").ToArray(); var udp = relevant.Where(x => x.Protocol == "UDP").ToArray();
        var passed = tcp.Any(x => x.Kind == NetworkEventKind.ConnectionAttempted)
            && tcp.Any(x => x.Kind == NetworkEventKind.ConnectionEstablished)
            && tcp.Any(x => x.Kind == NetworkEventKind.ConnectionClosed)
            && udp.Any(x => x.Kind == NetworkEventKind.DatagramObserved)
            && relevant.All(x => x.ProcessId > 0 && x.LocalPort is >= 0 and <= 65535);
        var report = new
        {
            schema = "platform.network-native-self-test.v1",
            executedAt = DateTimeOffset.UtcNow,
            elevated,
            collector = collector.Type,
            collectorVersion = collector.Version,
            collectorState = collector.State,
            collectorError = collector.Error,
            lostEvents = collector.LostEvents,
            sessionName = WindowsEtwNetworkCollector.SessionName,
            tcpPort = port,
            udpPort,
            eventCount = relevant.Length,
            operations = relevant.GroupBy(x => x.Kind).ToDictionary(x => x.Key.ToString(), x => x.Count()),
            protocols = relevant.GroupBy(x => x.Protocol).ToDictionary(x => x.Key, x => x.Count()),
            processIds = relevant.Select(x => x.ProcessId).Distinct().Order().ToArray(),
            knownLimitations = collector.KnownLimitations,
            noPacketOrPayloadCapture = true,
            noDnsTlsOrHttpCapture = true,
            passed
        };
        var code = passed ? 0 : 4; await collector.DisposeAsync();
        var sessionStopped = !TraceEventSession.GetActiveSessionNames().Contains(WindowsEtwNetworkCollector.SessionName, StringComparer.Ordinal);
        return await Write(output, new { report.schema, report.executedAt, report.elevated, report.collector, report.collectorVersion, report.collectorState, report.collectorError, report.lostEvents, report.sessionName, report.tcpPort, report.udpPort, report.eventCount, report.operations, report.protocols, report.processIds, report.knownLimitations, report.noPacketOrPayloadCapture, report.noDnsTlsOrHttpCapture, sessionStopped, passed = report.passed && sessionStopped }, report.passed && sessionStopped ? 0 : code);
    }

    static async Task<int> Write(string? output, object report, int code)
    { var text = JsonSerializer.Serialize(report, Json); Console.WriteLine(text); if (!string.IsNullOrWhiteSpace(output)) { Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!); await File.WriteAllTextAsync(output, text); } return code; }
    [SupportedOSPlatform("windows")]
    static bool IsElevated() { try { using var identity = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; } }
}
