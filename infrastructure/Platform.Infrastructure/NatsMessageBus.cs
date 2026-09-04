using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NATS.Client.Serializers.Json;
using NATS.Net;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed partial class NatsMessageBus : IMessageBus, IAsyncDisposable
{
    private readonly NatsClient _client;
    private readonly INatsJSContext _jetStream;
    private readonly ILogger<NatsMessageBus> _logger;
    private volatile bool _healthy;

    public NatsMessageBus(string url, string serviceName, ILogger<NatsMessageBus> logger)
    {
        _logger = logger;
        if (
            !Uri.TryCreate(url, UriKind.Absolute, out var parsed)
            || parsed.Scheme is not ("nats" or "tls")
        )
            throw new InvalidOperationException("NATS URL is invalid.");
        var options = NatsOpts.Default with
        {
            Url = url,
            Name = serviceName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            MaxReconnectRetry = 20,
            ReconnectWaitMin = TimeSpan.FromMilliseconds(250),
            ReconnectWaitMax = TimeSpan.FromSeconds(5),
        };
        _client = new NatsClient(options);
        _jetStream = _client.CreateJetStreamContext();
    }

    public bool IsHealthy => _healthy;

    public async ValueTask<bool> HealthAsync(CancellationToken ct)
    {
        try
        {
            await _client.PingAsync(ct);
            _healthy = true;
        }
        catch (NatsException)
        {
            _healthy = false;
        }
        return _healthy;
    }

    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        await _client.ConnectAsync();
        await _client.PingAsync(cancellationToken);
        await _jetStream.CreateOrUpdateStreamAsync(
            new StreamConfig("PLATFORM_ENDPOINTS", ["platform.>"]),
            cancellationToken
        );
        _healthy = true;
    }

    public async ValueTask PublishAsync<T>(
        TypedMessage<T> message,
        CancellationToken cancellationToken
    )
    {
        var subject = SubjectPart().Replace(message.Type.ToLowerInvariant(), "_");
        var headers = new NatsHeaders
        {
            { "Nats-Msg-Id", message.Id },
            { "X-Event-Type", message.Type },
            { "X-Schema-Version", message.Version },
            { "X-Tenant-ID", message.TenantId },
            { "traceparent", message.TraceId },
        };
        try
        {
            await _jetStream.PublishAsync(
                $"platform.{subject}.v1",
                message,
                headers: headers,
                cancellationToken: cancellationToken
            );
            _healthy = true;
        }
        catch (NatsException)
        {
            _healthy = false;
            throw;
        }
    }

    public async Task ConsumeEndpointEventsAsync(
        Func<TypedMessage<JsonElement>, CancellationToken, Task> handler,
        CancellationToken ct
    )
    {
        var config = new ConsumerConfig("endpoint-projection-v2")
        {
            DurableName = "endpoint-projection-v2",
            FilterSubject = "platform.>",
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            DeliverPolicy = ConsumerConfigDeliverPolicy.New,
            MaxDeliver = 50,
            // Return abandoned work promptly after a gateway crash. Active work
            // extends this bounded window with progress acknowledgements below.
            AckWait = TimeSpan.FromSeconds(30),
        };
        var consumer = await _jetStream.CreateOrUpdateConsumerAsync(
            "PLATFORM_ENDPOINTS",
            config,
            ct
        );
        // Compose gives each gateway a 20-connection PostgreSQL pool. Keep
        // four connections reserved for readiness and API/control-plane work
        // while allowing sustained native telemetry projection.
        const int projectionConcurrency = 16;
        using var concurrency = new SemaphoreSlim(projectionConcurrency, projectionConcurrency);
        await foreach (
            var message in consumer.ConsumeAsync(
                new NatsJsonSerializer<TypedMessage<JsonElement>>(),
                cancellationToken: ct
            )
        )
        {
            await concurrency.WaitAsync(ct);
            _ = HandleAsync(message);
        }

        async Task HandleAsync(INatsJSMsg<TypedMessage<JsonElement>> message)
        {
            using var progress = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var progressTask = KeepOwnershipAsync(message, progress.Token);
            try
            {
                if (message.Data is not null)
                    await handler(message.Data, ct);
                await message.AckAsync(cancellationToken: ct);
                _healthy = true;
            }
            catch (Exception error) when (!ct.IsCancellationRequested)
            {
                _healthy = false;
                _logger.LogWarning(
                    "NATS projection message {MessageId} failed with {ErrorType}",
                    message.Data?.Id,
                    error.GetType().Name
                );
                await message.NakAsync(delay: TimeSpan.FromSeconds(15), cancellationToken: ct);
            }
            finally
            {
                await progress.CancelAsync();
                try
                {
                    await progressTask;
                }
                catch (OperationCanceledException) when (progress.IsCancellationRequested) { }
                concurrency.Release();
            }
        }

        static async Task KeepOwnershipAsync(
            INatsJSMsg<TypedMessage<JsonElement>> message,
            CancellationToken ct
        )
        {
            var deadline = DateTimeOffset.UtcNow.AddSeconds(90);
            while (!ct.IsCancellationRequested && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromSeconds(10), ct);
                try
                {
                    await message.AckProgressAsync(cancellationToken: ct);
                }
                catch (NatsException) when (!ct.IsCancellationRequested)
                {
                    return;
                }
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _client.DisposeAsync();
    }

    [GeneratedRegex("[^a-z0-9]+", RegexOptions.CultureInvariant)]
    private static partial Regex SubjectPart();
}
