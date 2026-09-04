using System.Collections.Concurrent;
using OpenSecurityPlatform.Foundation;

sealed class AiRequestLimiter
{
    sealed class State { public readonly object Gate = new(); public DateTimeOffset Window = DateTimeOffset.UtcNow; public int Requests; public int Active; }
    readonly ConcurrentDictionary<string, State> states = new();
    public IDisposable Acquire(string tenant, AiPolicy policy)
    {
        var state = states.GetOrAdd(tenant, _ => new()); lock (state.Gate)
        {
            var now = DateTimeOffset.UtcNow; if (now - state.Window >= TimeSpan.FromMinutes(1)) { state.Window = now; state.Requests = 0; }
            if (state.Requests >= policy.MaximumRequestsPerMinute) throw new EnrollmentConflictException("AI_RATE_LIMITED", "Tenant AI request limit is exhausted for this bounded minute.");
            if (state.Active >= policy.MaximumConcurrentRequests) throw new EnrollmentConflictException("AI_CONCURRENCY_LIMITED", "Tenant AI concurrency limit is exhausted.");
            state.Requests++; state.Active++; return new Lease(state);
        }
    }
    sealed class Lease(State state) : IDisposable { int disposed; public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) != 0) return; lock (state.Gate) state.Active--; } }
}
