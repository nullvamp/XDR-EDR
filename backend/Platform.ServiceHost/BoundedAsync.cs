static class BoundedAsync
{
    public static Task ForEachAsync<T>(
        IReadOnlyList<T> items,
        int maximumConcurrency,
        Func<T, CancellationToken, Task> action,
        CancellationToken cancellationToken
    )
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumConcurrency, 1);
        if (items.Count == 0)
            return Task.CompletedTask;

        var nextIndex = -1;
        var workerCount = Math.Min(maximumConcurrency, items.Count);
        var workers = new Task[workerCount];
        for (var worker = 0; worker < workerCount; worker++)
            workers[worker] = RunWorkerAsync();

        return Task.WhenAll(workers);

        async Task RunWorkerAsync()
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var index = Interlocked.Increment(ref nextIndex);
                if (index >= items.Count)
                    return;
                await action(items[index], cancellationToken);
            }
        }
    }
}
