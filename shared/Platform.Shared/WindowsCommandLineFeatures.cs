using System.Text;

namespace OpenSecurityPlatform.Foundation;

public sealed record WindowsCommandLineFeatureSet(
    string InterpreterType,
    int CommandLength,
    int TokenCount,
    int UrlCount,
    int EncodedTokenCount,
    int MaximumBase64CandidateLength,
    int UserWritablePathCount,
    int InterpreterNestingDepth,
    bool EncodedArgument,
    bool SuspiciousSwitch,
    bool RetrievalIndicator,
    bool ExecutionIndicator,
    bool HiddenOrNonInteractive,
    bool ObfuscationIndicator,
    bool UserWritableArgument,
    string SuspiciousSwitchSet,
    string FilePathArgument);

public static class WindowsCommandLineFeatures
{
    public const int MaximumInputLength = 16_384;
    public const int MaximumTokens = 256;
    public const int MaximumCandidates = 16;
    public const int MaximumNesting = 8;

    static readonly string[] EncodedSwitches = ["-encodedcommand", "-enc", "/encodedcommand"];
    static readonly string[] SuspiciousSwitches = ["-executionpolicy", "-ep", "bypass", "-windowstyle", "hidden", "-noninteractive", "-noni", "-nop", "-w hidden"];
    static readonly string[] RetrievalTerms = ["invoke-webrequest", "iwr", "invoke-restmethod", "irm", "downloadstring", "downloadfile", "net.webclient", "start-bitstransfer", "urlcache", "http://", "https://"];
    static readonly string[] ExecutionTerms = ["invoke-expression", "iex", "frombase64string", "start-process", "javascript:", "vbscript:", "scrobj.dll", "-decode", "/decode"];
    static readonly string[] Interpreters = ["powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta"];
    static readonly string[] WritableMarkers = ["\\downloads\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "%temp%", "%appdata%", "%userprofile%", "$env:temp", "$env:appdata", "$env:userprofile"];

    public static WindowsCommandLineFeatureSet Extract(string? commandLine, string? executablePath = null)
    {
        var input = (commandLine ?? string.Empty).Length <= MaximumInputLength
            ? commandLine ?? string.Empty
            : (commandLine ?? string.Empty)[..MaximumInputLength];
        var lower = input.ToLowerInvariant();
        var tokens = Tokenize(input);
        var encoded = tokens.Where(IsBase64Candidate).Take(MaximumCandidates).ToArray();
        var switches = SuspiciousSwitches.Where(x => lower.Contains(x, StringComparison.Ordinal)).Distinct().Take(16).ToArray();
        var encodedArgument = EncodedSwitches.Any(x => TokenOrPrefix(tokens, x)) || encoded.Any(x => x.Length >= 40);
        var retrieval = RetrievalTerms.Any(x => lower.Contains(x, StringComparison.Ordinal));
        var execution = ExecutionTerms.Any(x => ContainsSemantic(lower, x));
        var writable = WritableMarkers.Count(x => lower.Contains(x, StringComparison.Ordinal));
        var quoteCount = input.Count(x => x is '\'' or '"');
        var escapeCount = input.Count(x => x is '^' or '`' or '\\');
        var concatCount = Count(lower, "+") + Count(lower, "&") + Count(lower, "|");
        var nesting = Math.Min(MaximumNesting, Interpreters.Count(x => lower.Contains(x, StringComparison.OrdinalIgnoreCase)));
        var interpreter = Interpreter(executablePath, tokens.FirstOrDefault());
        var filePathArgument = FileArgument(tokens, executablePath);
        return new(
            interpreter,
            input.Length,
            tokens.Count,
            Count(lower, "http://") + Count(lower, "https://"),
            encoded.Length,
            encoded.Select(x => x.Length).DefaultIfEmpty().Max(),
            writable,
            nesting,
            encodedArgument,
            switches.Length > 0,
            retrieval,
            execution,
            (lower.Contains("hidden") || lower.Contains("noninteractive") || lower.Contains("-noni")),
            encoded.Length > 0 || escapeCount >= 8 || quoteCount >= 12 || concatCount >= 6,
            writable > 0,
            string.Join(',', switches),
            filePathArgument);
    }

    static List<string> Tokenize(string input)
    {
        var output = new List<string>(); var current = new StringBuilder(); var quoted = false; var quote = '\0';
        foreach (var c in input)
        {
            if (c is '\'' or '"') { if (!quoted) { quoted = true; quote = c; } else if (quote == c) quoted = false; current.Append(c); continue; }
            if (char.IsWhiteSpace(c) && !quoted) { if (current.Length > 0) { output.Add(current.ToString()); current.Clear(); if (output.Count == MaximumTokens) break; } }
            else current.Append(c);
        }
        if (current.Length > 0 && output.Count < MaximumTokens) output.Add(current.ToString());
        return output;
    }

    static bool IsBase64Candidate(string value)
    {
        var x = value.Trim('"', '\'', '(', ')', '[', ']', '{', '}', ',', ';');
        if (x.Length is < 24 or > 4096 || x.Length % 4 != 0) return false;
        var valid = x.Count(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=');
        return valid >= x.Length * 9 / 10;
    }
    static bool TokenOrPrefix(IEnumerable<string> tokens, string value) => tokens.Any(x => x.Equals(value, StringComparison.OrdinalIgnoreCase) || value == "-enc" && x.StartsWith("-enc:", StringComparison.OrdinalIgnoreCase));
    static bool ContainsSemantic(string input, string value) => input.Contains(value, StringComparison.Ordinal) && (value.Length > 3 || input.Split([' ', '\t', ';', '(', ')'], StringSplitOptions.RemoveEmptyEntries).Any(x => x.Equals(value, StringComparison.OrdinalIgnoreCase)));
    static int Count(string input, string value) { var count = 0; var at = 0; while (count < MaximumCandidates && (at = input.IndexOf(value, at, StringComparison.Ordinal)) >= 0) { count++; at += value.Length; } return count; }
    static string Interpreter(string? executablePath, string? firstToken)
    {
        // Path.GetFileName follows the host OS separator rules. Detection evaluation also
        // runs on Linux, where a Windows path containing backslashes would otherwise be
        // treated as one filename and the interpreter would not be recognized.
        var candidate = (executablePath ?? firstToken ?? string.Empty).Replace('\\', '/');
        var name = Path.GetFileName(candidate).ToLowerInvariant();
        return name switch { "powershell.exe" or "powershell" or "pwsh.exe" or "pwsh" => "powershell", "cmd.exe" or "cmd" => "cmd", "wscript.exe" or "wscript" => "wscript", "cscript.exe" or "cscript" => "cscript", "mshta.exe" or "mshta" => "mshta", _ => "none" };
    }

    static string FileArgument(IReadOnlyList<string> tokens, string? executablePath)
    {
        static string Normalize(string value) => value.Trim('"', '\'', '(', ')', '[', ']', '{', '}', ',', ';')
            .Replace('/', '\\').ToLowerInvariant();
        static bool Supported(string value)
        {
            if (value.StartsWith("http:", StringComparison.Ordinal) || value.StartsWith("https:", StringComparison.Ordinal)) return false;
            return new[] { ".ps1", ".vbs", ".js", ".hta", ".cmd", ".bat", ".exe", ".dll", ".msi", ".inf" }
                .Any(x => value.EndsWith(x, StringComparison.Ordinal));
        }
        foreach (var token in tokens.Skip(1).Take(MaximumCandidates))
        {
            var value = Normalize(token);
            if (Supported(value)) return value;
        }
        var executable = Normalize(executablePath ?? string.Empty);
        return Supported(executable) ? executable : string.Empty;
    }
}
