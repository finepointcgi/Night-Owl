using System.Globalization;
using NightOwl.Core.Findings;
using NightOwl.Core.Policy;

namespace NightOwl.Cli;

/// <summary>
/// The effective rules for one scan: command-line flags win over <c>.nightowl/policy.yml</c>, which wins over
/// the built-in defaults. Resolved from the scanned project's root so CI and developers agree.
/// </summary>
internal sealed record PolicySettings(
    PolicyFile? File,
    string? Source,
    QualityGate Gate,
    string GateLabel,
    bool IgnoreUnimported,
    double? MinCoverage,
    double? MaxDuplication,
    int MaxComplexity)
{
    public static PolicySettings Resolve(string projectRoot, Options options)
    {
        var file = PolicyFile.Load(projectRoot, out var source);
        var gatePolicy = file?.Gate;

        var contexts = ResolveContexts(options.Value("include-context"), gatePolicy?.IncludeContexts);
        QualityGate gate;
        string label;
        if (options.Value("fail-on") is { } flag)
        {
            // An explicit flag is an explicit decision: it replaces the policy's thresholds entirely.
            gate = new QualityGate(Parse(flag, "--fail-on"), null, contexts);
            label = flag;
        }
        else
        {
            var fallback = gatePolicy?.FailOn ?? "high";
            var perCategory = (gatePolicy?.PerCategory ?? [])
                .ToDictionary(p => Enum.Parse<FindingCategory>(p.Key, ignoreCase: true), p => Parse(p.Value, "gate.per-category"));
            gate = new QualityGate(Parse(fallback, "gate.fail-on"), perCategory.Count == 0 ? null : perCategory, contexts);
            label = perCategory.Count == 0
                ? fallback
                : $"{fallback}; " + string.Join(", ", perCategory.OrderBy(p => p.Key).Select(p => $"{p.Key.ToString().ToLowerInvariant()}: {(p.Value is { } v ? v.ToString().ToLowerInvariant() : "none")}"));
        }

        return new PolicySettings(
            file, source, gate, label,
            options.Has("ignore-unimported") || gatePolicy?.IgnoreUnimported == true,
            Number(options.Value("min-coverage")) ?? file?.Quality.MinCoverage,
            Number(options.Value("max-duplication")) ?? file?.Quality.MaxDuplication,
            options.Value("max-complexity") is { } c ? int.Parse(c, CultureInfo.InvariantCulture) : file?.Quality.MaxComplexity ?? 15);
    }

    /// <summary>--include-context beats the policy; both take a comma list of test, example, docs, generated, vendored or all.</summary>
    private static HashSet<FindingContext> ResolveContexts(string? flag, IEnumerable<string>? fromPolicy)
    {
        var result = new HashSet<FindingContext>();
        var names = flag is null ? fromPolicy ?? [] : flag.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        foreach (var name in names)
        {
            if (!PolicyFile.TryParseContext(name, out var parsed))
            {
                throw new ArgumentException($"include-context: '{name}' is not one of test, example, docs, generated, vendored, all");
            }

            result.UnionWith(parsed);
        }

        return result;
    }

    private static Severity? Parse(string text, string where) =>
        PolicyFile.TryParseThreshold(text, out var threshold) ? threshold : throw new ArgumentException($"{where}: '{text}' is not one of none, info, low, medium, high, critical");

    private static double? Number(string? text) => text is null ? null : double.Parse(text, CultureInfo.InvariantCulture);
}
