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

        QualityGate gate;
        string label;
        if (options.Value("fail-on") is { } flag)
        {
            // An explicit flag is an explicit decision: it replaces the policy's thresholds entirely.
            gate = new QualityGate(Parse(flag, "--fail-on"));
            label = flag;
        }
        else
        {
            var fallback = gatePolicy?.FailOn ?? "high";
            var perCategory = (gatePolicy?.PerCategory ?? [])
                .ToDictionary(p => Enum.Parse<FindingCategory>(p.Key, ignoreCase: true), p => Parse(p.Value, "gate.per-category"));
            gate = new QualityGate(Parse(fallback, "gate.fail-on"), perCategory.Count == 0 ? null : perCategory);
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

    private static Severity? Parse(string text, string where) =>
        PolicyFile.TryParseThreshold(text, out var threshold) ? threshold : throw new ArgumentException($"{where}: '{text}' is not one of none, info, low, medium, high, critical");

    private static double? Number(string? text) => text is null ? null : double.Parse(text, CultureInfo.InvariantCulture);
}
