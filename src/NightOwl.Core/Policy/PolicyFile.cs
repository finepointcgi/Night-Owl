using NightOwl.Core.Findings;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace NightOwl.Core.Policy;

/// <summary>
/// Team policy kept in the repository (<c>.nightowl/policy.yml</c>) and reviewed like code.
/// Precedence: command-line flags &gt; policy file &gt; built-in defaults.
/// Unknown keys are rejected, so a typo never silently disables a rule.
/// </summary>
public sealed class PolicyFile
{
    public static readonly string[] FileNames = [".nightowl/policy.yml", ".nightowl/policy.yaml"];

    public int Version { get; set; } = 1;
    public GatePolicy Gate { get; set; } = new();
    public LicensesPolicy Licenses { get; set; } = new();
    public QualityPolicy Quality { get; set; } = new();

    /// <summary>The policy in <paramref name="root"/>, or null when the project has none.</summary>
    public static PolicyFile? Load(string root, out string? path)
    {
        path = FileNames.Select(n => Path.Combine(root, n)).FirstOrDefault(File.Exists);
        return path is null ? null : Parse(File.ReadAllText(path), path);
    }

    public static PolicyFile Parse(string yaml, string source = "policy")
    {
        var deserializer = new DeserializerBuilder().WithNamingConvention(HyphenatedNamingConvention.Instance).Build();
        PolicyFile file;
        try
        {
            file = deserializer.Deserialize<PolicyFile?>(yaml) ?? new PolicyFile();
        }
        catch (YamlException e)
        {
            throw new PolicyException($"{source}: {(e.InnerException ?? e).Message} (line {e.Start.Line})");
        }

        // A section whose lines are all commented out parses as null.
        file.Gate ??= new GatePolicy();
        file.Gate.PerCategory ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        file.Licenses ??= new LicensesPolicy();
        file.Quality ??= new QualityPolicy();

        var errors = file.Validate().ToList();
        if (errors.Count > 0)
        {
            throw new PolicyException($"{source} is invalid:\n  - " + string.Join("\n  - ", errors));
        }

        return file;
    }

    public IEnumerable<string> Validate()
    {
        if (Version != 1) { yield return $"version must be 1 (got {Version})"; }

        if (Gate.FailOn is { } failOn && !TryParseThreshold(failOn, out _)) { yield return $"gate.fail-on '{failOn}' is not one of none, info, low, medium, high, critical"; }

        foreach (var (category, threshold) in Gate.PerCategory)
        {
            if (!Enum.TryParse<FindingCategory>(category, ignoreCase: true, out _)) { yield return $"gate.per-category: unknown category '{category}' (use {string.Join(", ", Enum.GetNames<FindingCategory>().Select(n => n.ToLowerInvariant()))})"; }
            if (!TryParseThreshold(threshold, out _)) { yield return $"gate.per-category.{category}: '{threshold}' is not one of none, info, low, medium, high, critical"; }
        }

        foreach (var context in Gate.IncludeContexts ?? [])
        {
            if (!TryParseContext(context, out _)) { yield return $"gate.include-contexts: '{context}' is not one of test, example, docs, generated, vendored, all"; }
        }

        if (Quality.MinCoverage is < 0 or > 100) { yield return "quality.min-coverage must be between 0 and 100"; }
        if (Quality.MaxDuplication is < 0 or > 100) { yield return "quality.max-duplication must be between 0 and 100"; }
        if (Quality.MaxComplexity is < 1) { yield return "quality.max-complexity must be at least 1"; }
        if (Licenses.Allow is { Count: > 0 } allow && Licenses.Deny is { } deny && allow.Intersect(deny, StringComparer.OrdinalIgnoreCase).Any())
        {
            yield return $"licenses: {string.Join(", ", allow.Intersect(deny, StringComparer.OrdinalIgnoreCase))} appear in both allow and deny";
        }
    }

    /// <summary>Parses a context name; "all" maps to every non-production context.</summary>
    public static bool TryParseContext(string text, out IReadOnlyList<FindingContext> contexts)
    {
        if (text.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            contexts = Enum.GetValues<FindingContext>().Where(c => c != FindingContext.Production).ToList();
            return true;
        }

        if (Enum.TryParse<FindingContext>(text, ignoreCase: true, out var one) && one != FindingContext.Production)
        {
            contexts = [one];
            return true;
        }

        contexts = [];
        return false;
    }

    /// <summary>"none" means the category never fails the gate; otherwise the lowest severity that does.</summary>
    public static bool TryParseThreshold(string text, out Severity? threshold)
    {
        threshold = null;
        if (text.Equals("none", StringComparison.OrdinalIgnoreCase)) { return true; }
        if (Enum.TryParse<Severity>(text, ignoreCase: true, out var severity) && severity != Severity.Unknown) { threshold = severity; return true; }
        return false;
    }

    public const string Template = """
        # Night Owl policy. Lives in the repository, reviewed like code.
        # Precedence: command-line flags > this file > built-in defaults.
        version: 1

        gate:
          # Lowest severity that fails the build: none | info | low | medium | high | critical
          fail-on: high
          # Override per category (secret, code, vulnerability, license, infrastructure, dynamic, quality).
          per-category:
            secret: low          # any secret fails the build
            quality: none        # maintainability findings never fail it
          # Don't fail on dependency CVEs when first-party code never imports the package.
          ignore-unimported: false
          # Findings in tests, examples, docs, generated and vendored files are listed but don't fail the build.
          # Opt back in per kind: test | example | docs | generated | vendored | all
          # include-contexts: [test]

        licenses:
          # Each list replaces the built-in default for that list.
          # deny: [AGPL-3.0-only, SSPL-1.0]    # high severity
          # review: [GPL-3.0-only, MPL-2.0]    # medium severity
          # allow: [MIT, Apache-2.0, BSD-3-Clause, ISC]   # anything else is flagged for review
          flag-unknown: true

        quality:
          # min-coverage: 80        # percent, needs a coverage report in the project
          # max-duplication: 5      # percent
          # max-complexity: 15      # cyclomatic complexity per function
        """;
}

public sealed class GatePolicy
{
    public string? FailOn { get; set; }
    public Dictionary<string, string> PerCategory { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public bool? IgnoreUnimported { get; set; }

    /// <summary>Non-production contexts that still gate: test, example, docs, generated, vendored (or "all").</summary>
    public List<string>? IncludeContexts { get; set; }
}

public sealed class LicensesPolicy
{
    public List<string>? Deny { get; set; }
    public List<string>? Review { get; set; }

    /// <summary>When set, a license outside this list (and not denied or under review) is flagged for review.</summary>
    public List<string>? Allow { get; set; }

    public bool? FlagUnknown { get; set; }
}

public sealed class QualityPolicy
{
    public double? MinCoverage { get; set; }
    public double? MaxDuplication { get; set; }
    public int? MaxComplexity { get; set; }
}

public sealed class PolicyException(string message) : Exception(message);
