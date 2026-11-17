using NightOwl.Core.Findings;

namespace NightOwl.Core.Policy;

/// <summary>
/// Pass/fail decision for CI. Fails on any untriaged or confirmed finding at or above the threshold.
/// <paramref name="PerCategory"/> overrides the default for a category; a null threshold there means
/// "never fail on this category". Findings in tests, examples, docs, generated and vendored files only gate
/// when their context is listed in <paramref name="IncludeContexts"/> (default: production code only).
/// </summary>
public sealed record QualityGate(
    Severity? FailOn,
    IReadOnlyDictionary<FindingCategory, Severity?>? PerCategory = null,
    IReadOnlySet<FindingContext>? IncludeContexts = null)
{
    public Severity? ThresholdFor(FindingCategory category) =>
        PerCategory is not null && PerCategory.TryGetValue(category, out var threshold) ? threshold : FailOn;

    public bool Covers(FindingContext context) => context == FindingContext.Production || IncludeContexts?.Contains(context) == true;

    public GateResult Evaluate(IEnumerable<Finding> findings)
    {
        var blocking = new List<Finding>();
        var excluded = new List<Finding>();
        foreach (var f in findings.Where(f => f.Triage is TriageState.New or TriageState.Confirmed && ThresholdFor(f.Category) is { } t && f.Severity >= t))
        {
            (Covers(f.Context) ? blocking : excluded).Add(f);
        }

        return new GateResult(blocking.Count == 0, blocking, excluded);
    }
}

/// <param name="Excluded">Findings that would have blocked but sit in tests, examples, docs, generated or vendored files.</param>
public sealed record GateResult(bool Passed, IReadOnlyList<Finding> Blocking, IReadOnlyList<Finding> Excluded);
