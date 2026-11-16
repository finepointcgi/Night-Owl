using NightOwl.Core.Findings;

namespace NightOwl.Core.Policy;

/// <summary>
/// Pass/fail decision for CI. Fails on any untriaged or confirmed finding at or above the threshold.
/// <paramref name="PerCategory"/> overrides the default for a category; a null threshold there means
/// "never fail on this category".
/// </summary>
public sealed record QualityGate(Severity? FailOn, IReadOnlyDictionary<FindingCategory, Severity?>? PerCategory = null)
{
    public Severity? ThresholdFor(FindingCategory category) =>
        PerCategory is not null && PerCategory.TryGetValue(category, out var threshold) ? threshold : FailOn;

    public GateResult Evaluate(IEnumerable<Finding> findings)
    {
        var blocking = findings
            .Where(f => f.Triage is TriageState.New or TriageState.Confirmed && ThresholdFor(f.Category) is { } t && f.Severity >= t)
            .ToList();
        return new GateResult(blocking.Count == 0, blocking);
    }
}

public sealed record GateResult(bool Passed, IReadOnlyList<Finding> Blocking);
