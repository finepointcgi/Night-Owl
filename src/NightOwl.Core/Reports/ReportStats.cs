using NightOwl.Core.Findings;

namespace NightOwl.Core.Reports;

/// <summary>Counts shared by the dashboard and the exports, so every screen agrees on what "open" means.</summary>
public static class ReportStats
{
    /// <summary>Findings that still need attention: not a quality metric, and not triaged away or fixed.</summary>
    public static IEnumerable<Finding> Open(ScanReport report) =>
        report.Findings.Where(IsOpen);

    public static bool IsOpen(Finding f) =>
        f.Category != FindingCategory.Quality && f.Triage is TriageState.New or TriageState.Confirmed or TriageState.AcceptedRisk;

    public static IReadOnlyDictionary<Severity, int> BySeverity(IEnumerable<Finding> findings) =>
        findings.GroupBy(f => f.Severity).ToDictionary(g => g.Key, g => g.Count());

    public static int Count(IReadOnlyDictionary<Severity, int> counts, Severity severity) =>
        counts.TryGetValue(severity, out var n) ? n : 0;

    /// <summary>A single comparable number for ranking projects by risk: critical outweighs high outweighs the rest.</summary>
    public static int RiskScore(IEnumerable<Finding> open)
    {
        var score = 0;
        foreach (var f in open)
        {
            score += f.Severity switch { Severity.Critical => 100, Severity.High => 20, Severity.Medium => 4, Severity.Low => 1, _ => 0 };
        }

        return score;
    }
}
