namespace NightOwl.Core.Findings;

/// <summary>Merges findings that share a fingerprint into one, keeping the most informative data.</summary>
public static class FindingMerger
{
    public static IReadOnlyList<Finding> Merge(IEnumerable<Finding> findings) =>
        CollapseOverlappingCodeFindings(findings
            .GroupBy(f => f.Id)
            .Select(group => group.Aggregate(MergePair)))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Title, StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// A pattern rule ("shell command with a dynamic string") and a taint rule ("request data reaches a shell
    /// command") often fire on the same line and describe the same bug. The taint finding says more (the data
    /// really flows there), so it stays and absorbs the pattern finding: severity is the worse of the two, the
    /// absorbed rule ids and CWEs are kept as aliases, and the engines are unioned. Only collapses when the taint
    /// rule's weakness class covers the pattern rule's, so an unrelated finding on the same line (a weak hash next
    /// to an injection) is never swallowed.
    /// </summary>
    private static IEnumerable<Finding> CollapseOverlappingCodeFindings(IEnumerable<Finding> findings)
    {
        var all = findings.ToList();
        var taint = all.Where(IsTaint).ToList();
        if (taint.Count == 0)
        {
            return all;
        }

        var absorbed = new HashSet<Finding>(ReferenceEqualityComparer.Instance);
        var result = new List<Finding>(all.Count);
        foreach (var finding in all)
        {
            if (absorbed.Contains(finding))
            {
                continue;
            }

            if (IsTaint(finding))
            {
                var current = finding;
                foreach (var pattern in all.Where(f => !ReferenceEquals(f, finding) && Covers(finding, f)))
                {
                    absorbed.Add(pattern);
                    current = current with
                    {
                        Severity = current.Severity >= pattern.Severity ? current.Severity : pattern.Severity,
                        Engines = Union(current.Engines, pattern.Engines),
                        Aliases = Union(current.Aliases, pattern.Aliases.Prepend(pattern.RuleId)),
                    };
                }

                result.Add(current);
            }
            else
            {
                result.Add(finding);
            }
        }

        return result.Where(f => !absorbed.Contains(f));
    }

    private static bool IsTaint(Finding f) =>
        f.Category == FindingCategory.Code && f.RuleId.Contains(".taint.", StringComparison.OrdinalIgnoreCase);

    private static bool Covers(Finding taint, Finding other)
    {
        if (other.Category != FindingCategory.Code || IsTaint(other)
            || taint.Location is not { Path: { } path, StartLine: { } line }
            || other.Location is not { Path: { } otherPath, StartLine: { } otherLine }
            || line != otherLine || !SamePath(path, otherPath))
        {
            return false;
        }

        var covered = taint.Aliases.Select(CweNumber).Where(n => n is not null).SelectMany(n => Family(n!.Value)).ToHashSet();
        return other.Aliases.Select(CweNumber).Any(n => n is not null && covered.Contains(n.Value));
    }

    private static bool SamePath(string a, string b) =>
        string.Equals(a.Replace('\\', '/').TrimStart('.', '/'), b.Replace('\\', '/').TrimStart('.', '/'), StringComparison.Ordinal);

    private static int? CweNumber(string alias) =>
        alias.StartsWith("CWE-", StringComparison.OrdinalIgnoreCase) && int.TryParse(alias.AsSpan(4), out var n) ? n : null;

    /// <summary>The weaknesses a taint rule of this class also covers (CWE-74 is the parent of the injection family).</summary>
    private static IEnumerable<int> Family(int cwe) => cwe switch
    {
        74 => [74, 77, 78, 88, 89, 90, 94, 95, 98, 917],
        22 => [22, 23, 36],
        _ => [cwe],
    };

    private static Finding MergePair(Finding a, Finding b) => a with
    {
        // Engines disagree on severity sometimes; report the worst so nothing is understated.
        Severity = a.Severity >= b.Severity ? a.Severity : b.Severity,
        Description = a.Description ?? b.Description,
        Location = a.Location ?? b.Location,
        Assessment = a.Assessment ?? b.Assessment,
        Engines = Union(a.Engines, b.Engines),
        Aliases = Union(a.Aliases, b.Aliases),
        FixedVersions = Union(a.FixedVersions, b.FixedVersions),
        References = Union(a.References, b.References),
    };

    private static List<string> Union(IEnumerable<string> a, IEnumerable<string> b) =>
        a.Concat(b).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}
