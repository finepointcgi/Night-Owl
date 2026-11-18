using System.Text.RegularExpressions;
using NightOwl.Core.Findings;

namespace NightOwl.Core.Stig;

/// <summary>
/// Decides which findings bear on which STIG rule. This is a judgement call, so it is deliberately cautious:
/// a rule is "Open" only when scan results clearly bear on what the rule asks, and every other rule stays
/// "Not Reviewed". No finding never means "Not a Finding": a scan can't prove that a control is met.
/// </summary>
public static class StigMapper
{
    private sealed record Topic(string Name, int[] Cwes, FindingCategory[] Categories, string[] Phrases);

    private static readonly Topic[] Topics =
    [
        new("injection", [74, 77, 78, 88, 89, 90, 91, 94, 95, 98, 564, 643, 917], [], ["sql injection", "command injection", "injection flaw", "ldap injection", "xml injection", "xpath injection", "code injection", "xquery", "os command"]),
        new("cross-site scripting", [79, 80, 83, 87], [], ["cross-site scripting", "xss"]),
        new("path traversal", [22, 23, 36, 73], [], ["path traversal", "directory traversal"]),
        new("embedded credentials", [259, 321, 798], [FindingCategory.Secret], ["embedded authentication data", "embedded authentication", "hard-coded", "hardcoded", "embedded password", "embedded credential"]),
        new("weak cryptography", [326, 327, 328, 330, 338, 916], [], ["fips", "cryptographic module", "approved hash", "approved cryptograph", "weak cryptograph"]),
        new("certificate validation", [295, 297, 299], [], ["certificate validation", "validate certificate", "validates certificate", "certification path"]),
        new("buffer overflow", [119, 120, 121, 122, 125, 787, 134, 190], [], ["buffer overflow", "overflow attack", "memory corruption"]),
        new("known vulnerabilities in components", [1104, 937], [FindingCategory.Vulnerability], ["known vulnerabilit", "unsupported component", "no longer supported", "vendor-supported", "vendor supported"]),
        new("deserialization", [502], [], ["deserializ", "serialized object"]),
        new("xml external entities", [611], [], ["xml external", "xxe", "external entit"]),
        new("request forgery", [352, 918], [], ["cross-site request forgery", "csrf", "request forgery"]),
    ];

    /// <summary>The findings that bear on <paramref name="rule"/>, and why. Empty when none do.</summary>
    public static IReadOnlyList<Finding> FindingsFor(StigRule rule, IReadOnlyList<Finding> findings)
    {
        var text = rule.SearchText;
        var matched = new List<Finding>();

        // A rule that names a CWE outright is the strongest signal.
        var named = Regex.Matches(text, @"cwe-(\d+)").Select(m => int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture)).ToHashSet();
        if (named.Count > 0)
        {
            matched.AddRange(findings.Where(f => Cwes(f).Overlaps(named)));
        }

        foreach (var topic in Topics.Where(t => t.Phrases.Any(text.Contains)))
        {
            matched.AddRange(findings.Where(f =>
                Cwes(f).Overlaps(topic.Cwes) ||
                (topic.Categories.Contains(f.Category) && (f.Category != FindingCategory.Vulnerability || f.Package is not null))));
        }

        return matched.DistinctBy(f => f.Id).OrderByDescending(f => f.Severity).ToList();
    }

    private static HashSet<int> Cwes(Finding f) =>
        f.Aliases.Select(a => Regex.Match(a, @"^CWE-(\d+)$", RegexOptions.IgnoreCase)).Where(m => m.Success)
            .Select(m => int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture)).ToHashSet();
}
