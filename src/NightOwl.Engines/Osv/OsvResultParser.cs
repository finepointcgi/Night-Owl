using System.Globalization;
using System.Text.Json;
using NightOwl.Core.Findings;
using NightOwl.Engines.Execution;

namespace NightOwl.Engines.Osv;

/// <summary>Maps OSV-Scanner JSON output to normalized findings.</summary>
public static class OsvResultParser
{
    public static IReadOnlyList<Finding> Parse(string json, string sourcePath, string engine)
    {
        using var document = JsonDocument.Parse(json);
        var findings = new List<Finding>();
        var root = JsonGuards.RootObject(document, engine);

        foreach (var result in JsonGuards.Array(root, "results"))
        {
            if (!JsonGuards.IsObject(result))
            {
                continue;
            }

            var sourceFile = result.TryGetProperty("source", out var source) && Str(source, "path") is { } p
                ? ToolRunner.ToProjectPath(p, sourcePath)
                : null;

            foreach (var entry in JsonGuards.Array(result, "packages"))
            {
                if (!JsonGuards.IsObject(entry) || !entry.TryGetProperty("package", out var pkg) || pkg.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var package = new PackageRef(Str(pkg, "name") ?? "", Str(pkg, "version") ?? "", Str(pkg, "ecosystem") ?? "");
                var groupSeverity = GroupSeverities(entry);

                foreach (var vulnerability in JsonGuards.Array(entry, "vulnerabilities"))
                {
                    if (!JsonGuards.IsObject(vulnerability))
                    {
                        continue;
                    }

                    var id = Str(vulnerability, "id") ?? "UNKNOWN";
                    var aliases = Strings(vulnerability, "aliases");
                    var severity = groupSeverity.GetValueOrDefault(id, Severity.Unknown);
                    if (severity == Severity.Unknown)
                    {
                        severity = DatabaseSeverity(vulnerability);
                    }

                    findings.Add(new Finding
                    {
                        Id = Fingerprint.ForVulnerability(package, id, aliases),
                        Category = FindingCategory.Vulnerability,
                        Severity = severity,
                        RuleId = id,
                        Title = $"{Str(vulnerability, "summary") ?? id} in {package.Name}@{package.Version}",
                        Description = Str(vulnerability, "details"),
                        Package = package,
                        Location = sourceFile is null ? null : new SourceLocation(sourceFile),
                        Aliases = aliases,
                        FixedVersions = FixedVersions(vulnerability, package),
                        References = References(vulnerability),
                        Engines = [engine],
                    });
                }
            }
        }

        return findings;
    }

    /// <summary>OSV-Scanner groups aliases together and gives each group a max CVSS score.</summary>
    private static Dictionary<string, Severity> GroupSeverities(JsonElement entry)
    {
        var map = new Dictionary<string, Severity>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in JsonGuards.Array(entry, "groups").Where(JsonGuards.IsObject))
        {
            var severity = Str(group, "max_severity") is { } score
                && double.TryParse(score, NumberStyles.Float, CultureInfo.InvariantCulture, out var cvss)
                ? FromCvss(cvss)
                : Severity.Unknown;

            foreach (var id in Strings(group, "ids"))
            {
                map[id] = severity;
            }
        }

        return map;
    }

    public static Severity FromCvss(double score) => score switch
    {
        >= 9.0 => Severity.Critical,
        >= 7.0 => Severity.High,
        >= 4.0 => Severity.Medium,
        > 0 => Severity.Low,
        _ => Severity.Unknown,
    };

    private static Severity DatabaseSeverity(JsonElement vulnerability) =>
        vulnerability.TryGetProperty("database_specific", out var db) && Str(db, "severity") is { } text
            ? text.ToUpperInvariant() switch
            {
                "CRITICAL" => Severity.Critical,
                "HIGH" => Severity.High,
                "MODERATE" or "MEDIUM" => Severity.Medium,
                "LOW" => Severity.Low,
                _ => Severity.Unknown,
            }
            : Severity.Unknown;

    private static List<string> FixedVersions(JsonElement vulnerability, PackageRef package)
    {
        var fixes = new List<string>();
        foreach (var item in JsonGuards.Array(vulnerability, "affected").Where(JsonGuards.IsObject))
        {
            if (item.TryGetProperty("package", out var pkg)
                && !string.Equals(Str(pkg, "name"), package.Name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var range in JsonGuards.Array(item, "ranges"))
            {
                foreach (var e in JsonGuards.Array(range, "events"))
                {
                    if (Str(e, "fixed") is { } fixedVersion)
                    {
                        fixes.Add(fixedVersion);
                    }
                }
            }
        }

        return fixes.Distinct().ToList();
    }

    private static List<string> References(JsonElement vulnerability) =>
        vulnerability.TryGetProperty("references", out var refs) && refs.ValueKind == JsonValueKind.Array
            ? refs.EnumerateArray().Select(r => Str(r, "url")).OfType<string>().ToList()
            : [];

    private static List<string> Strings(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
            : [];

    private static string? Str(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
