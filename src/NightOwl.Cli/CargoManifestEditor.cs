using System.Text.RegularExpressions;

namespace NightOwl.Cli;

/// <summary>
/// Rewrites the version requirement of a direct dependency in a Cargo.toml — every
/// declaration of it, across [dependencies], [dev-dependencies], [build-dependencies],
/// workspace and target sections — keeping the manifest's own pinning style (a bare "1.2"
/// stays a caret-style requirement, "=1.2" stays exact). Only simple requirements are
/// edited: a single version with an optional =, ~ or ^ prefix. Ranges, wildcards,
/// workspace-inherited and git/path dependencies are left to a human, reported by
/// returning null, as are packages the manifest does not declare directly.
/// </summary>
internal static partial class CargoManifestEditor
{
    private static readonly string[] DependencySections = ["dependencies", "dev-dependencies", "build-dependencies"];

    public static string? SetVersionRequirement(string toml, string package, string targetVersion)
    {
        var newline = toml.Contains("\r\n") ? "\r\n" : "\n";
        var lines = toml.Split(newline);

        var section = SectionKind.Other;
        string? tablePackage = null; // Effective package name of a [dependencies.<name>] table.
        var changed = false;
        var i = 0;
        while (i < lines.Length)
        {
            var line = lines[i];
            if (SectionHeader().Match(line) is { Success: true } header)
            {
                var segments = SplitSegments(header.Groups[1].Value);
                section = Classify(segments, out tablePackage);
                i++;
                continue;
            }

            switch (section)
            {
                case SectionKind.Entries:
                    // Not return-on-first-edit: the same crate can be declared in several
                    // sections ([dependencies], [dev-dependencies], a target table), and every
                    // declaration has to move or the lockfile update fights the stale one.
                    if (TryEditEntry(lines, i, package, targetVersion))
                    {
                        changed = true;
                    }

                    break;

                case SectionKind.DependencyTable:
                {
                    // The table's real package name can differ from the section name when the
                    // dependency is renamed (package = "..."), so read the whole table first.
                    var end = i;
                    while (end < lines.Length && !SectionHeader().IsMatch(lines[end]))
                    {
                        end++;
                    }

                    string? effective = null;
                    for (var j = i; j < end; j++)
                    {
                        if (PackageKey().Match(lines[j]) is { Success: true } rename)
                        {
                            effective = rename.Groups[1].Value;
                            break;
                        }
                    }

                    effective ??= tablePackage;

                    if (effective == package)
                    {
                        for (var j = i; j < end; j++)
                        {
                            if (BareVersion().Match(lines[j]) is { Success: true } versionLine &&
                                Retarget(versionLine.Groups[2].Value, targetVersion) is { } retargeted)
                            {
                                lines[j] = $"{versionLine.Groups[1].Value}version = \"{retargeted}\"{versionLine.Groups[3].Value}";
                                changed = true;
                                break;
                            }
                        }
                    }

                    i = end;
                    continue;
                }
            }

            i++;
        }

        return changed ? string.Join(newline, lines) : null;
    }

    private enum SectionKind { Other, Entries, DependencyTable }

    private static SectionKind Classify(List<string> segments, out string? tablePackage)
    {
        tablePackage = null;
        var marker = segments.FindIndex(s => DependencySections.Contains(s));
        if (marker < 0)
        {
            return SectionKind.Other;
        }

        if (marker == segments.Count - 1)
        {
            return SectionKind.Entries;
        }

        if (marker == segments.Count - 2)
        {
            tablePackage = segments[^1];
            return SectionKind.DependencyTable;
        }

        return SectionKind.Other;
    }

    /// <summary>One `key = ...` line inside a dependencies section. True when it declared the package and was edited.</summary>
    private static bool TryEditEntry(string[] lines, int index, string package, string targetVersion)
    {
        var line = lines[index];

        // Dotted-key form: serde.version = "1.0"
        if (DottedVersion().Match(line) is { Success: true } dotted)
        {
            var dottedKey = dotted.Groups[3].Success ? dotted.Groups[3].Value
                : dotted.Groups[4].Success ? dotted.Groups[4].Value
                : dotted.Groups[5].Value;
            if (dottedKey != package || Retarget(dotted.Groups[6].Value, targetVersion) is not { } dottedTarget)
            {
                return false;
            }

            lines[index] = $"{dotted.Groups[1].Value}{dotted.Groups[2].Value}.version = \"{dottedTarget}\"{dotted.Groups[7].Value}";
            return true;
        }

        if (Entry().Match(line) is not { Success: true } entry || KeyToken().Match(line) is not { Success: true } keyToken)
        {
            return false;
        }

        var key = keyToken.Groups[1].Success ? keyToken.Groups[1].Value
            : keyToken.Groups[2].Success ? keyToken.Groups[2].Value
            : keyToken.Groups[3].Value;
        var rest = entry.Groups[2].Value;
        var renamed = key != package && rest.StartsWith('{') &&
                      PackageKey().Match(rest) is { Success: true } rename && rename.Groups[1].Value == package;
        if (key != package && !renamed)
        {
            return false;
        }

        if (rest.StartsWith('"'))
        {
            // String form: serde = "1.0"
            var close = rest.IndexOf('"', 1);
            if (close < 0)
            {
                return false; // Unterminated string: invalid TOML, leave it alone rather than throw.
            }

            var spec = rest[1..close];
            if (Retarget(spec, targetVersion) is not { } retargeted)
            {
                return false;
            }

            lines[index] = $"{entry.Groups[1].Value}\"{retargeted}\"{rest[(close + 1)..]}";
            return true;
        }

        if (rest.StartsWith('{'))
        {
            // Inline-table form: serde = { version = "1.0", features = ["derive"] }
            var versionKey = VersionKey().Match(rest);
            if (!versionKey.Success || Retarget(versionKey.Groups[1].Value, targetVersion) is not { } retargeted)
            {
                return false;
            }

            lines[index] = entry.Groups[1].Value + VersionKey().Replace(rest, $"version = \"{retargeted}\"", 1);
            return true;
        }

        return false;
    }

    /// <summary>
    /// The target version in the manifest's own style: a bare or ^ requirement takes the plain
    /// target, = and ~ keep their operator. Anything more complex (ranges, wildcards) returns
    /// null so the requirement is left untouched.
    /// </summary>
    private static string? Retarget(string spec, string targetVersion)
    {
        var trimmed = spec.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        if (char.IsDigit(trimmed[0]))
        {
            // A compound requirement can also start with a digit ("1.0, <1.5"); only a lone
            // version (digits, dots, and a pre-release/build suffix) is safe to replace.
            return trimmed.All(c => char.IsDigit(c) || c is '.' or '-' or '+' or '_' || char.IsLetter(c)) ? targetVersion : null;
        }

        return trimmed[0] is '=' or '~' or '^' && trimmed[1..].TrimStart() is { Length: > 0 } rest &&
               Retarget(rest, targetVersion) is not null
            ? $"{trimmed[0]}{targetVersion}"
            : null;
    }

    /// <summary>Splits a section header body on dots that are not inside quotes: target.'cfg(windows)'.dependencies</summary>
    private static List<string> SplitSegments(string header)
    {
        var segments = new List<string>();
        var current = "";
        var quote = '\0';
        foreach (var c in header)
        {
            if (quote != '\0')
            {
                if (c == quote)
                {
                    quote = '\0';
                }
                else
                {
                    current += c;
                }
            }
            else if (c is '\'' or '"')
            {
                quote = c;
            }
            else if (c == '.')
            {
                segments.Add(current.Trim());
                current = "";
            }
            else
            {
                current += c;
            }
        }

        segments.Add(current.Trim());
        return segments;
    }

    [GeneratedRegex(@"^\s*\[\[?\s*(.+?)\s*\]\]?\s*(?:#.*)?$")]
    private static partial Regex SectionHeader();

    [GeneratedRegex(@"^(\s*(?:""[^""]+""|'[^']+'|[A-Za-z0-9_-]+)\s*=\s*)(.*)$")]
    private static partial Regex Entry();

    [GeneratedRegex(@"^\s*(?:""([^""]+)""|'([^']+)'|([A-Za-z0-9_-]+))\s*=")]
    private static partial Regex KeyToken();

    [GeneratedRegex(@"^(\s*)(""([^""]+)""|'([^']+)'|([A-Za-z0-9_-]+))\.version\s*=\s*""([^""]*)""(.*)$")]
    private static partial Regex DottedVersion();

    [GeneratedRegex(@"version\s*=\s*""([^""]*)""")]
    private static partial Regex VersionKey();

    [GeneratedRegex(@"package\s*=\s*""([^""]+)""")]
    private static partial Regex PackageKey();

    [GeneratedRegex(@"^(\s*)version\s*=\s*""([^""]*)""(.*)$")]
    private static partial Regex BareVersion();
}
