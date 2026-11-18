using System.Text.RegularExpressions;

namespace NightOwl.Engines.Execution;

/// <summary>
/// Turns the root-relative paths git ignores into each engine's own "skip this" arguments. Paths come from
/// <c>git ls-files</c> and are passed as separate arguments (never through a shell), and in the <c>--flag=value</c>
/// form where the value could otherwise be mistaken for an option.
/// </summary>
public static class Exclusions
{
    /// <summary>Opengrep: <c>--exclude=path</c> skips a file or a whole directory.</summary>
    public static IEnumerable<string> Opengrep(IEnumerable<string> excluded) => excluded.Select(p => $"--exclude={p}");

    /// <summary>Syft: globs relative to the scan root, written <c>./path</c>.</summary>
    public static IEnumerable<string> Syft(IEnumerable<string> excluded) => excluded.SelectMany(p => new[] { "--exclude", $"./{p}" });

    /// <summary>
    /// OSV-Scanner: a regular expression over the path it walks. That path has no leading slash (inside the container
    /// it reads <c>src/bin/...</c>, where <c>src</c> is the mount point), so each pattern is anchored to the scanned
    /// folder, as seen from the container or on the host, and a root-level <c>bin</c> doesn't hide <c>src/bin</c>.
    /// </summary>
    public static IEnumerable<string> OsvScanner(IEnumerable<string> excluded, string rootPath)
    {
        var root = Regex.Escape(rootPath.Replace('\\', '/').Trim('/'));
        return excluded.SelectMany(p => new[] { "--experimental-exclude", $"r:(?:^|/)(?:src|{root})/{Regex.Escape(p)}(?:/|$)" });
    }

    /// <summary>lizard: <c>-x</c> takes shell-style patterns over the full path.</summary>
    public static IEnumerable<string> Lizard(IEnumerable<string> excluded) => excluded.SelectMany(p => new[] { "-x", $"*/{p}/*", "-x", $"*/{p}" });

    /// <summary>
    /// gitleaks has no exclude flag, so the paths go into a config that extends the default rules with an allowlist.
    /// Paths are anchored to the scanned folder as seen from inside the container (<c>/src</c>) or on the host,
    /// so a root-level <c>bin</c> doesn't hide <c>src/bin</c>. Null when there is nothing to exclude.
    /// </summary>
    public static string? GitleaksConfig(IEnumerable<string> excluded, string rootPath)
    {
        var root = Regex.Escape(rootPath.Replace('\\', '/').TrimEnd('/'));
        var patterns = excluded
            .Where(p => !p.Contains("'''", StringComparison.Ordinal))
            .Select(p => $"'''^(?:/src|{root})/{Regex.Escape(p)}(?:/|$)'''")
            .ToList();
        return patterns.Count == 0
            ? null
            : "[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = \"paths git ignores\"\npaths = [\n  " + string.Join(",\n  ", patterns) + ",\n]\n";
    }

    /// <summary>Trivy: <c>--skip-dirs</c> for folders and <c>--skip-files</c> for single files (told apart on the host).</summary>
    public static IEnumerable<string> Trivy(IEnumerable<string> excluded, string rootPath, string sourceToken) =>
        excluded.SelectMany(p => new[] { Directory.Exists(Path.Combine(rootPath, p)) ? "--skip-dirs" : "--skip-files", $"{sourceToken}/{p}" });

    /// <summary>cppcheck: <c>-i</c> ignores a path under the source folder.</summary>
    public static IEnumerable<string> Cppcheck(IEnumerable<string> excluded, string sourceToken) => excluded.SelectMany(p => new[] { "-i", $"{sourceToken}/{p}" });
}
