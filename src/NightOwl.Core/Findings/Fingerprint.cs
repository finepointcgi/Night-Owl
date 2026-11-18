using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NightOwl.Core.Findings;

/// <summary>
/// Builds stable finding ids. The same issue must get the same id across scans
/// (so triage decisions stick) and across engines (so duplicates merge).
/// </summary>
public static partial class Fingerprint
{
    /// <summary>
    /// Vulnerability in a dependency. Keyed on the package and the canonical advisory id,
    /// never on file path, so moving a lockfile does not reset triage.
    /// </summary>
    public static string ForVulnerability(PackageRef package, string advisoryId, IEnumerable<string> aliases)
    {
        var canonical = CanonicalAdvisoryId(advisoryId, aliases);
        return Hash("vuln", package.Ecosystem.ToLowerInvariant(), package.Name.ToLowerInvariant(), package.Version, canonical);
    }

    /// <summary>License issue for one package version.</summary>
    public static string ForLicense(PackageRef package, string license) =>
        Hash("license", package.Ecosystem.ToLowerInvariant(), package.Name.ToLowerInvariant(), package.Version, license.ToUpperInvariant());

    /// <summary>
    /// Code-level finding (SAST, secrets, IaC). Keyed on rule, file and the normalized
    /// code snippet rather than the line number, so unrelated edits above it do not change the id.
    /// </summary>
    public static string ForCode(string ruleId, string path, string? snippet, int? line)
    {
        var normalizedPath = path.Replace('\\', '/').TrimStart('.', '/');
        var anchor = string.IsNullOrWhiteSpace(snippet) ? "" : NormalizeSnippet(snippet);
        if (anchor.Length == 0)
        {
            // Nothing but whitespace — or, since comment stripping, nothing but a comment:
            // fall back to the line, or every such finding in the file would share one id.
            anchor = $"line:{line}";
        }

        return Hash("code", ruleId, normalizedPath, anchor);
    }

    /// <summary>
    /// Finding from active testing. Keyed on rule, method, the URL without query values (query
    /// parameter names are kept, sorted) and the affected parameter, so re-tests produce the same id.
    /// </summary>
    public static string ForDynamic(string ruleId, string method, Uri uri, string? parameter)
    {
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2)[0])
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);
        var location = $"{uri.Scheme}://{uri.Host.ToLowerInvariant()}:{uri.Port}{uri.AbsolutePath}?{string.Join('&', query)}";
        return Hash("dynamic", ruleId, method.ToUpperInvariant(), location, parameter ?? "");
    }

    /// <summary>
    /// Prefer a CVE id, then GHSA, then whatever the engine gave, so two engines that
    /// report the same CVE under different ids still produce one fingerprint.
    /// </summary>
    public static string CanonicalAdvisoryId(string advisoryId, IEnumerable<string> aliases)
    {
        var all = aliases.Prepend(advisoryId).Select(a => a.Trim().ToUpperInvariant()).ToList();
        return all.Where(a => a.StartsWith("CVE-", StringComparison.Ordinal)).Order(StringComparer.Ordinal).FirstOrDefault()
            ?? all.Where(a => a.StartsWith("GHSA-", StringComparison.Ordinal)).Order(StringComparer.Ordinal).FirstOrDefault()
            ?? all[0];
    }

    internal static string NormalizeSnippet(string snippet) => Whitespace().Replace(StripComments(snippet), " ").Trim();

    /// <summary>
    /// Removes //, /* */ and # comments so editing a comment (or moving code between a //
    /// language and a # language style) does not mint a new fingerprint and re-open triage.
    /// The scan is quote-aware: comment markers inside '...', "..." or `...` literals are
    /// kept, and a # only starts a comment at a word boundary, so "http://a#b" and C#
    /// member access survive. It is a heuristic over a snippet, not a parser — the failure
    /// mode is keeping a comment (an id changes when the comment does), never eating code.
    /// </summary>
    internal static string StripComments(string snippet)
    {
        var result = new StringBuilder(snippet.Length);
        var quote = '\0';
        for (var i = 0; i < snippet.Length; i++)
        {
            var c = snippet[i];
            if (quote != '\0')
            {
                result.Append(c);
                if (c == '\\' && i + 1 < snippet.Length)
                {
                    result.Append(snippet[++i]);
                }
                else if (c == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (c is '"' or '\'' or '`')
            {
                quote = c;
                result.Append(c);
                continue;
            }

            if (c == '/' && i + 1 < snippet.Length && snippet[i + 1] == '/' &&
                (result.Length == 0 || result[^1] != ':'))
            {
                // Not "://" — a URL or path separator in a config value is not a comment.
                i = SkipToEndOfLine(snippet, i + 2);
                continue;
            }

            if (c == '/' && i + 1 < snippet.Length && snippet[i + 1] == '*')
            {
                var end = snippet.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? snippet.Length - 1 : end + 1;
                continue;
            }

            if (c == '#' && (result.Length == 0 || char.IsWhiteSpace(result[^1])))
            {
                i = SkipToEndOfLine(snippet, i + 1);
                continue;
            }

            result.Append(c);
        }

        return result.ToString();
    }

    /// <summary>Index of the newline ending the line that starts before <paramref name="from"/>, or the last index.</summary>
    private static int SkipToEndOfLine(string text, int from)
    {
        var newline = text.IndexOf('\n', from);
        return newline < 0 ? text.Length - 1 : newline - 1;
    }

    private static string Hash(params string[] parts)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001f', parts)));
        return Convert.ToHexStringLower(bytes)[..32];
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
