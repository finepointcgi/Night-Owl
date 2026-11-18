using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace NightOwl.Cli;

/// <summary>
/// Rewrites one requirement in a composer.json, keeping the constraint style the project
/// chose: an exact pin stays exact, ^ and ~ keep their operator. Only simple constraints
/// are edited — a single version with an optional ^ or ~ prefix. Ranges, wildcards and
/// branch constraints (dev-master, *) are left to a human, as are packages the manifest
/// does not require directly: Composer has no overrides mechanism to pin a transitive
/// dependency with. A package required in both require and require-dev has every
/// declaration retargeted (all-or-nothing), and the file's indentation and character
/// escaping are preserved, so the fix stays a one-line diff.
/// </summary>
internal static partial class ComposerManifestEditor
{
    public static string? SetRequirement(string composerJson, string package, string targetVersion)
    {
        var root = JsonNode.Parse(composerJson)?.AsObject();
        if (root is null)
        {
            return null;
        }

        var edits = new List<(JsonObject Requirements, string Key, string Retargeted)>();
        foreach (var section in new[] { "require", "require-dev" })
        {
            if (root[section] is not JsonObject requirements)
            {
                continue;
            }

            var key = requirements.Select(p => p.Key)
                .FirstOrDefault(k => string.Equals(k, package, StringComparison.OrdinalIgnoreCase));
            if (key is null || requirements[key]?.GetValue<string>() is not { } constraint)
            {
                continue;
            }

            if (Retarget(constraint, targetVersion) is not { } retargeted)
            {
                return null; // Declared, but in a form a human must move: no partial edits.
            }

            edits.Add((requirements, key, retargeted));
        }

        if (edits.Count == 0)
        {
            return null;
        }

        foreach (var (requirements, key, retargeted) in edits)
        {
            requirements[key] = retargeted;
        }

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            IndentSize = DetectIndent(composerJson),
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        return root.ToJsonString(options) + "\n";
    }

    /// <summary>The file's own indentation width (spaces before the first nested key), defaulting to 4 — composer's own style.</summary>
    private static int DetectIndent(string json)
    {
        var match = IndentedKey().Match(json);
        return match.Success ? match.Groups[1].Length : 4;
    }

    private static string? Retarget(string constraint, string targetVersion)
    {
        var trimmed = constraint.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        if (char.IsDigit(trimmed[0]))
        {
            // A lone version only: digits, dots and a pre-release suffix. Anything with a
            // space, comma, | or * is a range or wildcard and is left alone.
            return trimmed.All(c => char.IsDigit(c) || c is '.' or '-' or '+' or '_' || char.IsLetter(c)) ? targetVersion : null;
        }

        return trimmed[0] is '^' or '~' && Retarget(trimmed[1..].TrimStart(), targetVersion) is not null
            ? $"{trimmed[0]}{targetVersion}"
            : null;
    }

    [GeneratedRegex("(?m)^(\\s+)\"")]
    private static partial Regex IndentedKey();
}
