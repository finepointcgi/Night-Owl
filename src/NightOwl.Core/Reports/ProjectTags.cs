using System.Text.Json;

namespace NightOwl.Core.Reports;

/// <summary>
/// Free-form tags on projects (team, environment, release train) so the dashboard can group and filter them.
/// One small JSON file, NIGHTOWL_HOME/tags.json, keyed by <see cref="ReportArchive.KeyFor"/>.
/// </summary>
public sealed class ProjectTags(string homeDirectory)
{
    public const int MaxTags = 10;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private string PathFor => Path.Combine(homeDirectory, "tags.json");

    /// <summary>Lower-case, letters, digits and <c>. _ : -</c>, up to 30 characters; null when nothing usable is left.</summary>
    public static string? Normalize(string? tag)
    {
        var cleaned = new string((tag ?? "").Trim().ToLowerInvariant().Replace(' ', '-').Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '-').ToArray());
        return cleaned.Length == 0 ? null : cleaned[..Math.Min(cleaned.Length, 30)];
    }

    public IReadOnlyList<string> Get(string project) => Load().GetValueOrDefault(ReportArchive.KeyFor(project)) ?? [];

    public IReadOnlyDictionary<string, string[]> All() => Load();

    public void Add(string project, IEnumerable<string?> tags)
    {
        var all = Load();
        var key = ReportArchive.KeyFor(project);
        var merged = (all.GetValueOrDefault(key) ?? []).Concat(tags.Select(Normalize).OfType<string>())
            .Distinct(StringComparer.Ordinal).Take(MaxTags).Order(StringComparer.Ordinal).ToArray();
        all[key] = merged;
        Save(all);
    }

    public void Remove(string project, string tag)
    {
        var all = Load();
        var key = ReportArchive.KeyFor(project);
        if (!all.TryGetValue(key, out var current)) { return; }
        var left = current.Where(t => !t.Equals(tag, StringComparison.Ordinal)).ToArray();
        if (left.Length == 0) { all.Remove(key); } else { all[key] = left; }
        Save(all);
    }

    private Dictionary<string, string[]> Load()
    {
        try
        {
            return File.Exists(PathFor) ? JsonSerializer.Deserialize<Dictionary<string, string[]>>(File.ReadAllText(PathFor), Json) ?? [] : [];
        }
        catch (Exception e) when (e is JsonException or IOException)
        {
            return [];
        }
    }

    private void Save(Dictionary<string, string[]> all)
    {
        Directory.CreateDirectory(homeDirectory);
        File.WriteAllText(PathFor, JsonSerializer.Serialize(all, Json));
    }
}
