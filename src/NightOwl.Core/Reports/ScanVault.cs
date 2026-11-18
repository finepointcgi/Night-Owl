using System.Globalization;
using System.Text.Json;
using NightOwl.Core.Findings;

namespace NightOwl.Core.Reports;

/// <summary>One saved scan in a project's history.</summary>
public sealed record ScanInfo(string Id, DateTimeOffset At, int Open, int Critical, int High, double Seconds, long ManifestSequence, string? Label);

/// <summary>
/// Every scan of a project, kept as its own file under NIGHTOWL_HOME/reports/scans/&lt;project&gt;/, so an older
/// scan can be reopened and two scans compared. A scan can carry a label such as a release version
/// (<c>nightowl scan --label v1.4.0</c>). Only the newest <see cref="MaxScans"/> are kept; labelled scans are kept too.
/// </summary>
public sealed class ScanVault(string homeDirectory)
{
    public const int MaxScans = 30;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private string DirectoryFor(string project) => Path.Combine(homeDirectory, "reports", "scans", ReportArchive.KeyFor(project));
    private string LabelsPath(string project) => Path.Combine(DirectoryFor(project), "labels.json");

    /// <summary>The id of a scan: its start time, sortable and safe in a file name or URL.</summary>
    public static string IdFor(ScanReport report) => report.StartedAt.UtcDateTime.ToString("yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture);

    public string Save(ScanReport report, string? label = null)
    {
        var directory = DirectoryFor(report.Project);
        Directory.CreateDirectory(directory);
        var id = IdFor(report);
        File.WriteAllText(Path.Combine(directory, id + ".json"), report.ToJson());
        if (!string.IsNullOrWhiteSpace(label))
        {
            SetLabel(report.Project, id, label);
        }

        Prune(report.Project);
        return id;
    }

    public IReadOnlyList<ScanInfo> List(string project)
    {
        var directory = DirectoryFor(project);
        if (!Directory.Exists(directory))
        {
            return [];
        }

        var labels = Labels(project);
        var scans = new List<ScanInfo>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.json").Where(f => !f.EndsWith("labels.json", StringComparison.Ordinal)))
        {
            if (Read(file) is { } report)
            {
                var open = ReportStats.Open(report).ToList();
                scans.Add(new ScanInfo(Path.GetFileNameWithoutExtension(file), report.StartedAt, open.Count,
                    open.Count(f => f.Severity == Severity.Critical), open.Count(f => f.Severity == Severity.High),
                    report.Seconds, report.ManifestSequence, labels.GetValueOrDefault(Path.GetFileNameWithoutExtension(file))));
            }
        }

        return scans.OrderByDescending(s => s.At).ToList();
    }

    public ScanReport? Load(string project, string id)
    {
        // The id becomes part of a path: accept only what IdFor can produce.
        if (id.Length != 19 || !id.All(c => char.IsAsciiDigit(c) || c is 'T' or 'Z'))
        {
            return null;
        }

        var path = Path.Combine(DirectoryFor(project), id + ".json");
        return File.Exists(path) ? Read(path) : null;
    }

    public void SetLabel(string project, string id, string? label)
    {
        var labels = Labels(project);
        if (string.IsNullOrWhiteSpace(label)) { labels.Remove(id); } else { labels[id] = label.Trim()[..Math.Min(label.Trim().Length, 60)]; }
        Directory.CreateDirectory(DirectoryFor(project));
        File.WriteAllText(LabelsPath(project), JsonSerializer.Serialize(labels, Json));
    }

    private Dictionary<string, string> Labels(string project)
    {
        try
        {
            return File.Exists(LabelsPath(project))
                ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(LabelsPath(project)), Json) ?? []
                : [];
        }
        catch (Exception e) when (e is JsonException or IOException)
        {
            return [];
        }
    }

    private void Prune(string project)
    {
        var labels = Labels(project);
        var files = Directory.EnumerateFiles(DirectoryFor(project), "*.json")
            .Where(f => !f.EndsWith("labels.json", StringComparison.Ordinal))
            .OrderByDescending(f => f, StringComparer.Ordinal).ToList();
        foreach (var old in files.Skip(MaxScans).Where(f => !labels.ContainsKey(Path.GetFileNameWithoutExtension(f))))
        {
            try { File.Delete(old); } catch (IOException) { /* Still in use; the next scan prunes it. */ }
        }
    }

    private static ScanReport? Read(string path)
    {
        try { return ScanReport.FromJson(File.ReadAllText(path)); }
        catch (Exception e) when (e is JsonException or InvalidDataException or IOException) { return null; }
    }
}

/// <summary>What changed between two scans of the same project.</summary>
public sealed record ScanDiff(IReadOnlyList<Finding> New, IReadOnlyList<Finding> Resolved, IReadOnlyList<(Finding Before, Finding After)> Changed, int Unchanged)
{
    /// <summary>Compares open findings by fingerprint: what appeared, what went away, and what stayed with a new severity or triage state.</summary>
    public static ScanDiff Compare(ScanReport older, ScanReport newer)
    {
        var before = ReportStats.Open(older).ToDictionary(f => f.Id, StringComparer.Ordinal);
        var after = ReportStats.Open(newer).ToDictionary(f => f.Id, StringComparer.Ordinal);
        var added = after.Values.Where(f => !before.ContainsKey(f.Id)).OrderByDescending(f => f.Severity).ToList();
        var resolved = before.Values.Where(f => !after.ContainsKey(f.Id)).OrderByDescending(f => f.Severity).ToList();
        var changed = after.Values.Where(f => before.TryGetValue(f.Id, out var b) && (b.Severity != f.Severity || b.Triage != f.Triage))
            .Select(f => (before[f.Id], f)).ToList();
        return new ScanDiff(added, resolved, changed, after.Count - added.Count - changed.Count);
    }
}
