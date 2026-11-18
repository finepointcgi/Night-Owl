using NightOwl.Core.Findings;
using NightOwl.Core.Reports;

namespace NightOwl.Tests;

public sealed class ScanVaultTests : IDisposable
{
    private readonly string _home = Path.Combine(Path.GetTempPath(), "nightowl-vault-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_home)) { Directory.Delete(_home, true); }
    }

    private static Finding F(string id, Severity severity = Severity.High, TriageState triage = TriageState.New) => new()
    { Id = id, Category = FindingCategory.Vulnerability, Severity = severity, RuleId = id, Title = "t " + id, Triage = triage };

    private static ScanReport Report(DateTimeOffset at, params Finding[] findings) => new()
    {
        Project = "/p/app", StartedAt = at, Seconds = 1, ManifestSequence = 0, Engines = [], Findings = findings,
    };

    [Fact]
    public void Archive_save_keeps_every_scan_with_labels_newest_first()
    {
        var archive = new ReportArchive(_home);
        var t = new DateTimeOffset(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        archive.Save(Report(t, F("a")), label: "v1.0");
        archive.Save(Report(t.AddDays(1), F("a"), F("b")));

        var vault = new ScanVault(_home);
        var scans = vault.List("/p/app");
        Assert.Equal(2, scans.Count);
        Assert.Equal(2, scans[0].Open);                 // newest first
        Assert.Equal("v1.0", scans[1].Label);
        Assert.Equal(1, archive.LoadAll().Count);       // the latest-report listing is unchanged: snapshots live in a subfolder
        Assert.NotNull(vault.Load("/p/app", scans[1].Id));
    }

    [Fact]
    public void Load_rejects_ids_that_are_not_scan_ids()
    {
        var vault = new ScanVault(_home);
        Assert.Null(vault.Load("/p/app", "../../etc/passwd"));
        Assert.Null(vault.Load("/p/app", "labels"));
    }

    [Fact]
    public void Old_scans_are_pruned_but_labelled_ones_are_kept()
    {
        var vault = new ScanVault(_home);
        var t = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        vault.Save(Report(t, F("a")), "release-0");
        for (var i = 1; i <= ScanVault.MaxScans + 3; i++) { vault.Save(Report(t.AddDays(i), F("a"))); }

        var scans = vault.List("/p/app");
        Assert.Equal(ScanVault.MaxScans + 1, scans.Count);
        Assert.Contains(scans, s => s.Label == "release-0");
    }

    [Fact]
    public void Diff_reports_new_resolved_and_changed_findings()
    {
        var t = DateTimeOffset.UtcNow;
        var older = Report(t, F("keep"), F("gone"), F("sev", Severity.Medium));
        var newer = Report(t.AddDays(1), F("keep"), F("new", Severity.Critical), F("sev", Severity.High));

        var diff = ScanDiff.Compare(older, newer);

        Assert.Equal(["new"], diff.New.Select(f => f.Id));
        Assert.Equal(["gone"], diff.Resolved.Select(f => f.Id));
        Assert.Equal("sev", Assert.Single(diff.Changed).After.Id);
        Assert.Equal(1, diff.Unchanged);
    }

    [Fact]
    public void A_finding_triaged_as_false_positive_counts_as_resolved()
    {
        var t = DateTimeOffset.UtcNow;
        var diff = ScanDiff.Compare(Report(t, F("x")), Report(t.AddDays(1), F("x", triage: TriageState.FalsePositive)));
        Assert.Equal(["x"], diff.Resolved.Select(f => f.Id));
    }
}
