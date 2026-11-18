using System.Diagnostics;
using NightOwl.Core.Findings;
using NightOwl.Core.Gates;
using NightOwl.Core.Reports;
using NightOwl.Core.Triage;

namespace NightOwl.Tests;

public sealed class TriageAndGateTests : IDisposable
{
    private readonly string _home = Directory.CreateTempSubdirectory("nightowl-triage-home-").FullName;
    private readonly string _project = Directory.CreateTempSubdirectory("nightowl-triage-project-").FullName;

    public void Dispose()
    {
        Directory.Delete(_home, recursive: true);
        Directory.Delete(_project, recursive: true);
    }

    [Fact]
    public void Saved_decisions_apply_on_the_next_scan_and_reset_removes_them()
    {
        var store = new TriageStore(_home);
        var finding = Code("abc123", "a.py", 3);

        store.Save(_project, Decision("abc123", TriageState.FalsePositive), shared: false);
        Assert.Equal(TriageState.FalsePositive, store.Apply(_project, [finding], DateTimeOffset.UtcNow)[0].Triage);

        store.Save(_project, Decision("abc123", TriageState.New), shared: false);
        Assert.Equal(TriageState.New, store.Apply(_project, [finding], DateTimeOffset.UtcNow)[0].Triage);
    }

    [Fact]
    public void Shared_repository_file_wins_over_local_decision()
    {
        var store = new TriageStore(_home);
        store.Save(_project, Decision("abc123", TriageState.AcceptedRisk), shared: false);
        var sharedPath = store.Save(_project, Decision("abc123", TriageState.Confirmed), shared: true);

        Assert.Equal(Path.Combine(_project, ".nightowl", "triage.json"), sharedPath);
        Assert.Equal(TriageState.Confirmed, store.Apply(_project, [Code("abc123", "a.py", 1)], DateTimeOffset.UtcNow)[0].Triage);
        Assert.Contains("\"confirmed\"", File.ReadAllText(sharedPath)); // readable in PR review
    }

    [Fact]
    public void Expired_accepted_risk_counts_again()
    {
        var store = new TriageStore(_home);
        store.Save(_project, Decision("abc123", TriageState.AcceptedRisk) with { Expires = DateTimeOffset.UtcNow.AddDays(-1) }, shared: false);

        Assert.Equal(TriageState.New, store.Apply(_project, [Code("abc123", "a.py", 1)], DateTimeOffset.UtcNow)[0].Triage);
    }

    [Fact]
    public void Baseline_marks_only_unseen_fingerprints_as_new()
    {
        var baseline = Report([Code("old", "a.py", 1)]);
        var ids = NewCodeDetector.AgainstBaseline([Code("old", "a.py", 9), Code("fresh", "b.py", 2)], baseline);

        Assert.Equal(["fresh"], ids);
    }

    [Fact]
    public void Diff_parser_reads_new_side_line_numbers()
    {
        const string diff = """
            diff --git a/app.py b/app.py
            --- a/app.py
            +++ b/app.py
            @@ -2,0 +3,2 @@ def x():
            +    eval(a)
            +    eval(b)
            @@ -10 +12 @@
            -old
            +new
            diff --git a/new.js b/new.js
            --- /dev/null
            +++ b/new.js
            @@ -0,0 +1,3 @@
            """;

        var changed = NewCodeDetector.ParseDiff(diff);

        Assert.Equal([3, 4, 12], changed["app.py"].Order());
        Assert.Equal([1, 2, 3], changed["new.js"].Order());
    }

    [Fact]
    public void Since_git_ref_flags_changed_lines_and_new_dependency_versions_only()
    {
        Git("init", "-q", "-b", "main");
        Git("config", "user.email", "t@example.invalid");
        Git("config", "user.name", "t");
        File.WriteAllText(Path.Combine(_project, "app.py"), "a = 1\nb = 2\n");
        File.WriteAllText(Path.Combine(_project, "requirements.txt"), "requests==2.0.0\n");
        Git("add", ".");
        Git("commit", "-qm", "base");
        Git("checkout", "-qb", "feature");
        File.WriteAllText(Path.Combine(_project, "app.py"), "a = 1\nb = 2\neval(x)\n");
        File.WriteAllText(Path.Combine(_project, "requirements.txt"), "requests==2.0.0\npyyaml==5.1\n");
        Git("commit", "-qam", "change");

        Finding[] findings =
        [
            Code("old-line", "app.py", 1),
            Code("new-line", "app.py", 3),
            Dependency("old-dep", "requests", "2.0.0"),
            Dependency("new-dep", "pyyaml", "5.1"),
        ];

        var ids = NewCodeDetector.SinceGitRef(findings, _project, "main");

        Assert.Equal(["new-dep", "new-line"], ids.Order());
    }

    [Fact]
    public void Rename_parser_reads_from_to_pairs()
    {
        const string diff = """
            diff --git a/old.py b/new.py
            similarity index 90%
            rename from old.py
            rename to new.py
            diff --git a/plain.py b/plain.py
            --- a/plain.py
            +++ b/plain.py
            """;

        var renames = NewCodeDetector.ParseRenames(diff);

        Assert.Equal("old.py", renames["new.py"]);
        Assert.Single(renames);
    }

    [Fact]
    public void Rename_parser_unquotes_git_quoted_paths()
    {
        const string diff = """
            diff --git a/my old.py b/my new.py
            similarity index 100%
            rename from "my old.py"
            rename to "my new.py"
            """;

        var renames = NewCodeDetector.ParseRenames(diff);

        Assert.Equal("my old.py", renames["my new.py"]);
    }

    [Fact]
    public void Since_git_ref_survives_file_renames()
    {
        Git("init", "-q", "-b", "main");
        Git("config", "user.email", "t@example.invalid");
        Git("config", "user.name", "t");
        File.WriteAllText(Path.Combine(_project, "app.py"), "a = 1\nb = 2\n");
        File.WriteAllText(Path.Combine(_project, "requirements.txt"), "requests==2.0.0\n");
        Git("add", ".");
        Git("commit", "-qm", "base");
        Git("checkout", "-qb", "feature");
        // Rename both files; app.py also gains one line, the lockfile is untouched.
        Git("mv", "app.py", "main.py");
        File.AppendAllText(Path.Combine(_project, "main.py"), "eval(x)\n");
        Git("mv", "requirements.txt", "reqs.txt");
        Git("commit", "-qam", "rename");

        Finding[] findings =
        [
            Code("old-line", "main.py", 1),
            Code("new-line", "main.py", 3),
            Dependency("old-dep", "requests", "2.0.0") with { Location = new SourceLocation("reqs.txt") },
        ];

        var ids = NewCodeDetector.SinceGitRef(findings, _project, "main");

        Assert.Equal(["new-line"], ids.Order());
    }

    private void Git(params string[] args)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = _project, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) { start.ArgumentList.Add(arg); }
        using var process = Process.Start(start)!;
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"git {string.Join(' ', args)}: {process.StandardError.ReadToEnd()}");
    }

    private static TriageDecision Decision(string id, TriageState state) =>
        new() { FindingId = id, State = state, Reason = "test", At = DateTimeOffset.UtcNow };

    private static Finding Code(string id, string path, int line) => new()
    {
        Id = id, Category = FindingCategory.Code, Severity = Severity.High, RuleId = "r", Title = "t",
        Location = new SourceLocation(path, line),
    };

    private static Finding Dependency(string id, string name, string version) => new()
    {
        Id = id, Category = FindingCategory.Vulnerability, Severity = Severity.High, RuleId = "CVE-1", Title = "t",
        Package = new PackageRef(name, version, "PyPI"), Location = new SourceLocation("requirements.txt"),
    };

    private static ScanReport Report(IReadOnlyList<Finding> findings) => new()
    {
        Project = "/p", StartedAt = DateTimeOffset.UnixEpoch, Seconds = 0, ManifestSequence = 0, Engines = [], Findings = findings,
    };
}
