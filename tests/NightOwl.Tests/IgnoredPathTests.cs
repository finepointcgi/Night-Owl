using System.Diagnostics;
using NightOwl.Core.Engines;
using NightOwl.Engines.Execution;

namespace NightOwl.Tests;

public class IgnoredPathTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("nightowl-ignored-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private static bool Git(string folder, params string[] args)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = folder, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) { start.ArgumentList.Add(a); }
        using var p = Process.Start(start)!;
        p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return p.ExitCode == 0;
    }

    [Fact]
    public void Parse_normalises_nul_separated_git_output()
    {
        var paths = GitIgnored.Parse("bin/\0.claude/worktrees/\0notes.tmp\0../escape/\0bin/\0");
        Assert.Equal(["bin", ".claude/worktrees", "notes.tmp"], paths);
    }

    [Fact]
    public void Finds_the_directories_a_repository_ignores()
    {
        if (!Git(_root, "init", "-q")) { return; } // git not installed: nothing to assert
        File.WriteAllText(Path.Combine(_root, ".gitignore"), "build/\n*.log\n");
        Directory.CreateDirectory(Path.Combine(_root, "build", "deep"));
        File.WriteAllText(Path.Combine(_root, "build", "deep", "a.js"), "x");
        File.WriteAllText(Path.Combine(_root, "run.log"), "x");
        File.WriteAllText(Path.Combine(_root, "keep.py"), "x");

        var ignored = GitIgnored.Find(_root);

        Assert.Contains("build", ignored);
        Assert.Contains("run.log", ignored);
        Assert.DoesNotContain("keep.py", ignored);
    }

    [Fact]
    public void A_folder_that_is_not_a_repository_yields_nothing()
    {
        Assert.Empty(GitIgnored.Find(_root));
    }

    [Fact]
    public void Detection_skips_ignored_directories()
    {
        Directory.CreateDirectory(Path.Combine(_root, "src"));
        Directory.CreateDirectory(Path.Combine(_root, ".claude", "worktrees", "copy"));
        File.WriteAllText(Path.Combine(_root, "src", "app.py"), "x");
        File.WriteAllText(Path.Combine(_root, ".claude", "worktrees", "copy", "package.json"), "{}");

        Assert.Contains("npm", ProjectDetector.Detect(_root).Ecosystems);
        var profile = ProjectDetector.Detect(_root, [".claude/worktrees"]);
        Assert.DoesNotContain("npm", profile.Ecosystems);
        Assert.Contains("python", profile.Languages);
    }

    [Fact]
    public void Engine_arguments_are_built_per_tool_and_safe_against_option_lookalikes()
    {
        string[] paths = ["--evil", "build", "a b/c.d"];

        Assert.Equal(["--exclude=--evil", "--exclude=build", "--exclude=a b/c.d"], Exclusions.Opengrep(paths));
        Assert.Equal(["--exclude", "./build"], Exclusions.Syft(["build"]));
        Assert.Equal(["--experimental-exclude", @"r:(?:^|/)(?:src|work/app)/a\ b/c\.d(?:/|$)"], Exclusions.OsvScanner(["a b/c.d"], "/work/app"));
        Assert.Equal(["-x", "*/build/*", "-x", "*/build"], Exclusions.Lizard(["build"]));
        Assert.Equal(["-i", "${SRC}/build"], Exclusions.Cppcheck(["build"], "${SRC}"));
    }

    [Fact]
    public void Trivy_skips_folders_and_single_files_differently()
    {
        Directory.CreateDirectory(Path.Combine(_root, "out"));
        File.WriteAllText(Path.Combine(_root, "scratch.tf"), "x");

        Assert.Equal(["--skip-dirs", "${SRC}/out", "--skip-files", "${SRC}/scratch.tf"], Exclusions.Trivy(["out", "scratch.tf"], _root, "${SRC}"));
    }

    [Fact]
    public void Gitleaks_config_anchors_each_path_to_the_scanned_folder()
    {
        Assert.Null(Exclusions.GitleaksConfig([], "/work/app"));

        var toml = Exclusions.GitleaksConfig(["bin", "a.b"], "/work/app")!;
        Assert.Contains("useDefault = true", toml);
        Assert.Contains("'''^(?:/src|/work/app)/bin(?:/|$)'''", toml);
        Assert.Contains(@"/a\.b(?:/|$)", toml);
        Assert.Null(Exclusions.GitleaksConfig(["it's'''bad"], "/work/app"));
    }

    [Fact]
    public void A_release_tag_on_head_is_found_and_only_while_head_is_on_it()
    {
        if (!Git(_root, "init", "-q")) { return; } // git not installed: nothing to assert
        File.WriteAllText(Path.Combine(_root, "a.txt"), "1");
        Git(_root, "add", ".");
        Git(_root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "one");
        Assert.Null(NightOwl.Core.Reports.GitTag.AtHead(_root));

        Git(_root, "-c", "user.name=t", "-c", "user.email=t@example.com", "tag", "-a", "v1.0", "-m", "release");
        Assert.Equal("v1.0", NightOwl.Core.Reports.GitTag.AtHead(_root));

        File.WriteAllText(Path.Combine(_root, "a.txt"), "2");
        Git(_root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-am", "two");
        Assert.Null(NightOwl.Core.Reports.GitTag.AtHead(_root)); // a nightly build after the release is not the release
        Assert.Null(NightOwl.Core.Reports.GitTag.AtHead(Path.GetTempPath() + "does-not-exist"));
    }
}
