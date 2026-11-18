using System.Diagnostics;

namespace NightOwl.Core.Engines;

/// <summary>
/// Paths inside a git work tree that git itself ignores (.gitignore, .git/info/exclude, the global ignore file):
/// build output, dependency folders, caches, agent worktrees. Scanning them is slow and mostly produces findings
/// about code nobody wrote, so engines are told to skip them. Returns nothing when the folder isn't a git
/// repository or git isn't installed, in which case only the built-in skip list applies.
/// </summary>
public static class GitIgnored
{
    /// <summary>Root-relative paths with forward slashes and no trailing slash. Directories are listed once, not per file.</summary>
    public static IReadOnlyList<string> Find(string root)
    {
        try
        {
            var start = new ProcessStartInfo("git")
            {
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };

            foreach (var argument in new[] { "-c", "core.quotepath=off", "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory" })
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start);
            if (process is null)
            {
                return [];
            }

            var errors = process.StandardError.ReadToEndAsync();
            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(TimeSpan.FromSeconds(30)))
            {
                process.Kill(entireProcessTree: true);
                return [];
            }

            _ = errors.GetAwaiter().GetResult();
            return process.ExitCode == 0 ? Parse(output) : [];
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return [];
        }
    }

    /// <summary>Parses NUL-separated <c>git ls-files</c> output.</summary>
    public static IReadOnlyList<string> Parse(string output) =>
        output.Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Replace('\\', '/').Trim('/'))
            .Where(p => p.Length > 0 && !p.StartsWith("../", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToList();
}
