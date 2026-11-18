using System.Diagnostics;

namespace NightOwl.Core.Reports;

/// <summary>Reads release tags from the scanned repository, so a scan taken at a release is labelled with it automatically.</summary>
public static class GitTag
{
    /// <summary>The tag that points exactly at HEAD (a release build), or null: not a git repo, no tag, or git is unavailable.</summary>
    public static string? AtHead(string root)
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
            foreach (var argument in new[] { "describe", "--tags", "--exact-match", "HEAD" })
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start);
            if (process is null) { return null; }
            var errors = process.StandardError.ReadToEndAsync();
            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(TimeSpan.FromSeconds(10)))
            {
                process.Kill(entireProcessTree: true);
                return null;
            }

            _ = errors.GetAwaiter().GetResult();
            return process.ExitCode == 0 ? Clean(output) : null;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
    }

    /// <summary>First line only, trimmed to what a label allows; null if empty.</summary>
    public static string? Clean(string output)
    {
        var line = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        return string.IsNullOrWhiteSpace(line) ? null : line[..Math.Min(line.Length, 60)];
    }
}
