using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using NightOwl.Core.Engines;
using NightOwl.Core.Findings;
using NightOwl.Core.Quality;
using NightOwl.Engines.Execution;

namespace NightOwl.Engines.Lizard;

/// <summary>
/// Maintainability with lizard: cyclomatic complexity per function and duplicated blocks,
/// for 30+ languages without building the code. Over-threshold functions and duplicate blocks
/// become low/medium Quality findings (they never fail a security gate at the default
/// threshold); totals go into the report's metrics.
/// </summary>
public sealed partial class LizardEngine(ToolRunner runner, int complexityThreshold = 15) : IEngine
{
    private static readonly string[] Excludes = ["*/node_modules/*", "*/.git/*", "*/bin/*", "*/obj/*", "*/vendor/*", "*/dist/*", "*/build/*", "*/target/*", "*.min.js"];

    public string Name => "lizard";
    public int Order => 60;

    public bool AppliesTo(ScanContext context) => context.Profile.Languages.Count > 0;

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        string[] excludeArgs = [.. Excludes.SelectMany(e => new[] { "-x", e }), .. Exclusions.Lizard(context.Excluded)];

        var csv = await runner.RunAsync(Name, ["--csv", .. excludeArgs, ToolRunner.SourceToken],
            context.RootPath, context.WorkDirectory, TimeSpan.FromMinutes(20), cancellationToken);
        if (csv.ExitCode != 0)
        {
            return EngineResult.Failed(Name, $"lizard exited {csv.ExitCode}: {csv.StandardError.Trim()}", stopwatch.Elapsed);
        }

        var functions = ParseCsv(csv.StandardOutput, context.RootPath);
        var findings = functions
            .Where(f => f.Complexity > complexityThreshold)
            .Select(f => ComplexityFinding(f, complexityThreshold))
            .ToList();

        if (functions.Count > 0)
        {
            context.Metrics[MetricNames.Functions] = functions.Count;
            context.Metrics[MetricNames.AverageComplexity] = functions.Average(f => f.Complexity);
            context.Metrics[MetricNames.MaxComplexity] = functions.Max(f => f.Complexity);
            context.Metrics[MetricNames.ComplexFunctions] = findings.Count;
        }

        // Duplicate detection is a separate pass: lizard prints it as text, not in the CSV. It compares code against
        // all other code, so its cost grows much faster than the project does. Past a size limit it is skipped (or
        // cut off after a few minutes) and says so, instead of making the whole scan wait for the complexity results.
        string? note = null;
        var sourceBytes = SourceBytes(context);
        if (sourceBytes > DuplicationSizeLimitBytes)
        {
            note = $"duplication check skipped: {sourceBytes / 1_000_000} MB of source is over the {DuplicationSizeLimitBytes / 1_000_000} MB limit. Scan a sub-folder to measure duplication.";
        }
        else
        {
            try
            {
                var duplicates = await runner.RunAsync(Name, ["-Eduplicate", .. excludeArgs, ToolRunner.SourceToken],
                    context.RootPath, context.WorkDirectory, DuplicationTimeout, cancellationToken);
                // lizard's exit code counts threshold warnings, so judge the run by its output instead.
                if (duplicates.StandardOutput.Contains("Total duplicate rate", StringComparison.Ordinal))
                {
                    var (blocks, rate) = ParseDuplicates(duplicates.StandardOutput, context.RootPath);
                    findings.AddRange(blocks.Select(DuplicateFinding));
                    if (rate is { } r)
                    {
                        context.Metrics[MetricNames.DuplicationRate] = r;
                    }
                }
            }
            catch (TimeoutException)
            {
                note = $"duplication check stopped after {DuplicationTimeout.TotalMinutes:0} minutes; complexity results are complete.";
            }
        }

        return new EngineResult(Name, findings, stopwatch.Elapsed, Note: note);
    }

    private const long DuplicationSizeLimitBytes = 25_000_000;
    private static readonly TimeSpan DuplicationTimeout = TimeSpan.FromMinutes(5);

    private static long SourceBytes(ScanContext context)
    {
        long total = 0;
        foreach (var file in ProjectDetector.EnumerateFiles(context.RootPath, context.Excluded))
        {
            if (ProjectDetector.ExtensionLanguages.ContainsKey(Path.GetExtension(file)))
            {
                try { total += new FileInfo(file).Length; } catch (IOException) { }
            }
        }

        return total;
    }

    public sealed record FunctionInfo(string Path, string Name, int StartLine, int Complexity, int Lines);

    public sealed record DuplicateBlock(IReadOnlyList<(string Path, int Start, int End)> Copies);

    /// <summary>CSV columns: NLOC, CCN, tokens, params, length, location, file, function, long name, start, end.</summary>
    public static List<FunctionInfo> ParseCsv(string csv, string root)
    {
        var functions = new List<FunctionInfo>();
        foreach (var line in csv.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = CsvField().Matches(line).Select(m => m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).ToList();
            if (fields.Count < 11 || !int.TryParse(fields[1], CultureInfo.InvariantCulture, out var ccn))
            {
                continue;
            }

            functions.Add(new FunctionInfo(
                ToolRunner.ToProjectPath(fields[6], root),
                fields[7],
                int.Parse(fields[9], CultureInfo.InvariantCulture),
                ccn,
                int.Parse(fields[0], CultureInfo.InvariantCulture)));
        }

        return functions;
    }

    public static (List<DuplicateBlock> Blocks, double? Rate) ParseDuplicates(string text, string root)
    {
        var blocks = new List<DuplicateBlock>();
        List<(string, int, int)>? current = null;
        double? rate = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("Duplicate block", StringComparison.Ordinal))
            {
                current = [];
            }
            else if (current is not null && DuplicateLocation().Match(line) is { Success: true } m)
            {
                current.Add((ToolRunner.ToProjectPath(m.Groups[1].Value, root), int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture), int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture)));
            }
            else if (current is not null && line.StartsWith("^^^", StringComparison.Ordinal))
            {
                if (current.Count > 1)
                {
                    blocks.Add(new DuplicateBlock(current));
                }

                current = null;
            }
            else if (DuplicateRate().Match(line) is { Success: true } r)
            {
                rate = double.Parse(r.Groups[1].Value, CultureInfo.InvariantCulture);
            }
        }

        return (blocks, rate);
    }

    private static Finding ComplexityFinding(FunctionInfo f, int threshold) => new()
    {
        Id = Fingerprint.ForCode("quality/complexity", f.Path, $"function:{f.Name}", f.StartLine),
        Category = FindingCategory.Quality,
        Severity = f.Complexity > threshold * 2 ? Severity.Medium : Severity.Low,
        RuleId = "quality/complexity",
        Title = $"{f.Name} is too complex (cyclomatic complexity {f.Complexity}, limit {threshold})",
        Description = "Hard to test and review, and a common hiding place for bugs. Split it into smaller functions or simplify the branching.",
        Location = new SourceLocation(f.Path, f.StartLine),
        Engines = ["lizard"],
    };

    private static Finding DuplicateFinding(DuplicateBlock block)
    {
        var (path, start, end) = block.Copies[0];
        var others = string.Join(", ", block.Copies.Skip(1).Select(c => $"{c.Path}:{c.Start}"));
        return new Finding
        {
            Id = Fingerprint.ForCode("quality/duplication", path, string.Join("|", block.Copies.Select(c => c.Path).Order(StringComparer.Ordinal)), start),
            Category = FindingCategory.Quality,
            Severity = Severity.Low,
            RuleId = "quality/duplication",
            Title = $"{end - start + 1} duplicated lines in {path} (also at {others})",
            Description = "Copies drift apart and fixes get applied to only one of them. Extract the shared code.",
            Location = new SourceLocation(path, start, end),
            Engines = ["lizard"],
        };
    }

    [GeneratedRegex("\"([^\"]*)\"|([^,]+)")]
    private static partial Regex CsvField();

    [GeneratedRegex(@"^(.+):(\d+) ~ (\d+)$")]
    private static partial Regex DuplicateLocation();

    [GeneratedRegex(@"^Total duplicate rate:\s*([\d.]+)%")]
    private static partial Regex DuplicateRate();
}

/// <summary>Picks up coverage reports the project's own tests produced; no tool is run.</summary>
public sealed class CoverageEngine : IEngine
{
    public string Name => "coverage";
    public int Order => 61;

    public bool AppliesTo(ScanContext context) => true;

    public Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        if (CoverageReader.Find(context.RootPath, ProjectDetector.EnumerateFiles(context.RootPath, context.Excluded)) is { } coverage)
        {
            context.Metrics[MetricNames.LineCoverage] = coverage.LineRate;
        }

        return Task.FromResult(new EngineResult(Name, [], stopwatch.Elapsed));
    }
}
