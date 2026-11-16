using NightOwl.Core.Engines;
using NightOwl.Core.Policy;
using NightOwl.Engines.Cppcheck;
using NightOwl.Engines.Execution;
using NightOwl.Engines.Gitleaks;
using NightOwl.Engines.Lizard;
using NightOwl.Engines.Opengrep;
using NightOwl.Engines.Osv;
using NightOwl.Engines.Syft;
using NightOwl.Engines.Trivy;

namespace NightOwl.Cli;

/// <summary>The static-analysis engine set, shared by `scan` and `canary` so they can never drift apart.</summary>
internal static class EngineFactory
{
    public static IEngine[] Create(ToolRunner runner, Options options, string? projectRoot = null)
    {
        var policy = projectRoot is null ? null : PolicySettings.Resolve(projectRoot, options);
        var ruleDirectories = options.Value("rules")?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];
        if (ruleDirectories.FirstOrDefault(d => !Directory.Exists(d)) is { } missing)
        {
            throw new ArgumentException($"rules directory not found: {missing}");
        }

        var images = options.Value("image")?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];

        IEngine[] engines =
        [
            new SyftEngine(runner, LicensePolicy.From(policy?.File?.Licenses)),
            new OsvScannerEngine(runner),
            new GitleaksEngine(runner, HistoryScope.Parse(options.Value("history"))),
            new OpengrepEngine(runner, ruleDirectories),
            new CppcheckEngine(runner),
            new TrivyIacEngine(runner),
            new TrivyImageEngine(runner, images, options.Has("image-include-unfixed")),
            new LizardEngine(runner, policy?.MaxComplexity ?? int.Parse(options.Value("max-complexity") ?? "15", System.Globalization.CultureInfo.InvariantCulture)),
            new CoverageEngine(),
        ];

        var only = options.Value("engines")?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return only is null ? engines : engines.Where(e => only.Contains(e.Name, StringComparer.OrdinalIgnoreCase)).ToArray();
    }

    public static ToolRunner Runner(NightOwl.Core.Updates.EngineManifest manifest, Options options) =>
        new(manifest, options.Has("container") ? ToolMode.Container : ToolMode.Auto,
            Path.Combine(NightOwl.Core.Updates.ManifestStore.Default().HomeDirectory, "cache"));
}
