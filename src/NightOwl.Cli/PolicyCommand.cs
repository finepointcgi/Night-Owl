using NightOwl.Core.Policy;

namespace NightOwl.Cli;

/// <summary>
/// nightowl policy init [path]       write a commented starter .nightowl/policy.yml
/// nightowl policy validate [path]   check the file and show the rules that will apply
/// </summary>
internal static class PolicyCommand
{
    public static int Run(Options options)
    {
        var action = options.Positional.FirstOrDefault();
        var root = Path.GetFullPath(options.Positional.ElementAtOrDefault(1) ?? ".");
        switch (action)
        {
            case "init":
            {
                var target = Path.Combine(root, PolicyFile.FileNames[0]);
                if (File.Exists(target))
                {
                    Console.Error.WriteLine($"error: {target} already exists.");
                    return Cli.ExitError;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.WriteAllText(target, PolicyFile.Template + "\n");
                Console.Error.WriteLine($"Wrote {target}. Commit it so CI and developers use the same rules.");
                return Cli.ExitPassed;
            }

            case "validate":
            {
                try
                {
                    var settings = PolicySettings.Resolve(root, options);
                    if (settings.File is null)
                    {
                        Console.Error.WriteLine("No policy file; built-in defaults apply. Create one with `nightowl policy init`.");
                        return Cli.ExitPassed;
                    }

                    Console.WriteLine($"{Path.GetRelativePath(root, settings.Source!)}: valid");
                    Console.WriteLine($"  gate: fail on {settings.GateLabel}{(settings.IgnoreUnimported ? "; ignoring unimported dependencies" : "")}");
                    var licenses = settings.File.Licenses;
                    Console.WriteLine($"  licenses: deny {Count(licenses.Deny)}, review {Count(licenses.Review)}, allow {(licenses.Allow is null ? "(no allow list)" : licenses.Allow.Count.ToString())}");
                    Console.WriteLine($"  quality: coverage ≥ {settings.MinCoverage?.ToString() ?? "-"}, duplication ≤ {settings.MaxDuplication?.ToString() ?? "-"}, complexity ≤ {settings.MaxComplexity}");
                    return Cli.ExitPassed;
                }
                catch (PolicyException e)
                {
                    Console.Error.WriteLine($"error: {e.Message}");
                    return Cli.ExitError;
                }
            }

            default:
                Console.Error.WriteLine("usage: nightowl policy init|validate [path]");
                return Cli.ExitError;
        }
    }

    private static string Count(List<string>? list) => list is null ? "(defaults)" : list.Count.ToString();
}
