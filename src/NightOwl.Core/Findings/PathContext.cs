namespace NightOwl.Core.Findings;

/// <summary>Where a finding lives. Only <see cref="Production"/> gates the build by default.</summary>
public enum FindingContext
{
    Production,
    Test,
    Example,
    Docs,
    Generated,
    Vendored,
}

/// <summary>
/// Classifies a project-relative path as production code, tests, examples, docs, generated or vendored files.
/// Deliberately conservative: it only matches well-known directory names and file-name conventions, and the
/// result never hides a finding, it only decides whether the finding gates the build.
/// </summary>
public static class PathContext
{
    private static readonly HashSet<string> VendoredDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules", "vendor", "third_party", "third-party", "thirdparty", "site-packages", ".venv", "venv", "bower_components", "Pods",
    };

    private static readonly HashSet<string> GeneratedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "dist", "generated", "__generated__",
    };

    private static readonly HashSet<string> TestDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "test", "tests", "__tests__", "spec", "specs", "testdata", "test-data", "testing", "fixtures", "fixture", "e2e", "mocks", "__mocks__",
    };

    private static readonly HashSet<string> ExampleDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "example", "examples", "sample", "samples", "demo", "demos", "tutorial", "tutorials", "playground",
    };

    private static readonly HashSet<string> DocsDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "doc", "docs", "documentation",
    };

    private static readonly string[] GeneratedSuffixes =
        [".min.js", ".min.css", ".pb.go", ".pb.cc", ".pb.h", "_pb2.py", ".g.cs", ".designer.cs", ".generated.cs", ".generated.ts", ".generated.go"];

    private static readonly string[] TestSuffixes =
        ["_test.go", "_test.py", "_spec.rb", "Test.php", "Tests.cs", "Test.cs", "Tests.java", "Test.java", "Tests.kt", "Test.kt"];

    private static readonly string[] DocsExtensions = [".md", ".rst", ".adoc", ".mdx"];

    public static FindingContext Classify(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return FindingContext.Production;
        }

        var segments = path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        var directories = segments[..^1];
        var file = segments[^1];

        if (directories.Any(VendoredDirectories.Contains)) { return FindingContext.Vendored; }
        // Entity Framework migrations are produced by `dotnet ef migrations add`, and are near-copies by design.
        var efMigration = file.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) && directories.Any(d => d.Equals("Migrations", StringComparison.Ordinal));
        if (efMigration || directories.Any(GeneratedDirectories.Contains) || GeneratedSuffixes.Any(s => file.EndsWith(s, StringComparison.OrdinalIgnoreCase))) { return FindingContext.Generated; }
        if (directories.Any(TestDirectories.Contains) || IsTestFile(file)) { return FindingContext.Test; }
        if (directories.Any(ExampleDirectories.Contains)) { return FindingContext.Example; }
        if (directories.Any(DocsDirectories.Contains) || DocsExtensions.Any(e => file.EndsWith(e, StringComparison.OrdinalIgnoreCase))) { return FindingContext.Docs; }
        return FindingContext.Production;
    }

    private static bool IsTestFile(string file) =>
        TestSuffixes.Any(s => file.EndsWith(s, StringComparison.Ordinal))
        || file.StartsWith("test_", StringComparison.OrdinalIgnoreCase) && file.EndsWith(".py", StringComparison.OrdinalIgnoreCase)
        || file.Contains(".test.", StringComparison.OrdinalIgnoreCase)
        || file.Contains(".spec.", StringComparison.OrdinalIgnoreCase)
        || file.Equals("conftest.py", StringComparison.OrdinalIgnoreCase);
}
