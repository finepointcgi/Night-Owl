using NightOwl.Core.Findings;
using NightOwl.Core.Policy;

namespace NightOwl.Tests;

public sealed class FindingContextTests
{
    [Theory]
    // production
    [InlineData("src/app/main.py", FindingContext.Production)]
    [InlineData("lib/response.js", FindingContext.Production)]
    [InlineData("requirements.txt", FindingContext.Production)]   // .txt is not docs
    [InlineData("src/Latest/Service.cs", FindingContext.Production)]   // "Latest" is not a test dir
    [InlineData("contest/entry.py", FindingContext.Production)]        // substring is not a segment
    [InlineData(null, FindingContext.Production)]
    // tests
    [InlineData("context_test.go", FindingContext.Test)]
    [InlineData("testdata/certificate/key.pem", FindingContext.Test)]
    [InlineData("tests/test_app.py", FindingContext.Test)]
    [InlineData("src/test/java/com/acme/FooTest.java", FindingContext.Test)]
    [InlineData("web/app.spec.ts", FindingContext.Test)]
    [InlineData("web/app.test.js", FindingContext.Test)]
    [InlineData("src/Orders/OrderTests.cs", FindingContext.Test)]
    [InlineData("pkg/conftest.py", FindingContext.Test)]
    [InlineData("test_utils.py", FindingContext.Test)]
    // examples and docs
    [InlineData("examples/params/index.js", FindingContext.Example)]
    [InlineData("samples/Demo.cs", FindingContext.Example)]
    [InlineData("docs/config.rst", FindingContext.Docs)]
    [InlineData("README.md", FindingContext.Docs)]
    [InlineData("guide/intro.adoc", FindingContext.Docs)]
    // generated and vendored
    [InlineData("static/app.min.js", FindingContext.Generated)]
    [InlineData("api/user.pb.go", FindingContext.Generated)]
    [InlineData("dist/bundle.js", FindingContext.Generated)]
    [InlineData("src/App.Migrations.Sqlite/Migrations/20240101_Init.cs", FindingContext.Generated)]
    [InlineData("db/migrations/001.sql", FindingContext.Production)]    // only EF's C# migrations are treated as generated
    [InlineData("node_modules/lodash/index.js", FindingContext.Vendored)]
    [InlineData("vendor/github.com/x/y/y.go", FindingContext.Vendored)]
    [InlineData("vendor/tests/a.py", FindingContext.Vendored)]       // vendored wins over test
    [InlineData("docs\\examples\\a.js", FindingContext.Example)]    // Windows separators
    public void Paths_are_classified(string? path, FindingContext expected) =>
        Assert.Equal(expected, PathContext.Classify(path));

    private static Finding F(FindingContext context, Severity severity = Severity.High, FindingCategory category = FindingCategory.Code) => new()
    { Id = $"{context}{severity}{category}", Category = category, Severity = severity, RuleId = "R", Title = "t", Context = context };

    [Fact]
    public void Gate_ignores_non_production_contexts_by_default_but_reports_them()
    {
        var gate = new QualityGate(Severity.High);
        var result = gate.Evaluate([F(FindingContext.Production), F(FindingContext.Test, category: FindingCategory.Secret), F(FindingContext.Example)]);

        Assert.False(result.Passed);
        Assert.Single(result.Blocking);
        Assert.Equal(2, result.Excluded.Count);
        Assert.True(gate.Evaluate([F(FindingContext.Test), F(FindingContext.Docs)]).Passed);
    }

    [Fact]
    public void Included_contexts_gate_again()
    {
        var gate = new QualityGate(Severity.High, null, new HashSet<FindingContext> { FindingContext.Test });
        Assert.False(gate.Evaluate([F(FindingContext.Test)]).Passed);
        Assert.True(gate.Evaluate([F(FindingContext.Example)]).Passed);   // only tests were opted in
    }

    [Fact]
    public void Policy_accepts_include_contexts_and_rejects_typos()
    {
        var policy = PolicyFile.Parse("gate:\n  include-contexts: [test, docs]\n");
        Assert.Equal(["test", "docs"], policy.Gate.IncludeContexts);
        Assert.True(PolicyFile.TryParseContext("all", out var all));
        Assert.Equal(5, all.Count);
        Assert.Throws<PolicyException>(() => PolicyFile.Parse("gate:\n  include-contexts: [tests]\n"));
        Assert.Throws<PolicyException>(() => PolicyFile.Parse("gate:\n  include-contexts: [production]\n"));
    }

    [Fact]
    public void The_include_context_flag_overrides_the_policy()
    {
        var dir = Directory.CreateTempSubdirectory("nightowl-ctx-").FullName;
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, ".nightowl"));
            File.WriteAllText(Path.Combine(dir, ".nightowl", "policy.yml"), "gate:\n  include-contexts: [docs]\n");

            var fromPolicy = NightOwl.Cli.PolicySettings.Resolve(dir, NightOwl.Cli.Options.Parse(["scan"]));
            Assert.True(fromPolicy.Gate.Covers(FindingContext.Docs));
            Assert.False(fromPolicy.Gate.Covers(FindingContext.Test));

            var fromFlag = NightOwl.Cli.PolicySettings.Resolve(dir, NightOwl.Cli.Options.Parse(["scan", "--include-context", "test,example"]));
            Assert.True(fromFlag.Gate.Covers(FindingContext.Test));
            Assert.True(fromFlag.Gate.Covers(FindingContext.Example));
            Assert.False(fromFlag.Gate.Covers(FindingContext.Docs));      // the flag replaces the policy list

            Assert.True(NightOwl.Cli.PolicySettings.Resolve(dir, NightOwl.Cli.Options.Parse(["scan", "--include-context", "all"])).Gate.Covers(FindingContext.Vendored));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
