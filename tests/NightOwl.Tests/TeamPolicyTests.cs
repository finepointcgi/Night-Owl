using NightOwl.Core.Findings;
using NightOwl.Core.Policy;
using NightOwl.Core.Sbom;

namespace NightOwl.Tests;

public sealed class TeamPolicyTests
{
    private static Finding F(FindingCategory category, Severity severity, TriageState triage = TriageState.New) => new()
    { Id = $"{category}{severity}", Category = category, Severity = severity, RuleId = "R", Title = "t", Triage = triage };

    [Fact]
    public void Parses_a_full_policy()
    {
        var policy = PolicyFile.Parse("""
            version: 1
            gate:
              fail-on: medium
              per-category: { secret: low, quality: none }
              ignore-unimported: true
            licenses:
              deny: [AGPL-3.0-only]
              allow: [MIT]
              flag-unknown: false
            quality: { min-coverage: 80, max-duplication: 5, max-complexity: 20 }
            """);
        Assert.Equal("medium", policy.Gate.FailOn);
        Assert.Equal("low", policy.Gate.PerCategory["secret"]);
        Assert.True(policy.Gate.IgnoreUnimported);
        Assert.Equal(["AGPL-3.0-only"], policy.Licenses.Deny);
        Assert.Equal(80, policy.Quality.MinCoverage);
        Assert.Equal(20, policy.Quality.MaxComplexity);
    }

    [Fact]
    public void The_starter_template_is_itself_valid() =>
        Assert.Equal("high", PolicyFile.Parse(PolicyFile.Template).Gate.FailOn);

    [Theory]
    [InlineData("gate:\n  fail-onn: high", "fail-onn")]                     // typo: unknown key
    [InlineData("gate:\n  fail-on: urgent", "urgent")]                       // bad severity
    [InlineData("gate:\n  per-category: { secrets: low }", "secrets")]        // bad category
    [InlineData("quality:\n  min-coverage: 150", "min-coverage")]
    [InlineData("version: 2", "version")]
    [InlineData("licenses:\n  allow: [MIT]\n  deny: [mit]", "both allow and deny")]
    public void Mistakes_are_rejected_with_a_useful_message(string yaml, string mention)
    {
        var e = Assert.Throws<PolicyException>(() => PolicyFile.Parse(yaml));
        Assert.Contains(mention, e.Message);
    }

    [Fact]
    public void Gate_applies_per_category_thresholds_and_skips_triaged_findings()
    {
        var gate = new QualityGate(Severity.High, new Dictionary<FindingCategory, Severity?>
        {
            [FindingCategory.Secret] = Severity.Low,
            [FindingCategory.Quality] = null,
        });

        Assert.False(gate.Evaluate([F(FindingCategory.Secret, Severity.Low)]).Passed);          // stricter for secrets
        Assert.True(gate.Evaluate([F(FindingCategory.Quality, Severity.Critical)]).Passed);      // never fails on quality
        Assert.True(gate.Evaluate([F(FindingCategory.Code, Severity.Medium)]).Passed);           // below default
        Assert.False(gate.Evaluate([F(FindingCategory.Code, Severity.High)]).Passed);
        Assert.True(gate.Evaluate([F(FindingCategory.Secret, Severity.High, TriageState.FalsePositive)]).Passed);
    }

    [Fact]
    public void License_allow_list_flags_everything_else_but_not_denied_ones_twice()
    {
        SbomComponent C(string name, string license) => new(new PackageRef(name, "1", "npm"), [license], ["package.json"]);
        var sbom = new SoftwareBillOfMaterials([C("a", "MIT"), C("b", "Zlib"), C("c", "AGPL-3.0-only")], "{}");
        var policy = LicensePolicy.From(new LicensesPolicy { Allow = ["MIT"] });

        var findings = policy.Evaluate(sbom).ToDictionary(f => f.Package!.Name);

        Assert.DoesNotContain("a", findings.Keys);
        Assert.Equal(Severity.Medium, findings["b"].Severity);
        Assert.Contains("allow list", findings["b"].Title);
        Assert.Equal(Severity.High, findings["c"].Severity);   // denied wins
    }

    [Fact]
    public void Licenses_lists_replace_the_defaults_only_when_given()
    {
        var policy = LicensePolicy.From(new LicensesPolicy { Deny = ["Foo-1.0"] });
        Assert.Contains("Foo-1.0", policy.Denied);
        Assert.DoesNotContain("AGPL-3.0", policy.Denied);
        Assert.Contains("GPL-3.0", policy.Review);   // untouched default
    }
}

public sealed class PolicyPrecedenceTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nightowl-policy-").FullName;
    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private void Write(string yaml)
    {
        Directory.CreateDirectory(Path.Combine(_dir, ".nightowl"));
        File.WriteAllText(Path.Combine(_dir, ".nightowl", "policy.yml"), yaml);
    }

    [Fact]
    public void Without_a_policy_the_defaults_apply()
    {
        var s = NightOwl.Cli.PolicySettings.Resolve(_dir, NightOwl.Cli.Options.Parse(["scan"]));
        Assert.Null(s.File);
        Assert.Equal(Severity.High, s.Gate.FailOn);
        Assert.Equal(15, s.MaxComplexity);
        Assert.False(s.IgnoreUnimported);
    }

    [Fact]
    public void Policy_values_apply_when_no_flag_is_given()
    {
        Write("gate:\n  fail-on: medium\n  per-category: { secret: low }\n  ignore-unimported: true\nquality:\n  min-coverage: 70\n  max-complexity: 25\n");
        var s = NightOwl.Cli.PolicySettings.Resolve(_dir, NightOwl.Cli.Options.Parse(["scan"]));
        Assert.Equal(Severity.Medium, s.Gate.FailOn);
        Assert.Equal(Severity.Low, s.Gate.ThresholdFor(FindingCategory.Secret));
        Assert.True(s.IgnoreUnimported);
        Assert.Equal(70, s.MinCoverage);
        Assert.Equal(25, s.MaxComplexity);
    }

    [Fact]
    public void Command_line_flags_override_the_policy_entirely()
    {
        Write("gate:\n  fail-on: critical\n  per-category: { secret: low }\nquality:\n  min-coverage: 70\n");
        var s = NightOwl.Cli.PolicySettings.Resolve(_dir, NightOwl.Cli.Options.Parse(["scan", "--fail-on", "none", "--min-coverage", "90"]));
        Assert.Null(s.Gate.FailOn);
        Assert.Null(s.Gate.PerCategory);          // the flag replaces per-category rules too
        Assert.Equal(90, s.MinCoverage);
    }
}
