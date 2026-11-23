using NightOwl.Core.Findings;
using NightOwl.Core.Policy;
using NightOwl.Core.Sbom;

namespace NightOwl.Tests;

public class FingerprintTests
{
    private static readonly PackageRef Lodash = new("lodash", "4.17.20", "npm");

    [Fact]
    public void Prefers_cve_so_engines_using_different_ids_agree()
    {
        var fromOsv = Fingerprint.ForVulnerability(Lodash, "GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"]);
        var fromOther = Fingerprint.ForVulnerability(Lodash, "CVE-2021-23337", ["GHSA-35jh-r3h4-6jhm"]);
        Assert.Equal(fromOsv, fromOther);
    }

    [Fact]
    public void Different_versions_get_different_ids()
    {
        var a = Fingerprint.ForVulnerability(Lodash, "CVE-2021-23337", []);
        var b = Fingerprint.ForVulnerability(Lodash with { Version = "4.17.21" }, "CVE-2021-23337", []);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Code_fingerprint_ignores_line_moves_and_whitespace()
    {
        var before = Fingerprint.ForCode("sql-injection", "./src/Db.cs", "query(  \"SELECT \" + id )", 10);
        var after = Fingerprint.ForCode("sql-injection", "src/Db.cs", "query( \"SELECT \" + id )", 42);
        Assert.Equal(before, after);
    }

    [Theory]
    [InlineData("var x = eval(input); // dangerous", "var x = eval(input);")]
    [InlineData("var x = eval(input); // a rewritten note", "var x = eval(input);")]
    [InlineData("run(query)  # TODO fix", "run(query)")]
    [InlineData("a(); /* note */ b();", "a();  b();")]
    [InlineData("a(); /* multi\nline */ b();", "a(); b();")]
    [InlineData("var u = \"http://a/b\"; // c", "var u = \"http://a/b\";")]
    [InlineData("  indented();\n    more();  ", "indented(); more();")]
    public void Code_fingerprint_ignores_comments(string withComment, string withoutComment)
    {
        var a = Fingerprint.ForCode("rule-x", "src/App.cs", withComment, 1);
        var b = Fingerprint.ForCode("rule-x", "src/App.cs", withoutComment, 1);
        Assert.Equal(b, a);
    }

    [Fact]
    public void A_comment_only_snippet_falls_back_to_the_line_anchor()
    {
        // Stripping leaves nothing to anchor on; without the fallback every comment-only
        // snippet in a file would collide into a single fingerprint.
        Assert.Equal(
            Fingerprint.ForCode("rule", "a.py", "", 5),
            Fingerprint.ForCode("rule", "a.py", "// just a comment", 5));
        Assert.NotEqual(
            Fingerprint.ForCode("rule", "a.py", "// just a comment", 5),
            Fingerprint.ForCode("rule", "a.py", "// just a comment", 6));
    }

    [Theory]
    [InlineData("url = http://example.com/x", "url = http://example.com/y")]
    [InlineData("x = a#b", "x = a#c")]
    [InlineData("eval(x)", "eval(y)")]
    public void Code_fingerprint_still_distinguishes_code_that_only_looks_like_a_comment(string a, string b)
    {
        Assert.NotEqual(
            Fingerprint.ForCode("rule-x", "src/App.cs", a, 1),
            Fingerprint.ForCode("rule-x", "src/App.cs", b, 1));
    }

    /// <summary>
    /// Regression corpus (backlog #3): these ids are pinned literally so a future change to
    /// fingerprinting shows up here as a deliberate, reviewed break instead of silently
    /// re-opening triaged findings in the field. Every snippet is comment-free, so each id
    /// also equals what the pre-comment-stripping normalization produced.
    /// </summary>
    [Theory]
    [InlineData("sql-injection", "src/Db.cs", "query( \"SELECT \" + id )", "fde5b3e116575cc19c033cb54fe9d970")]
    [InlineData("hardcoded-secret", "src/Config.cs", "var key = \"AKIAIOSFODNN7EXAMPLE\";", "741f5d673a52f2adcdecc49a198740c8")]
    [InlineData("terraform-public", "infra/main.tf", "cidr_blocks = [\"0.0.0.0/0\"]", "76b37e9237356c1b2aea43f25699ad24")]
    [InlineData("py-shell", "app/run.py", "os.system(cmd)", "d7635bed6a12bc8db0458480b3da879a")]
    public void Code_fingerprints_match_the_regression_corpus(string rule, string path, string snippet, string expected) =>
        Assert.Equal(expected, Fingerprint.ForCode(rule, path, snippet, 1));

    [Fact]
    public void Vulnerability_fingerprint_matches_the_regression_corpus() =>
        Assert.Equal("c52e02814b743f7d1434619b97e20e3a", Fingerprint.ForVulnerability(Lodash, "CVE-2021-23337", []));
}

public class FindingMergerTests
{
    [Fact]
    public void Merges_duplicates_keeping_worst_severity_and_all_engines()
    {
        var a = Make("id1", Severity.Medium, "osv-scanner", fixes: ["1.2.3"]);
        var b = Make("id1", Severity.High, "grype", fixes: ["1.2.3", "2.0.0"]);
        var c = Make("id2", Severity.Low, "osv-scanner");

        var merged = FindingMerger.Merge([a, b, c]);

        Assert.Equal(2, merged.Count);
        var first = merged[0];
        Assert.Equal(Severity.High, first.Severity);
        Assert.Equal(["osv-scanner", "grype"], first.Engines);
        Assert.Equal(["1.2.3", "2.0.0"], first.FixedVersions);
    }

    private static Finding Code(string id, string rule, string cwe, int line, Severity severity = Severity.High, string path = "src/app.py") => new()
    {
        Id = id, Category = FindingCategory.Code, Severity = severity, RuleId = rule, Title = rule,
        Engines = ["opengrep"], Aliases = [cwe], Location = new SourceLocation(path, line),
    };

    [Fact]
    public void Taint_finding_absorbs_pattern_finding_on_the_same_line()
    {
        var taint = Code("t", "nightowl.taint.python.injection", "CWE-74", 9, Severity.High);
        var pattern = Code("p", "nightowl.python.subprocess-shell", "CWE-78", 9, Severity.Critical);

        var merged = FindingMerger.Merge([pattern, taint]);

        var one = Assert.Single(merged);
        Assert.Equal("t", one.Id);
        Assert.Equal(Severity.Critical, one.Severity); // never understated
        Assert.Contains("nightowl.python.subprocess-shell", one.Aliases);
        Assert.Contains("CWE-78", one.Aliases);
    }

    [Fact]
    public void Unrelated_findings_on_the_same_line_are_kept()
    {
        var taint = Code("t", "nightowl.taint.python.injection", "CWE-74", 9);
        var weakHash = Code("h", "nightowl.python.weak-hash", "CWE-328", 9, Severity.Medium);
        var otherLine = Code("o", "nightowl.python.eval", "CWE-95", 20);
        var otherFile = Code("f", "nightowl.python.subprocess-shell", "CWE-78", 9, path: "src/other.py");

        Assert.Equal(4, FindingMerger.Merge([taint, weakHash, otherLine, otherFile]).Count);
    }

    [Fact]
    public void Path_traversal_taint_does_not_swallow_an_injection_pattern()
    {
        var taint = Code("t", "nightowl.taint.python.path-traversal", "CWE-22", 5);
        var pattern = Code("p", "nightowl.python.subprocess-shell", "CWE-78", 5);

        Assert.Equal(2, FindingMerger.Merge([taint, pattern]).Count);
    }

    private static Finding Make(string id, Severity severity, string engine, string[]? fixes = null) => new()
    {
        Id = id, Category = FindingCategory.Vulnerability, Severity = severity, RuleId = "CVE-1", Title = "t",
        Engines = [engine], FixedVersions = fixes ?? [],
    };
}

public class PolicyTests
{
    [Fact]
    public void License_policy_flags_denied_review_and_unknown()
    {
        var sbom = new SoftwareBillOfMaterials(
        [
            Component("ok", "MIT"),
            Component("copyleft", "AGPL-3.0-only"),
            Component("weak", "LGPL-2.1-only"),
            Component("mystery"),
        ], "{}");

        var findings = new LicensePolicy().Evaluate(sbom).ToList();

        Assert.Equal(3, findings.Count);
        Assert.Contains(findings, f => f.Package!.Name == "copyleft" && f.Severity == Severity.High);
        Assert.Contains(findings, f => f.Package!.Name == "weak" && f.Severity == Severity.Medium);
        Assert.Contains(findings, f => f.Package!.Name == "mystery" && f.Severity == Severity.Low);
    }

    [Fact]
    public void Quality_gate_ignores_triaged_findings()
    {
        Finding high = new() { Id = "1", Category = FindingCategory.Vulnerability, Severity = Severity.High, RuleId = "r", Title = "t" };
        var gate = new QualityGate(Severity.High);

        Assert.False(gate.Evaluate([high]).Passed);
        Assert.True(gate.Evaluate([high with { Triage = TriageState.FalsePositive }]).Passed);
        Assert.True(gate.Evaluate([high with { Severity = Severity.Medium }]).Passed);
    }

    private static SbomComponent Component(string name, params string[] licenses) =>
        new(new PackageRef(name, "1.0.0", "npm"), licenses, ["package-lock.json"]);
}
