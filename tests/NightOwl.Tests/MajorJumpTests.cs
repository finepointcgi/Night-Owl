using NightOwl.Core.Findings;
using NightOwl.Core.Fixes;

namespace NightOwl.Tests;

public class MajorJumpTests
{
    [Theory]
    [InlineData("2.15.0", "2.15.2", false)]
    [InlineData("2.15.0", "3.0.0", true)]
    [InlineData("4.1.90.Final", "4.1.100.Final", false)]
    [InlineData("4.1.90.Final", "5.0.0", true)]
    [InlineData("v1.2.3", "v2.0.0", true)]
    [InlineData("1.0.0", "1.0.1", false)]
    public void Major_jump_is_detected_from_the_planned_fix(string current, string target, bool expected)
    {
        var plan = FixPlanner.Plan([Vuln("pkg", current, target)]);
        var fix = Assert.Single(plan.Fixes);
        Assert.Equal(expected, fix.IsMajorJump);
    }

    [Fact]
    public void Major_jump_uses_the_smallest_fixing_version_not_the_largest_offered()
    {
        // Both advisories are fixed within 2.x; the planner must not jump to 3.x, so no warning.
        var plan = FixPlanner.Plan([
            Vuln("pkg", "2.0.0", "2.1.0", "3.0.0"),
        ]);
        var fix = Assert.Single(plan.Fixes);
        Assert.Equal("2.1.0", fix.TargetVersion);
        Assert.False(fix.IsMajorJump);
    }

    private static Finding Vuln(string name, string version, params string[] fixes) => new()
    {
        Id = name, Category = FindingCategory.Vulnerability, Severity = Severity.High, RuleId = "CVE-0000", Title = "x",
        Package = new PackageRef(name, version, "npm"), FixedVersions = fixes,
    };
}
