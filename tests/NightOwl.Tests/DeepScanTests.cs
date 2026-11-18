using NightOwl.Core.Findings;
using NightOwl.Engines.Cppcheck;
using NightOwl.Engines.Trivy;

namespace NightOwl.Tests;

public class DeepScanTests
{
    [Theory]
    [InlineData("arrayIndexOutOfBounds", Severity.Critical)]
    [InlineData("deallocuse", Severity.Critical)]
    [InlineData("uninitvar", Severity.High)]
    [InlineData("memleak", Severity.Medium)]
    [InlineData("nullPointerOutOfMemory", Severity.Low)]
    [InlineData("someNewCheck", Severity.Medium)] // unknown error-level checks are capped at medium
    public void Cppcheck_findings_are_graded_by_defect_class(string rule, Severity expected)
    {
        var finding = new Finding { Id = "x", Category = FindingCategory.Code, Severity = Severity.Critical, RuleId = rule, Title = "t" };
        Assert.Equal(expected, CppcheckEngine.Grade(finding).Severity);
    }

    [Theory]
    [InlineData("FROM node:20\nRUN npm ci\n", "node:20", 1)]
    [InlineData("FROM golang:1.23 AS build\nRUN go build\nFROM gcr.io/distroless/static:nonroot\nCOPY --from=build /app /app\n", "gcr.io/distroless/static:nonroot", 3)]
    [InlineData("ARG BASE=python:3.12-slim\nFROM ${BASE}\n", "python:3.12-slim", 2)]
    [InlineData("FROM --platform=linux/amd64 nginx:1.27 AS web\n", "nginx:1.27", 1)]
    [InlineData("FROM alpine:3.20 AS base\nFROM base\nRUN true\n", "alpine:3.20", 1)]
    public void Dockerfile_final_base_image_is_found(string dockerfile, string image, int line)
    {
        var result = TrivyImageEngine.ParseDockerfile(dockerfile.Split('\n'));
        Assert.Equal((image, line), result);
    }

    [Theory]
    [InlineData("FROM golang:1.23 AS build\nFROM scratch\nCOPY --from=build /app /app\n")]
    [InlineData("FROM ${UNDEFINED}\n")]
    public void Unscannable_final_stages_are_skipped(string dockerfile) =>
        Assert.Null(TrivyImageEngine.ParseDockerfile(dockerfile.Split('\n')));

    [Fact]
    public void Trivy_image_json_maps_to_vulnerability_findings_per_image()
    {
        const string json = """
            {"ArtifactName":"alpine:3.18.0","Results":[{"Target":"alpine:3.18.0 (alpine 3.18.0)","Class":"os-pkgs","Type":"alpine",
              "Vulnerabilities":[{"VulnerabilityID":"CVE-2022-48174","PkgName":"busybox","InstalledVersion":"1.36.0-r9","FixedVersion":"1.36.1-r1",
                "Severity":"CRITICAL","Title":"busybox: stack overflow","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2022-48174"}]}]}
            """;
        var target = new ImageTarget("alpine:3.18.0", "Dockerfile", 1);

        var finding = Assert.Single(TrivyImageEngine.Parse(json, target, "trivy-image"));
        var other = Assert.Single(TrivyImageEngine.Parse(json, target with { Reference = "alpine:3.18.1" }, "trivy-image"));

        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(["1.36.1-r1"], finding.FixedVersions);
        Assert.Equal("Dockerfile", finding.Location!.Path);
        Assert.Contains("(image alpine:3.18.0)", finding.Title);
        Assert.NotEqual(finding.Id, other.Id); // same package in another image is its own finding
    }

    [Fact]
    public void Many_image_vulnerabilities_fold_into_one_update_finding()
    {
        var vulns = string.Join(",", Enumerable.Range(1, 6).Select(n =>
            $$"""{"VulnerabilityID":"CVE-2025-{{n}}","PkgName":"pkg{{n % 2}}","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"{{(n == 3 ? "CRITICAL" : "HIGH")}}","Title":"t"}"""));
        var json = $$"""{"Results":[{"Type":"debian","Vulnerabilities":[{{vulns}}]}]}""";
        var target = new ImageTarget("postgres:17", "deploy/Dockerfile", 3);

        var parsed = TrivyImageEngine.Parse(json, target, "trivy-image");
        var grouped = Assert.Single(TrivyImageEngine.GroupIfMany(parsed, target, "trivy-image"));

        Assert.Equal(6, parsed.Count);
        Assert.Equal(Severity.Critical, grouped.Severity);
        Assert.Equal("image/outdated-base", grouped.RuleId);
        Assert.Equal(6, grouped.Aliases.Count);
        Assert.Contains("CVE-2025-3", grouped.Aliases);
        Assert.Equal("deploy/Dockerfile", grouped.Location!.Path);
        Assert.Contains("postgres:17", grouped.Title);
        Assert.Contains("6 known vulnerabilities", grouped.Title);
    }

    [Fact]
    public void A_few_image_vulnerabilities_stay_separate()
    {
        const string json = """{"Results":[{"Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","InstalledVersion":"1","Severity":"HIGH"},{"VulnerabilityID":"CVE-2","PkgName":"b","InstalledVersion":"1","Severity":"HIGH"}]}]}""";
        var target = new ImageTarget("alpine:3", "Dockerfile", 1);
        Assert.Equal(2, TrivyImageEngine.GroupIfMany(TrivyImageEngine.Parse(json, target, "trivy-image"), target, "trivy-image").Count);
    }
}
