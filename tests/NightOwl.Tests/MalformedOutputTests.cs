using System.Text.Json;
using NightOwl.Core.Findings;
using NightOwl.Engines.Gitleaks;
using NightOwl.Engines.Nuclei;
using NightOwl.Engines.Osv;
using NightOwl.Engines.Sarif;
using NightOwl.Engines.Syft;
using NightOwl.Engines.Zap;

namespace NightOwl.Tests;

/// <summary>
/// Backlog #13: engine output is untrusted input. Every parser gets the same corpus of
/// malformed outputs; the contract is that a parser either returns (possibly empty) results
/// or fails with a JsonException / InvalidDataException that names the problem — never a
/// raw InvalidOperationException, NullReferenceException or KeyNotFoundException from
/// deep inside a property access.
/// </summary>
public class MalformedOutputTests
{
    public static IEnumerable<object[]> Corpus()
    {
        string[] inputs =
        [
            "",
            "   ",
            "not json at all",
            "{",
            "[1,2",
            "[]",
            "42",
            "\"a string\"",
            "null",
            "{}",
            "{\"results\": null}",
            "{\"results\": [42, null]}",
            "{\"results\": [{\"packages\": [{\"vulnerabilities\": []}]}]}", // entry without "package"
            "{\"results\": [{\"packages\": [{\"package\": {\"name\": 5}, \"vulnerabilities\": [{\"id\": 123, \"fix\": {\"versions\": \"x\"}}]}]}]}",
            "{\"components\": [42, {\"name\": 5, \"licenses\": \"MIT\"}]}",
            "{\"components\": null}",
            "{\"site\": [{\"alerts\": [{\"instances\": \"nope\"}]}]}",
            "{\"runs\": null}",
            "{\"runs\": [42, {\"results\": [{\"locations\": \"nope\"}, {\"locations\": [{\"physicalLocation\": 7}]}]}]}",
            "{\"runs\": [{\"tool\": 5, \"results\": []}]}",
            "{\"RuleID\": 7, \"File\": null}",
        ];
        return inputs.Select(i => new object[] { i });
    }

    [Theory]
    [MemberData(nameof(Corpus))]
    public void Gitleaks_parser_survives_malformed_output(string input) =>
        AssertParsesCleanly(() => GitleaksParser.Parse(input, "/src", "gitleaks"));

    [Theory]
    [MemberData(nameof(Corpus))]
    public void Osv_parser_survives_malformed_output(string input) =>
        AssertParsesCleanly(() => OsvResultParser.Parse(input, "/src", "osv-scanner"));

    [Theory]
    [MemberData(nameof(Corpus))]
    public void CycloneDx_parser_survives_malformed_output(string input) =>
        AssertParsesCleanly(() => CycloneDxParser.Parse(input, "/src"));

    [Theory]
    [MemberData(nameof(Corpus))]
    public void Zap_parser_survives_malformed_output(string input) =>
        AssertParsesCleanly(() => ZapReportParser.Parse(input));

    [Theory]
    [MemberData(nameof(Corpus))]
    public void Sarif_parser_survives_malformed_output(string input) =>
        AssertParsesCleanly(() => SarifParser.Parse(input, "/src", "opengrep", FindingCategory.Code));

    [Theory]
    [MemberData(nameof(Corpus))]
    public void Nuclei_parser_survives_malformed_output(string input) =>
        AssertParsesCleanly(() => NucleiParser.Parse(input.Split('\n')));

    [Fact]
    public void Wrong_shape_root_is_one_clear_error_not_a_json_internals_message()
    {
        var error = Assert.Throws<InvalidDataException>(() => OsvResultParser.Parse("[]", "/src", "osv-scanner"));
        Assert.Contains("malformed", error.Message);
        Assert.Contains("osv-scanner", error.Message);
    }

    [Fact]
    public void Null_collections_count_as_no_results()
    {
        Assert.Empty(OsvResultParser.Parse("{\"results\": null}", "/src", "osv-scanner"));
        Assert.Empty(SarifParser.Parse("{\"runs\": null}", "/src", "opengrep", FindingCategory.Code));
        Assert.Empty(CycloneDxParser.Parse("{\"components\": null}", "/src").Components);
    }

    private static void AssertParsesCleanly(Action parse)
    {
        try
        {
            parse();
        }
        catch (Exception e) when (e is JsonException or InvalidDataException)
        {
            // The documented failure modes: not JSON, or JSON of the wrong shape.
        }
    }
}
