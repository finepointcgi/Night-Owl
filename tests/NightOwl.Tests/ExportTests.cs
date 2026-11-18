using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using NightOwl.Core.Export;
using NightOwl.Core.Findings;
using NightOwl.Core.Reports;
using NightOwl.Core.Stig;

namespace NightOwl.Tests;

public sealed class ExportTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nightowl-export-" + Guid.NewGuid().ToString("N"));

    public ExportTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, true);

    // A made-up two-rule benchmark in DISA's XCCDF layout. Not real STIG content: ids and wording are invented for the test.
    private const string SampleXccdf = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Sample_App_STIG">
          <title>Sample Application STIG</title><description>For tests only.</description><version>1</version>
          <plain-text id="release-info">Release: 1 Benchmark Date: 01 Jan 2026</plain-text>
          <Group id="V-900001"><title>SRG-TEST-1</title>
            <Rule id="SV-900001r1_rule" severity="high" weight="10.0"><version>TEST-001</version>
              <title>The application must not be vulnerable to SQL Injection.</title>
              <description>&lt;VulnDiscussion&gt;Injection lets attackers run queries.&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;Mitigations&gt;None.&lt;/Mitigations&gt;</description>
              <ident system="http://cyber.mil/legacy">V-11111</ident><ident system="http://cyber.mil/cci">CCI-001310</ident>
              <fixtext fixref="F-1">Use parameterized queries.</fixtext>
              <check system="C-1"><check-content-ref name="M"/><check-content>Review the code for string-built queries.</check-content></check>
            </Rule></Group>
          <Group id="V-900002"><title>SRG-TEST-2</title>
            <Rule id="SV-900002r1_rule" severity="low" weight="10.0"><version>TEST-002</version>
              <title>The application must log administrator actions.</title>
              <description>&lt;VulnDiscussion&gt;Logs help audits.&lt;/VulnDiscussion&gt;</description>
              <fixtext fixref="F-2">Enable logging.</fixtext>
              <check system="C-2"><check-content>Check the log settings.</check-content></check>
            </Rule></Group>
        </Benchmark>
        """;

    private static Finding F(string id, string title, Severity sev = Severity.High, params string[] aliases) => new()
    {
        Id = id, Category = FindingCategory.Code, Severity = sev, RuleId = "r." + id, Title = title, Aliases = aliases,
        Location = new SourceLocation("src/a.cs", 12),
    };

    private static ScanReport Report(params Finding[] findings) => new()
    {
        Project = "/p/app", StartedAt = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero), Seconds = 2, ManifestSequence = 0,
        Engines = [new EngineRun("opengrep", "1", true, 1, null)], Findings = findings,
    };

    private StigBenchmark Stig()
    {
        var path = Path.Combine(_dir, "sample-xccdf.xml");
        File.WriteAllText(path, SampleXccdf);
        return StigBenchmark.Load(path);
    }

    [Fact]
    public void Stig_xml_is_parsed_into_rules()
    {
        var stig = Stig();
        Assert.Equal("Sample Application STIG", stig.Title);
        Assert.Equal(2, stig.Rules.Count);
        var rule = stig.Rules[0];
        Assert.Equal("V-900001", rule.VulnId);
        Assert.Equal("high", rule.Severity);
        Assert.Equal("Injection lets attackers run queries.", rule.Discussion);
        Assert.Equal(["CCI-001310"], rule.Ccis);
        Assert.Equal(["V-11111"], rule.LegacyIds);
        Assert.Equal("Use parameterized queries.", rule.FixText);
    }

    [Fact]
    public void A_stig_zip_is_read_and_a_non_stig_is_refused()
    {
        var zipPath = Path.Combine(_dir, "stig.zip");
        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            using var w = new StreamWriter(zip.CreateEntry("U_Sample_Manual-xccdf.xml").Open());
            w.Write(SampleXccdf);
        }

        Assert.Equal(2, StigBenchmark.Load(zipPath).Rules.Count);

        var bad = Path.Combine(_dir, "bad.xml");
        File.WriteAllText(bad, "<html><body/></html>");
        Assert.Throws<InvalidDataException>(() => StigBenchmark.Load(bad));
        File.WriteAllText(bad, "<!DOCTYPE x [<!ENTITY a \"b\">]><Benchmark/>");
        Assert.Throws<InvalidDataException>(() => StigBenchmark.Load(bad));
    }

    [Fact]
    public void Ckl_marks_matching_rules_open_and_leaves_the_rest_not_reviewed()
    {
        var report = Report(F("sqli", "SQL built from user input", Severity.High, "CWE-89"), F("other", "Weak hash", Severity.Medium, "CWE-328"));

        var ckl = XDocument.Parse(CklWriter.Write(report, Stig(), "sample-xccdf.xml"));

        Assert.Equal("CHECKLIST", ckl.Root!.Name.LocalName);
        var vulns = ckl.Descendants("VULN").ToList();
        Assert.Equal(2, vulns.Count);
        Assert.Equal("V-900001", Attr(vulns[0], "Vuln_Num"));
        Assert.Equal("Open", vulns[0].Element("STATUS")!.Value);
        Assert.Contains("SQL built from user input", vulns[0].Element("FINDING_DETAILS")!.Value);
        Assert.DoesNotContain("Weak hash", vulns[0].Element("FINDING_DETAILS")!.Value);
        Assert.Equal("Not_Reviewed", vulns[1].Element("STATUS")!.Value);          // never claims NotAFinding
        Assert.Equal(["CCI-001310"], vulns[0].Elements("STIG_DATA").Where(d => d.Element("VULN_ATTRIBUTE")!.Value == "CCI_REF").Select(d => d.Element("ATTRIBUTE_DATA")!.Value));
        Assert.Equal("Sample Application STIG", ckl.Descendants("SI_DATA").First(d => d.Element("SID_NAME")!.Value == "title").Element("SID_DATA")!.Value);
        Assert.Equal("app", ckl.Descendants("HOST_NAME").Single().Value);
    }

    [Fact]
    public void Findings_triaged_away_do_not_open_rules()
    {
        var closed = F("sqli", "SQL built from user input", Severity.High, "CWE-89") with { Triage = TriageState.FalsePositive };
        var ckl = XDocument.Parse(CklWriter.Write(Report(closed), Stig(), "x.xml"));
        Assert.All(ckl.Descendants("VULN"), v => Assert.Equal("Not_Reviewed", v.Element("STATUS")!.Value));
    }

    [Fact]
    public void Ckl_survives_control_characters_in_scan_text()
    {
        var report = Report(F("sqli", "bad \u0001 char & <tag>", Severity.High, "CWE-89"));
        var xml = CklWriter.Write(report, Stig(), "x.xml");
        var ckl = XDocument.Parse(xml); // would throw on an invalid character
        Assert.Contains("bad  char & <tag>", ckl.Descendants("FINDING_DETAILS").First().Value);
    }

    [Fact]
    public void Csv_defuses_formulas_and_quotes_cells()
    {
        var report = Report(F("a", "=HYPERLINK(\"http://evil\")", Severity.High), F("b", "plain, with comma", Severity.Low));
        var csv = FindingCsv.Write(report);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        Assert.StartsWith("Severity,Category,Rule,Title", lines[0]);
        Assert.Equal(3, lines.Length);
        Assert.Contains("\"'=HYPERLINK(\"\"http://evil\"\")\"", lines[1]);
        Assert.Contains("\"plain, with comma\"", lines[2]);
        Assert.Equal("'+1", FindingCsv.Cell("+1"));
    }

    [Fact]
    public void Html_report_escapes_content_and_has_no_scripts()
    {
        var html = HtmlReport.Write(Report(F("x", "<script>alert(1)</script>")), label: "v1 <b>");

        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html);
        Assert.Contains("v1 &lt;b&gt;", html);
        Assert.StartsWith("<!doctype html>", html);
    }

    private static string Attr(XElement vuln, string name) =>
        vuln.Elements("STIG_DATA").First(d => d.Element("VULN_ATTRIBUTE")!.Value == name).Element("ATTRIBUTE_DATA")!.Value;
}
