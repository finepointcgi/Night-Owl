using System.Text;
using NightOwl.Core.Export;
using NightOwl.Core.Reports;
using NightOwl.Core.Stig;

namespace NightOwl.Web;

/// <summary>Download links: /export/{project}/{format}, for the latest scan or one named with ?scan=.</summary>
public static class ExportEndpoints
{
    public static readonly (string Format, string Label, string Hint)[] Formats =
    [
        ("html", "HTML report", "One file you can open, email or print to PDF."),
        ("csv", "CSV", "For spreadsheets and audit evidence."),
        ("json", "JSON", "The full scan report."),
        ("sarif", "SARIF", "For GitHub code scanning and IDEs."),
        ("cdx", "SBOM (CycloneDX)", "Component list from the last scan."),
        ("ckl", "STIG checklist (.ckl)", "For DISA STIG Viewer. Needs an imported STIG."),
    ];

    public static void Map(WebApplication app)
    {
        app.MapGet("/export/all/csv", (ReportArchive archive, ProjectTags tags, string? tag) =>
        {
            var reports = archive.LoadAll().Where(r => tag is null || tags.Get(r.Project).Contains(tag)).ToList();
            return Download(FindingCsv.Write(reports), "text/csv", $"nightowl-{(tag is null ? "all-projects" : Safe(tag))}.csv");
        });

        app.MapGet("/export/{key}/{format}", (string key, string format, string? scan, string? stig, ReportArchive archive, ScanVault vault, StigStore stigs) =>
        {
            var latest = archive.LoadAll().FirstOrDefault(r => ReportArchive.KeyFor(r.Project) == key);
            if (latest is null) { return Results.NotFound("No such project."); }

            var report = latest;
            string? label = null;
            if (scan is not null)
            {
                report = scan == ScanVault.IdFor(latest) ? latest : vault.Load(latest.Project, scan);
                if (report is null) { return Results.NotFound("No such scan."); }
                label = vault.List(latest.Project).FirstOrDefault(s => s.Id == scan)?.Label;
            }

            var name = Safe(Path.GetFileName(report.Project)) + (scan is null ? "" : "-" + scan[..8]);
            switch (format)
            {
                case "html": return Download(HtmlReport.Write(report, label), "text/html", name + ".html");
                case "csv": return Download(FindingCsv.Write(report), "text/csv", name + ".csv");
                case "json": return Download(report.ToJson(), "application/json", name + ".json");
                case "sarif": return Download(SarifWriter.Write(report, typeof(ExportEndpoints).Assembly.GetName().Version?.ToString(3) ?? "0"), "application/sarif+json", name + ".sarif");
                case "cdx":
                    var sbom = archive.SbomPath(latest.Project);
                    return File.Exists(sbom) ? Download(File.ReadAllText(sbom), "application/vnd.cyclonedx+json", name + ".cdx.json") : Results.NotFound("No SBOM was saved for this project. Run a scan first.");
                case "ckl":
                    if (stigs.PathFor(stig) is not { } stigPath) { return Results.BadRequest("Choose an imported STIG first (Exports page)."); }
                    StigBenchmark benchmark;
                    try { benchmark = StigBenchmark.Load(stigPath); }
                    catch (InvalidDataException e) { return Results.BadRequest(e.Message); }
                    return Download(CklWriter.Write(report, benchmark, Path.GetFileName(stigPath)), "application/xml", name + ".ckl");
                default: return Results.NotFound("Unknown format.");
            }
        });
    }

    private static IResult Download(string content, string contentType, string fileName) =>
        Results.File(Encoding.UTF8.GetBytes(content), contentType + "; charset=utf-8", fileName);

    private static string Safe(string name) =>
        new string(name.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '-').ToArray()) is { Length: > 0 } s ? s : "report";
}
