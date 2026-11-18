using System.Text;
using NightOwl.Core.Findings;
using NightOwl.Core.Reports;

namespace NightOwl.Core.Export;

/// <summary>All findings of a scan as CSV, for spreadsheets and audit evidence.</summary>
public static class FindingCsv
{
    private static readonly string[] Header =
        ["Severity", "Category", "Rule", "Title", "Path", "Line", "Package", "Version", "Ecosystem", "Fixed versions", "Triage", "Context", "Engines", "Aliases", "Id"];

    public static string Write(ScanReport report, string? projectColumn = null) => Write([report], projectColumn is not null);

    /// <summary>One CSV for several projects; adds a leading Project column.</summary>
    public static string Write(IEnumerable<ScanReport> reports, bool withProject = true)
    {
        var sb = new StringBuilder();
        Row(sb, withProject ? ["Project", .. Header] : Header);
        foreach (var report in reports)
        {
            foreach (var f in report.Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Title, StringComparer.Ordinal))
            {
                string[] cells =
                [
                    f.Severity.ToString(), f.Category.ToString(), f.RuleId, f.Title, f.Location?.Path ?? "", f.Location?.StartLine?.ToString() ?? "",
                    f.Package?.Name ?? "", f.Package?.Version ?? "", f.Package?.Ecosystem ?? "", string.Join("; ", f.FixedVersions),
                    f.Triage.ToString(), f.Context.ToString(), string.Join("; ", f.Engines), string.Join("; ", f.Aliases), f.Id,
                ];
                Row(sb, withProject ? [report.Project, .. cells] : cells);
            }
        }

        return sb.ToString();
    }

    private static void Row(StringBuilder sb, string[] cells)
    {
        sb.Append(string.Join(",", cells.Select(Cell))).Append("\r\n");
    }

    /// <summary>Quotes a cell, and defuses spreadsheet formulas: a title starting with = or + must not run when opened in Excel.</summary>
    internal static string Cell(string value)
    {
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            value = "'" + value;
        }

        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }
}
