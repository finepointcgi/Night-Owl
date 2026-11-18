using System.Text;
using System.Xml;
using NightOwl.Core.Findings;
using NightOwl.Core.Reports;

namespace NightOwl.Core.Stig;

/// <summary>
/// Writes a DISA STIG Viewer checklist (.ckl): every rule of the STIG with a status. Rules that scan results
/// clearly bear on are <c>Open</c> with the findings listed; all others are <c>Not_Reviewed</c>, because a
/// scanner cannot prove a control is met. A reviewer finishes the checklist in STIG Viewer.
/// </summary>
public static class CklWriter
{
    public static string Write(ScanReport report, StigBenchmark stig, string fileName, string? hostName = null)
    {
        var open = ReportStats.Open(report).ToList();
        var stigUuid = Guid.NewGuid().ToString();
        var settings = new XmlWriterSettings { Indent = true, Encoding = new UTF8Encoding(false) };
        var sb = new StringBuilder();
        using (var xml = XmlWriter.Create(new StringWriterUtf8(sb), settings))
        {
            xml.WriteStartDocument();
            xml.WriteComment("DISA STIG Viewer :: 2.18");
            xml.WriteStartElement("CHECKLIST");

            xml.WriteStartElement("ASSET");
            foreach (var (name, value) in new[]
            {
                ("ROLE", "None"), ("ASSET_TYPE", "Computing"), ("HOST_NAME", hostName ?? Path.GetFileName(report.Project)), ("HOST_IP", ""), ("HOST_MAC", ""),
                ("HOST_FQDN", ""), ("TARGET_COMMENT", "Night Owl scan of " + report.Project), ("TECH_AREA", ""), ("TARGET_KEY", ""),
                ("WEB_OR_DATABASE", "false"), ("WEB_DB_SITE", ""), ("WEB_DB_INSTANCE", ""),
            })
            {
                xml.WriteElementString(name, Clean(value));
            }

            xml.WriteEndElement();

            xml.WriteStartElement("STIGS");
            xml.WriteStartElement("iSTIG");
            xml.WriteStartElement("STIG_INFO");
            foreach (var (name, value) in new[]
            {
                ("version", stig.Version), ("classification", "UNCLASSIFIED"), ("customname", ""), ("stigid", stig.Id), ("description", stig.Description),
                ("filename", fileName), ("releaseinfo", stig.ReleaseInfo), ("title", stig.Title), ("uuid", stigUuid), ("notice", "terms-of-use"), ("source", ""),
            })
            {
                xml.WriteStartElement("SI_DATA");
                xml.WriteElementString("SID_NAME", name);
                xml.WriteElementString("SID_DATA", Clean(value));
                xml.WriteEndElement();
            }

            xml.WriteEndElement(); // STIG_INFO

            foreach (var rule in stig.Rules)
            {
                var hits = StigMapper.FindingsFor(rule, open);
                xml.WriteStartElement("VULN");
                foreach (var (name, value) in new[]
                {
                    ("Vuln_Num", rule.VulnId), ("Severity", rule.Severity), ("Group_Title", rule.GroupTitle), ("Rule_ID", rule.RuleId), ("Rule_Ver", rule.RuleVersion),
                    ("Rule_Title", rule.Title), ("Vuln_Discuss", rule.Discussion), ("IA_Controls", ""), ("Check_Content", rule.CheckText), ("Fix_Text", rule.FixText),
                    ("False_Positives", rule.FalsePositives), ("False_Negatives", rule.FalseNegatives), ("Documentable", "false"), ("Mitigations", rule.Mitigations),
                    ("Potential_Impact", ""), ("Third_Party_Tools", ""), ("Mitigation_Control", ""), ("Responsibility", ""), ("Security_Override_Guidance", ""),
                    ("Check_Content_Ref", "M"), ("Weight", rule.Weight), ("Class", "Unclass"), ("STIGRef", $"{stig.Title} :: Version {stig.Version}, {stig.ReleaseInfo}"),
                    ("TargetKey", ""), ("STIG_UUID", stigUuid),
                })
                {
                    Data(xml, name, value);
                }

                foreach (var legacy in rule.LegacyIds) { Data(xml, "LEGACY_ID", legacy); }
                foreach (var cci in rule.Ccis) { Data(xml, "CCI_REF", cci); }

                xml.WriteElementString("STATUS", hits.Count > 0 ? "Open" : "Not_Reviewed");
                xml.WriteElementString("FINDING_DETAILS", Clean(hits.Count > 0 ? Details(hits) : ""));
                xml.WriteElementString("COMMENTS", Clean(hits.Count > 0
                    ? $"Night Owl scan {report.StartedAt.UtcDateTime:yyyy-MM-dd}: {hits.Count} finding(s) matched this rule by weakness class. The match is automatic, so confirm it before keeping this status."
                    : "Not assessed by Night Owl. No scan result bears on this rule, which does not show the requirement is met."));
                xml.WriteElementString("SEVERITY_OVERRIDE", "");
                xml.WriteElementString("SEVERITY_JUSTIFICATION", "");
                xml.WriteEndElement(); // VULN
            }

            xml.WriteEndElement(); // iSTIG
            xml.WriteEndElement(); // STIGS
            xml.WriteEndElement(); // CHECKLIST
            xml.WriteEndDocument();
        }

        return sb.ToString();
    }

    private static string Details(IReadOnlyList<Finding> hits)
    {
        var lines = hits.Take(25).Select(f =>
        {
            var where = f.Location?.Path is { } p ? $" at {p}{(f.Location.StartLine is { } l ? ":" + l : "")}" : f.Package is { } pk ? $" in {pk.Name}@{pk.Version}" : "";
            return $"[{f.Severity.ToString().ToUpperInvariant()}] {f.RuleId}: {f.Title}{where}";
        });
        var more = hits.Count > 25 ? $"\n... and {hits.Count - 25} more (see the Night Owl report)." : "";
        return string.Join("\n", lines) + more;
    }

    private static void Data(XmlWriter xml, string name, string value)
    {
        xml.WriteStartElement("STIG_DATA");
        xml.WriteElementString("VULN_ATTRIBUTE", name);
        xml.WriteElementString("ATTRIBUTE_DATA", Clean(value));
        xml.WriteEndElement();
    }

    /// <summary>Drops characters XML 1.0 cannot carry (scan text can contain stray control bytes).</summary>
    private static string Clean(string? value) =>
        new((value ?? "").Where(c => c is '\t' or '\n' or '\r' || (c >= 0x20 && c != 0xFFFE && c != 0xFFFF && !char.IsSurrogate(c)) || char.IsSurrogate(c)).ToArray());

    private sealed class StringWriterUtf8(StringBuilder sb) : StringWriter(sb)
    {
        public override Encoding Encoding => new UTF8Encoding(false);
    }
}
