using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace NightOwl.Core.Stig;

/// <summary>One rule (a "Vuln" in STIG Viewer) from a DISA STIG.</summary>
public sealed record StigRule(
    string VulnId, string RuleId, string RuleVersion, string Severity, string GroupTitle, string Title,
    string Discussion, string FalsePositives, string FalseNegatives, string Mitigations, string CheckText, string FixText,
    IReadOnlyList<string> Ccis, IReadOnlyList<string> LegacyIds, string Weight)
{
    /// <summary>Everything a human would search when asking "is this rule about X?".</summary>
    public string SearchText => $"{Title}\n{Discussion}\n{CheckText}".ToLowerInvariant();
}

/// <summary>A STIG read from DISA's XCCDF file (the "Manual-xccdf.xml" inside a STIG zip).</summary>
public sealed record StigBenchmark(string Id, string Title, string Description, string Version, string ReleaseInfo, IReadOnlyList<StigRule> Rules)
{
    private const long MaxBytes = 64L * 1024 * 1024;

    /// <summary>Reads an XCCDF file, or a STIG zip containing one. Throws <see cref="InvalidDataException"/> when it is neither.</summary>
    public static StigBenchmark Load(string path)
    {
        using var stream = File.OpenRead(path);
        var isZip = stream.ReadByte() == 'P' && stream.ReadByte() == 'K';
        stream.Position = 0;
        if (!isZip)
        {
            return Parse(stream);
        }

        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        var entry = zip.Entries.FirstOrDefault(e => e.FullName.EndsWith("xccdf.xml", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidDataException("That zip does not contain a STIG (no *xccdf.xml inside).");
        if (entry.Length > MaxBytes)
        {
            throw new InvalidDataException("The STIG file inside the zip is unreasonably large.");
        }

        using var inner = entry.Open();
        return Parse(inner);
    }

    public static StigBenchmark Parse(Stream stream)
    {
        XDocument document;
        try
        {
            using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxBytes });
            document = XDocument.Load(reader);
        }
        catch (XmlException e)
        {
            throw new InvalidDataException("That file is not valid XML: " + e.Message, e);
        }

        var root = document.Root;
        if (root is null || root.Name.LocalName != "Benchmark")
        {
            throw new InvalidDataException("That file is not a STIG (XCCDF Benchmark) document.");
        }

        var rules = new List<StigRule>();
        foreach (var group in root.Elements().Where(e => e.Name.LocalName == "Group"))
        {
            if (group.Elements().FirstOrDefault(e => e.Name.LocalName == "Rule") is not { } rule)
            {
                continue;
            }

            var discussion = Text(rule, "description");
            rules.Add(new StigRule(
                (string?)group.Attribute("id") ?? "", (string?)rule.Attribute("id") ?? "", Text(rule, "version"),
                ((string?)rule.Attribute("severity") ?? "medium").ToLowerInvariant(), Text(group, "title"), Text(rule, "title"),
                Tag(discussion, "VulnDiscussion"), Tag(discussion, "FalsePositives"), Tag(discussion, "FalseNegatives"), Tag(discussion, "Mitigations"),
                rule.Descendants().FirstOrDefault(e => e.Name.LocalName == "check-content")?.Value.Trim() ?? "",
                Text(rule, "fixtext"),
                Idents(rule, "cci"), Idents(rule, "legacy"), (string?)rule.Attribute("weight") ?? "10.0"));
        }

        if (rules.Count == 0)
        {
            throw new InvalidDataException("That STIG has no rules.");
        }

        var release = root.Elements().FirstOrDefault(e => e.Name.LocalName == "plain-text" && (string?)e.Attribute("id") == "release-info")?.Value.Trim() ?? "";
        return new StigBenchmark((string?)root.Attribute("id") ?? "", Text(root, "title"), Text(root, "description"), Text(root, "version"), release, rules);
    }

    private static string Text(XElement parent, string name) =>
        parent.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim() ?? "";

    private static List<string> Idents(XElement rule, string kind) =>
        rule.Elements().Where(e => e.Name.LocalName == "ident" && ((string?)e.Attribute("system") ?? "").EndsWith("/" + kind, StringComparison.OrdinalIgnoreCase))
            .Select(e => e.Value.Trim()).Where(v => v.Length > 0).ToList();

    /// <summary>The rule's description holds escaped pseudo-tags (&lt;VulnDiscussion&gt;...); pull one out.</summary>
    private static string Tag(string text, string tag)
    {
        var m = Regex.Match(text, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline);
        return m.Success ? m.Groups[1].Value.Trim() : "";
    }
}
