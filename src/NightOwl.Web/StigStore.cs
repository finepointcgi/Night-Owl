using System.Text.RegularExpressions;
using NightOwl.Core.Stig;

namespace NightOwl.Web;

/// <summary>The STIG files you imported, kept under NIGHTOWL_HOME/stigs so a checklist can be built from any of them.</summary>
public sealed partial class StigStore(string homeDirectory)
{
    private string Directory_ => Path.Combine(homeDirectory, "stigs");

    public IReadOnlyList<string> List() =>
        System.IO.Directory.Exists(Directory_)
            ? System.IO.Directory.EnumerateFiles(Directory_).Select(Path.GetFileName).OfType<string>().Order(StringComparer.OrdinalIgnoreCase).ToList()
            : [];

    /// <summary>Resolves a stored STIG by name; null for anything that is not a file this store wrote.</summary>
    public string? PathFor(string? name)
    {
        if (string.IsNullOrEmpty(name) || name != Path.GetFileName(name) || !Safe().IsMatch(name)) { return null; }
        var path = Path.Combine(Directory_, name);
        return File.Exists(path) ? path : null;
    }

    /// <summary>Validates the upload as a real STIG before keeping it. Throws <see cref="InvalidDataException"/> with a plain message if not.</summary>
    public StigBenchmark Import(Stream upload, string originalName)
    {
        var extension = Path.GetExtension(originalName).ToLowerInvariant();
        if (extension is not (".xml" or ".zip"))
        {
            throw new InvalidDataException("Choose the STIG's .zip or its *-xccdf.xml file.");
        }

        var baseName = Safe().IsMatch(Path.GetFileName(originalName)) ? Path.GetFileName(originalName) : "stig" + extension;
        System.IO.Directory.CreateDirectory(Directory_);
        var temp = Path.Combine(Directory_, "." + Guid.NewGuid().ToString("N") + extension);
        try
        {
            using (var file = File.Create(temp)) { upload.CopyTo(file); }
            var stig = StigBenchmark.Load(temp); // refuses anything that is not a STIG
            File.Move(temp, Path.Combine(Directory_, baseName), overwrite: true);
            return stig;
        }
        finally
        {
            if (File.Exists(temp)) { File.Delete(temp); }
        }
    }

    public void Delete(string name)
    {
        if (PathFor(name) is { } path) { File.Delete(path); }
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")]
    private static partial Regex Safe();
}
