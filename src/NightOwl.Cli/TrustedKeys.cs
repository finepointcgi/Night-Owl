using System.Reflection;

namespace NightOwl.Cli;

/// <summary>
/// Release-time trust anchors. The release build embeds keys/nightowl-signing.pub and sets the
/// manifest URL (<c>-p:NightOwlManifestUrl=...</c>), so `nightowl update` and automatic updates
/// work with no flags. Source builds have neither and must pass --key/--url or env vars.
/// </summary>
internal static class TrustedKeys
{
    public static readonly string? Project = ReadEmbeddedKey();

    public static readonly string? DefaultManifestUrl = typeof(TrustedKeys).Assembly
        .GetCustomAttributes<AssemblyMetadataAttribute>()
        .FirstOrDefault(a => a.Key == "NightOwlManifestUrl" && !string.IsNullOrWhiteSpace(a.Value))?.Value;

    public static string? ManifestUrl(Options options) =>
        options.Value("url") ?? Environment.GetEnvironmentVariable("NIGHTOWL_MANIFEST_URL") ?? DefaultManifestUrl;

    public static string? PublicKey(Options options)
    {
        var path = options.Value("key") ?? Environment.GetEnvironmentVariable("NIGHTOWL_TRUSTED_KEY");
        return path is not null ? File.ReadAllText(path) : Project;
    }

    private static string? ReadEmbeddedKey()
    {
        using var stream = typeof(TrustedKeys).Assembly.GetManifestResourceStream("nightowl-signing.pub");
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
