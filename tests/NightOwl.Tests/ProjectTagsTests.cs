using NightOwl.Core.Reports;

namespace NightOwl.Tests;

public sealed class ProjectTagsTests : IDisposable
{
    private readonly string _home = Path.Combine(Path.GetTempPath(), "nightowl-tags-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_home)) { Directory.Delete(_home, true); }
    }

    [Theory]
    [InlineData("Prod", "prod")]
    [InlineData("  Team A  ", "team-a")]
    [InlineData("rel:1.4_x", "rel:1.4_x")]
    [InlineData("<script>", "script")]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    public void Tags_are_normalized(string? input, string? expected) => Assert.Equal(expected, ProjectTags.Normalize(input));

    [Fact]
    public void Add_dedupes_sorts_and_caps_and_remove_forgets_an_empty_project()
    {
        var tags = new ProjectTags(_home);
        tags.Add("/p/a", ["Prod", "prod", "api"]);
        Assert.Equal(["api", "prod"], tags.Get("/p/a"));
        Assert.Empty(tags.Get("/p/other"));

        tags.Add("/p/a", Enumerable.Range(0, 20).Select(i => "t" + i));
        Assert.Equal(ProjectTags.MaxTags, tags.Get("/p/a").Count);

        foreach (var t in tags.Get("/p/a").ToList()) { tags.Remove("/p/a", t); }
        Assert.Empty(tags.All());
    }

    [Fact]
    public void A_corrupt_tags_file_reads_as_empty()
    {
        Directory.CreateDirectory(_home);
        File.WriteAllText(Path.Combine(_home, "tags.json"), "{ not json");
        Assert.Empty(new ProjectTags(_home).Get("/p/a"));
    }
}
