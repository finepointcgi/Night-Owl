using NightOwl.Cli;

namespace NightOwl.Tests;

public class CargoFixTests
{
    private static string? Edit(string toml, string package = "serde", string target = "1.0.220") =>
        CargoManifestEditor.SetVersionRequirement(toml, package, target);

    [Fact]
    public void String_requirement_is_retargeted_and_the_rest_of_the_manifest_is_untouched()
    {
        var toml = """
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            serde = "1.0.100"
            tokio = "1"
            """;

        var updated = Edit(toml);

        Assert.NotNull(updated);
        Assert.Contains("serde = \"1.0.220\"", updated);
        Assert.Contains("tokio = \"1\"", updated);
        Assert.Contains("version = \"0.1.0\"", updated); // the package's own version is not a dependency
    }

    [Theory]
    [InlineData("=1.0.100", "=1.0.220")]
    [InlineData("~1.0.100", "~1.0.220")]
    [InlineData("^1.0.100", "^1.0.220")]
    [InlineData("1.0", "1.0.220")]
    public void Requirement_operators_are_preserved(string spec, string expected)
    {
        var updated = Edit($"[dependencies]\nserde = \"{spec}\"\n");
        Assert.Contains($"serde = \"{expected}\"", updated);
    }

    [Fact]
    public void Inline_table_keeps_its_other_keys()
    {
        var updated = Edit("[dependencies]\nserde = { version = \"1.0.100\", features = [\"derive\"] }\n");
        Assert.Contains("serde = { version = \"1.0.220\", features = [\"derive\"] }", updated);
    }

    [Fact]
    public void Renamed_dependency_is_matched_by_its_package_key()
    {
        var updated = Edit("[dependencies]\nserde2 = { package = \"serde\", version = \"1.0.100\" }\n");
        Assert.Contains("serde2 = { package = \"serde\", version = \"1.0.220\" }", updated);
    }

    [Fact]
    public void Dotted_key_form_is_retargeted()
    {
        var updated = Edit("[dependencies]\nserde.version = \"1.0.100\"\nserde.features = [\"derive\"]\n");
        Assert.Contains("serde.version = \"1.0.220\"", updated);
        Assert.Contains("serde.features = [\"derive\"]", updated);
    }

    [Fact]
    public void Dependency_table_section_is_retargeted()
    {
        var toml = """
            [dependencies.serde]
            version = "1.0.100"
            features = ["derive"]
            """;

        var updated = Edit(toml);
        Assert.Contains("version = \"1.0.220\"", updated);
        Assert.Contains("features = [\"derive\"]", updated);
    }

    [Fact]
    public void Dependency_table_with_a_rename_is_matched_by_its_package_key()
    {
        var toml = """
            [dependencies.serde2]
            package = "serde"
            version = "1.0.100"
            """;

        Assert.Contains("version = \"1.0.220\"", Edit(toml));
    }

    [Theory]
    [InlineData("[workspace.dependencies]\nserde = \"1.0.100\"\n")]
    [InlineData("[dev-dependencies]\nserde = \"1.0.100\"\n")]
    [InlineData("[build-dependencies]\nserde = \"1.0.100\"\n")]
    [InlineData("[target.'cfg(windows)'.dependencies]\nserde = \"1.0.100\"\n")]
    public void Every_dependency_section_kind_is_covered(string toml) =>
        Assert.Contains("serde = \"1.0.220\"", Edit(toml));

    [Theory]
    [InlineData("[dependencies]\nserde = \">=1.0, <2.0\"\n")]                       // compound range: a human decides
    [InlineData("[dependencies]\nserde = \"1.*\"\n")]                                // wildcard
    [InlineData("[dependencies]\nserde = { workspace = true }\n")]                  // inherited from the workspace root
    [InlineData("[dependencies]\nserde = { git = \"https://github.com/serde-rs/serde\" }\n")]
    [InlineData("[dependencies]\ntokio = \"1\"\n")]                                  // not a direct dependency here
    [InlineData("[package]\nname = \"serde\"\nversion = \"1.0.100\"\n")]             // the package itself, not a dependency
    [InlineData("[profile.release]\nserde = \"1.0.100\"\n")]                         // same key, wrong section
    public void Uneditable_or_absent_requirements_are_left_alone(string toml) =>
        Assert.Null(Edit(toml));

    [Fact]
    public void Matching_entries_in_every_section_change()
    {
        // The same crate in [dependencies] and [dev-dependencies] must both move, or the
        // lockfile update resolves against the stale declaration.
        var toml = "[dependencies]\nserde = \"1.0.100\"\n\n[dev-dependencies]\nserde = \"1.0.100\"\n";
        var updated = Edit(toml);
        Assert.NotNull(updated);
        Assert.Equal(2, updated.Split("1.0.220").Length - 1);
    }

    [Fact]
    public void Crlf_line_endings_survive()
    {
        var updated = Edit("[dependencies]\r\nserde = \"1.0.100\"\r\n");
        Assert.Equal("[dependencies]\r\nserde = \"1.0.220\"\r\n", updated);
    }

    [Fact]
    public void Every_declaration_of_the_package_is_retargeted()
    {
        var toml = """
            [dependencies]
            serde = "1.0.100"

            [dev-dependencies]
            serde = { version = "1.0.90", features = ["derive"] }

            [target.'cfg(windows)'.dependencies]
            serde = "~1.0.80"
            """;

        var updated = Edit(toml);

        Assert.NotNull(updated);
        Assert.Contains("serde = \"1.0.220\"", updated);
        Assert.Contains("version = \"1.0.220\"", updated);
        Assert.Contains("serde = \"~1.0.220\"", updated);
        Assert.DoesNotContain("1.0.100", updated);
        Assert.DoesNotContain("1.0.90", updated);
        Assert.DoesNotContain("1.0.80", updated);
    }

    [Fact]
    public void Unterminated_string_requirement_is_left_alone_not_an_exception()
    {
        var toml = "[dependencies]\nserde = \"1.0.100";
        Assert.Null(Edit(toml));
    }
}
