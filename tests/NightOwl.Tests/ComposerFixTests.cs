using NightOwl.Cli;

namespace NightOwl.Tests;

public class ComposerFixTests
{
    private const string Manifest = """
        {
            "name": "example/app",
            "require": {
                "php": ">=8.2",
                "guzzlehttp/guzzle": "^7.5.0",
                "monolog/monolog": "~3.4.0"
            },
            "require-dev": {
                "phpunit/phpunit": "10.5.0"
            }
        }
        """;

    [Fact]
    public void Caret_constraint_keeps_its_operator()
    {
        var updated = ComposerManifestEditor.SetRequirement(Manifest, "guzzlehttp/guzzle", "7.8.1");
        Assert.NotNull(updated);
        Assert.Contains("\"guzzlehttp/guzzle\": \"^7.8.1\"", updated);
        Assert.Contains("\"monolog/monolog\": \"~3.4.0\"", updated); // others untouched
    }

    [Fact]
    public void Tilde_constraint_keeps_its_operator()
    {
        var updated = ComposerManifestEditor.SetRequirement(Manifest, "monolog/monolog", "3.5.0");
        Assert.Contains("\"monolog/monolog\": \"~3.5.0\"", updated);
    }

    [Fact]
    public void Exact_pin_in_require_dev_stays_exact()
    {
        var updated = ComposerManifestEditor.SetRequirement(Manifest, "phpunit/phpunit", "10.5.20");
        Assert.Contains("\"phpunit/phpunit\": \"10.5.20\"", updated);
    }

    [Fact]
    public void Package_names_match_case_insensitively()
    {
        var updated = ComposerManifestEditor.SetRequirement(Manifest, "GuzzleHttp/Guzzle", "7.8.1");
        Assert.Contains("\"guzzlehttp/guzzle\": \"^7.8.1\"", updated);
    }

    [Theory]
    [InlineData("php")]                    // a range constraint, and not a library
    [InlineData("symfony/console")]        // not required directly (transitive): no override exists
    public void Uneditable_or_absent_requirements_are_left_alone(string package) =>
        Assert.Null(ComposerManifestEditor.SetRequirement(Manifest, package, "1.0.0"));

    [Theory]
    [InlineData("*")]
    [InlineData("dev-master")]
    [InlineData("^7.5 || ^8.0")]
    [InlineData(">=7.0,<8.0")]
    [InlineData("7.5.*")]
    public void Complex_constraints_are_left_alone(string constraint)
    {
        var manifest = "{\"require\": {\"guzzlehttp/guzzle\": \"" + constraint + "\"}}";
        Assert.Null(ComposerManifestEditor.SetRequirement(manifest, "guzzlehttp/guzzle", "7.8.1"));
    }

    [Fact]
    public void Require_and_require_dev_declarations_are_both_retargeted()
    {
        var json = """{"require": {"guzzlehttp/guzzle": "^7.5"}, "require-dev": {"guzzlehttp/guzzle": "~7.4"}}""";

        var updated = ComposerManifestEditor.SetRequirement(json, "guzzlehttp/guzzle", "7.8.1");

        Assert.NotNull(updated);
        Assert.Contains("\"guzzlehttp/guzzle\": \"^7.8.1\"", updated);
        Assert.Contains("\"guzzlehttp/guzzle\": \"~7.8.1\"", updated);
    }

    [Fact]
    public void An_uneditable_second_declaration_blocks_the_edit()
    {
        var json = """{"require": {"guzzlehttp/guzzle": "^7.5"}, "require-dev": {"guzzlehttp/guzzle": ">=7.0 <8.0"}}""";
        Assert.Null(ComposerManifestEditor.SetRequirement(json, "guzzlehttp/guzzle", "7.8.1"));
    }

    [Fact]
    public void Indentation_and_text_survive_the_rewrite()
    {
        var json = "{\n    \"name\": \"acme/café\",\n    \"homepage\": \"https://example.com/a+b\",\n    \"require\": {\n        \"guzzlehttp/guzzle\": \"^7.5\"\n    }\n}\n";

        var updated = ComposerManifestEditor.SetRequirement(json, "guzzlehttp/guzzle", "7.8.1");

        Assert.NotNull(updated);
        Assert.Contains("        \"guzzlehttp/guzzle\": \"^7.8.1\"", updated); // still 8 spaces deep, not re-indented to 2
        Assert.Contains("acme/café", updated); // not \u-escaped
        Assert.Contains("https://example.com/a+b", updated); // not \u-escaped
    }
}
