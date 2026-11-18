using NightOwl.Cli;

namespace NightOwl.Tests;

public class MavenFixTests
{
    private const string Pom = """
        <project>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <properties>
            <jackson.version>2.15.0</jackson.version>
            <java.version>21</java.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>com.fasterxml.jackson.core</groupId>
              <artifactId>jackson-databind</artifactId>
              <version>${jackson.version}</version>
            </dependency>
            <dependency>
              <groupId>org.apache.commons</groupId>
              <artifactId>commons-lang3</artifactId>
              <version>3.12.0</version>
            </dependency>
          </dependencies>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>io.netty</groupId>
                <artifactId>netty-all</artifactId>
                <version>4.1.90.Final</version>
                <type>pom</type>
                <scope>import</scope>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </project>
        """;

    [Fact]
    public void Literal_version_is_replaced_in_place()
    {
        var updated = PomEditor.SetDependencyVersion(Pom, "org.apache.commons:commons-lang3", "3.14.0");
        Assert.NotNull(updated);
        Assert.Contains("<version>3.14.0</version>", updated);
        Assert.DoesNotContain("3.12.0", updated);
        Assert.Contains("<version>1.0.0</version>", updated); // the project's own version is untouched
    }

    [Fact]
    public void Property_version_updates_the_property_not_the_reference()
    {
        var updated = PomEditor.SetDependencyVersion(Pom, "com.fasterxml.jackson.core:jackson-databind", "2.15.2");
        Assert.NotNull(updated);
        Assert.Contains("<jackson.version>2.15.2</jackson.version>", updated);
        Assert.Contains("<version>${jackson.version}</version>", updated);
        Assert.Contains("<java.version>21</java.version>", updated);
    }

    [Fact]
    public void Dependency_management_version_is_replaced()
    {
        var updated = PomEditor.SetDependencyVersion(Pom, "io.netty:netty-all", "4.1.100.Final");
        Assert.Contains("<version>4.1.100.Final</version>", updated);
    }

    [Fact]
    public void Bare_artifact_id_matches_when_it_is_unique()
    {
        var updated = PomEditor.SetDependencyVersion(Pom, "commons-lang3", "3.14.0");
        Assert.Contains("<version>3.14.0</version>", updated);
    }

    [Theory]
    [InlineData("org.apache.commons:missing-artifact", "3.14.0")]   // not in the pom
    [InlineData("wrong.group:commons-lang3", "3.14.0")]              // group does not match
    public void Unknown_or_mismatched_packages_are_left_alone(string package, string target) =>
        Assert.Null(PomEditor.SetDependencyVersion(Pom, package, target));

    [Fact]
    public void Ambiguous_bare_artifact_id_is_left_alone()
    {
        var pom = """
            <project><dependencies>
              <dependency><groupId>a</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>
              <dependency><groupId>b</groupId><artifactId>lib</artifactId><version>2.0</version></dependency>
            </dependencies></project>
            """;
        Assert.Null(PomEditor.SetDependencyVersion(pom, "lib", "3.0"));
        Assert.Contains("<version>3.0</version>", PomEditor.SetDependencyVersion(pom, "b:lib", "3.0"));
    }

    [Fact]
    public void Version_range_is_left_alone()
    {
        var pom = """
            <project><dependencies>
              <dependency><groupId>a</groupId><artifactId>lib</artifactId><version>[1.0,2.0)</version></dependency>
            </dependencies></project>
            """;
        Assert.Null(PomEditor.SetDependencyVersion(pom, "a:lib", "1.5"));
    }

    [Fact]
    public void Managed_version_without_a_version_element_is_left_alone()
    {
        var pom = """
            <project><dependencies>
              <dependency><groupId>a</groupId><artifactId>lib</artifactId></dependency>
            </dependencies></project>
            """;
        Assert.Null(PomEditor.SetDependencyVersion(pom, "a:lib", "1.5"));
    }

    [Fact]
    public void Property_defined_only_in_a_parent_pom_is_left_alone()
    {
        var pom = """
            <project><dependencies>
              <dependency><groupId>a</groupId><artifactId>lib</artifactId><version>${lib.version}</version></dependency>
            </dependencies></project>
            """;
        Assert.Null(PomEditor.SetDependencyVersion(pom, "a:lib", "1.5"));
    }

    [Fact]
    public void Declaration_in_dependency_management_wins_over_the_plain_declaration()
    {
        var pom = """
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.apache.commons</groupId>
                  <artifactId>commons-lang3</artifactId>
                </dependency>
              </dependencies>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.apache.commons</groupId>
                    <artifactId>commons-lang3</artifactId>
                    <version>3.12.0</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </project>
            """;

        var updated = PomEditor.SetDependencyVersion(pom, "org.apache.commons:commons-lang3", "3.14.0");

        Assert.NotNull(updated);
        Assert.Contains("<version>3.14.0</version>", updated);
    }

    [Fact]
    public void When_both_declarations_carry_a_version_the_managed_one_is_edited()
    {
        var pom = """
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.apache.commons</groupId>
                  <artifactId>commons-lang3</artifactId>
                  <version>3.11.0</version>
                </dependency>
              </dependencies>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.apache.commons</groupId>
                    <artifactId>commons-lang3</artifactId>
                    <version>3.12.0</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </project>
            """;

        var updated = PomEditor.SetDependencyVersion(pom, "org.apache.commons:commons-lang3", "3.14.0");

        Assert.NotNull(updated);
        Assert.Contains("<version>3.14.0</version>", updated);
        Assert.Contains("<version>3.11.0</version>", updated); // the plain declaration is untouched
        Assert.DoesNotContain("<version>3.12.0</version>", updated);
    }

    [Fact]
    public void Partial_property_version_is_left_alone()
    {
        var pom = """
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.apache.commons</groupId>
                  <artifactId>commons-lang3</artifactId>
                  <version>3.12-${rev}</version>
                </dependency>
              </dependencies>
            </project>
            """;

        Assert.Null(PomEditor.SetDependencyVersion(pom, "org.apache.commons:commons-lang3", "3.14.0"));
    }
}
