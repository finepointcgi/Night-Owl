using System.Security.Claims;
using NightOwl.Web;

namespace NightOwl.Tests;

public sealed class DashboardSignInTests
{
    private static Func<string, string?> Env(params (string Key, string Value)[] values) =>
        key => values.FirstOrDefault(v => v.Key == key).Value;

    [Fact]
    public void Sign_in_is_off_unless_an_authority_and_client_are_set()
    {
        Assert.Null(DashboardSignIn.FromEnvironment(Env()));
        Assert.Throws<InvalidOperationException>(() => DashboardSignIn.FromEnvironment(Env(("NIGHTOWL_OIDC_AUTHORITY", "https://idp/realms/suite"))));

        var on = DashboardSignIn.FromEnvironment(Env(
            ("NIGHTOWL_OIDC_AUTHORITY", "https://idp/realms/suite"), ("NIGHTOWL_OIDC_CLIENT_ID", "nightowl"),
            ("NIGHTOWL_OIDC_CLIENT_SECRET", "s3cret"), ("NIGHTOWL_OIDC_GROUP", "appsec")))!;
        Assert.Equal(("https://idp/realms/suite", "nightowl", "s3cret", "appsec", true), (on.Authority, on.ClientId, on.ClientSecret, on.Group, on.RequireHttpsMetadata));

        var dev = DashboardSignIn.FromEnvironment(Env(
            ("NIGHTOWL_OIDC_AUTHORITY", "http://localhost:8080/realms/suite"), ("NIGHTOWL_OIDC_CLIENT_ID", "nightowl"), ("NIGHTOWL_OIDC_REQUIRE_HTTPS_METADATA", "false")))!;
        Assert.False(dev.RequireHttpsMetadata);
        Assert.Null(dev.ClientSecret);
        Assert.Null(dev.Group);
    }

    [Fact]
    public void Group_membership_reads_groups_and_roles_claims()
    {
        var member = new ClaimsPrincipal(new ClaimsIdentity([new Claim("groups", "/appsec"), new Claim("groups", "/engineering")], "oidc"));
        var role = new ClaimsPrincipal(new ClaimsIdentity([new Claim("roles", "AppSec")], "oidc"));
        var outsider = new ClaimsPrincipal(new ClaimsIdentity([new Claim("groups", "/finance")], "oidc"));
        Assert.True(DashboardSignIn.InGroup(member, "appsec"));
        Assert.True(DashboardSignIn.InGroup(role, "appsec"));
        Assert.False(DashboardSignIn.InGroup(outsider, "appsec"));
    }
}
