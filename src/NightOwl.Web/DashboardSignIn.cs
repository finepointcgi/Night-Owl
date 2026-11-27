using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;

namespace NightOwl.Web;

/// <summary>
/// Optional single sign-on for the dashboard through any OpenID Connect provider (Keycloak, Entra ID, Okta, Authentik…).
/// Set <c>NIGHTOWL_OIDC_AUTHORITY</c> and <c>NIGHTOWL_OIDC_CLIENT_ID</c> (plus <c>NIGHTOWL_OIDC_CLIENT_SECRET</c> for a
/// confidential client) and every page and export needs a signed-in person; <c>NIGHTOWL_OIDC_GROUP</c> further limits it
/// to members of one group (the <c>groups</c> or <c>roles</c> claim). With sign-on configured the dashboard may listen on
/// the network without <c>NIGHTOWL_DASHBOARD_TOKEN</c>.
/// </summary>
public sealed record DashboardSignIn(string Authority, string ClientId, string? ClientSecret, string? Group, bool RequireHttpsMetadata)
{
    public const string GroupPolicy = "nightowl-dashboard";

    /// <summary>The configured sign-on, or null when the environment doesn't ask for one.</summary>
    public static DashboardSignIn? FromEnvironment(Func<string, string?> env)
    {
        var authority = env("NIGHTOWL_OIDC_AUTHORITY")?.Trim();
        var clientId = env("NIGHTOWL_OIDC_CLIENT_ID")?.Trim();
        if (string.IsNullOrEmpty(authority) && string.IsNullOrEmpty(clientId))
        {
            return null;
        }

        if (string.IsNullOrEmpty(authority) || string.IsNullOrEmpty(clientId))
        {
            throw new InvalidOperationException("Set both NIGHTOWL_OIDC_AUTHORITY and NIGHTOWL_OIDC_CLIENT_ID to turn on single sign-on.");
        }

        var secret = env("NIGHTOWL_OIDC_CLIENT_SECRET")?.Trim();
        var group = env("NIGHTOWL_OIDC_GROUP")?.Trim();
        var requireHttps = !string.Equals(env("NIGHTOWL_OIDC_REQUIRE_HTTPS_METADATA")?.Trim(), "false", StringComparison.OrdinalIgnoreCase);
        return new DashboardSignIn(authority, clientId, string.IsNullOrEmpty(secret) ? null : secret, string.IsNullOrEmpty(group) ? null : group, requireHttps);
    }

    /// <summary>Whether <paramref name="user"/> belongs to <paramref name="group"/> (a groups or roles claim; Keycloak group paths match without the leading slash).</summary>
    public static bool InGroup(ClaimsPrincipal user, string group) =>
        user.Claims.Where(c => c.Type is "groups" or "roles" or ClaimTypes.Role)
            .Any(c => string.Equals(c.Value.TrimStart('/'), group.TrimStart('/'), StringComparison.OrdinalIgnoreCase));

    public void AddTo(IServiceCollection services)
    {
        services.AddAuthentication(o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.Cookie.Name = "nightowl_session";
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.ExpireTimeSpan = TimeSpan.FromHours(8);
                o.SlidingExpiration = true;
                o.AccessDeniedPath = "/access-denied";
            })
            .AddOpenIdConnect(o =>
            {
                o.Authority = Authority;
                o.ClientId = ClientId;
                o.ClientSecret = ClientSecret;
                o.ResponseType = "code";
                o.UsePkce = true;
                o.RequireHttpsMetadata = RequireHttpsMetadata;
                o.MapInboundClaims = false;
                o.SaveTokens = false;
                o.GetClaimsFromUserInfoEndpoint = true;
                o.Scope.Clear();
                foreach (var scope in new[] { "openid", "profile", "email" })
                {
                    o.Scope.Add(scope);
                }

                o.TokenValidationParameters.NameClaimType = "preferred_username";
                o.TokenValidationParameters.RoleClaimType = "roles";
            });

        services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .RequireAssertion(ctx => Group is null || InGroup(ctx.User, Group))
                .Build());
    }

    /// <summary>Sign-out (ends the dashboard session) and the page shown to people outside the group.</summary>
    public static void MapEndpoints(WebApplication app)
    {
        app.MapGet("/signout", async (HttpContext http) =>
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Content("<html><body style='font-family:sans-serif;padding:2rem'><h2>Signed out of Night Owl.</h2><p><a href='/'>Sign in again</a></p></body></html>", "text/html");
        }).AllowAnonymous();
        app.MapGet("/access-denied", () => Results.Content(
            "<html><body style='font-family:sans-serif;padding:2rem'><h2>You're signed in, but not allowed to use this dashboard.</h2><p>Ask an administrator to add you to the dashboard's group.</p></body></html>",
            "text/html", statusCode: StatusCodes.Status403Forbidden)).AllowAnonymous();
    }
}
