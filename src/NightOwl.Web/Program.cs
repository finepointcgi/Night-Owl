using NightOwl.Core.Reports;
using NightOwl.Web.Components;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Same location the CLI writes to (NIGHTOWL_HOME, default ~/.nightowl).
var nightowlHome = NightOwl.Core.Updates.ManifestStore.Default().HomeDirectory;
builder.Services.AddSingleton(new ReportArchive(nightowlHome));
builder.Services.AddSingleton(new NightOwl.Core.Triage.TriageStore(nightowlHome));
builder.Services.AddSingleton(new ScanHistory(nightowlHome));
builder.Services.AddSingleton(new ScanVault(nightowlHome));
builder.Services.AddSingleton(new ProjectTags(nightowlHome));
builder.Services.AddHostedService<NightOwl.Web.MonitorService>();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// The dashboard shows vulnerabilities and triage controls. Bound to localhost it needs no login; bound to
// any other address it refuses to start unless NIGHTOWL_DASHBOARD_TOKEN is set, and then requires that token.
var dashboardToken = Environment.GetEnvironmentVariable("NIGHTOWL_DASHBOARD_TOKEN");
var configuredUrls = builder.Configuration["urls"] ?? builder.Configuration["ASPNETCORE_URLS"] ?? "http://localhost:5000";
if (string.IsNullOrEmpty(dashboardToken) && !NightOwl.Web.DashboardAccess.AllLoopback(configuredUrls))
{
    Console.Error.WriteLine($"error: the dashboard is configured to listen on {configuredUrls}, which is reachable from the network. Set NIGHTOWL_DASHBOARD_TOKEN to a long random value, or bind to localhost.");
    return 2;
}

var app = builder.Build();

if (!string.IsNullOrEmpty(dashboardToken))
{
    app.Use(NightOwl.Web.DashboardAccess.Middleware(dashboardToken));
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
return 0;
