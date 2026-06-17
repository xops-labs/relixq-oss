// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using Microsoft.EntityFrameworkCore;
using RelixQ.Auth.Local;
using RelixQ.OssApi.Data;
using RelixQ.OssApi.Endpoints;
using RelixQ.OssApi.Scanning;

var builder = WebApplication.CreateBuilder(args);

// ---- Uploads: allow source-archive (.zip) bodies well beyond the small defaults ----
const long MaxUploadBytes = 1024L * 1024 * 1024; // 1 GiB
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = MaxUploadBytes);
builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = MaxUploadBytes;
});

// ---- Persistence ----
var conn = builder.Configuration.GetConnectionString("Postgres")
           ?? "Host=localhost;Port=5432;Database=relixq;Username=relixq;Password=relixq";
builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(conn));

// ---- Local auth (RelixQ.Auth.Local) ----
// Demo-tuned Argon2 + a friendlier strength gate than the production defaults.
builder.Services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher(
    new Argon2Options { MemoryKiB = 19456, Iterations = 2, Parallelism = 1 }));
builder.Services.AddSingleton<IPasswordStrengthValidator>(new ZxcvbnPasswordStrengthValidator(
    new PasswordStrengthOptions { MinLength = 8, MinScore = 2 }));

// ---- Scanning (RelixQ.Scoring + the bundled Go engine) ----
var scanOpts = builder.Configuration.GetSection("Scan").Get<ScanOptions>() ?? new ScanOptions();
builder.Services.AddSingleton(scanOpts);
builder.Services.AddSingleton<ScoringService>();
builder.Services.AddScoped<ScanRunner>();

// ---- CORS (only needed if the browser calls the API directly) ----
var webOrigin = builder.Configuration["Web:Origin"];
if (!string.IsNullOrWhiteSpace(webOrigin))
{
    builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
        p.WithOrigins(webOrigin).AllowAnyHeader().AllowAnyMethod().AllowCredentials()));
}

var app = builder.Build();

// ---- Schema bootstrap (EnsureCreated; no migrations for the demo) ----
await EnsureDatabaseAsync(app);

if (!string.IsNullOrWhiteSpace(webOrigin)) app.UseCors();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapGet("/", () => Results.Ok(new { service = "relixq-oss-api", status = "ok" }));

app.MapAuthEndpoints();
app.MapProjectEndpoints();
app.MapExportEndpoints();
app.MapUploadEndpoints();
app.MapScanEndpoints();

app.Run();

static async Task EnsureDatabaseAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var log = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("startup");
    for (var attempt = 1; ; attempt++)
    {
        try
        {
            await db.Database.EnsureCreatedAsync();
            // EnsureCreated doesn't migrate existing databases; nudge the one additive
            // column so demo DBs created before "local/token sources" keep working.
            await db.Database.ExecuteSqlRawAsync(
                "ALTER TABLE \"Projects\" ADD COLUMN IF NOT EXISTS \"SourceToken\" text;");
            await db.Database.ExecuteSqlRawAsync(
                "ALTER TABLE \"ScanRuns\" ADD COLUMN IF NOT EXISTS \"FilesScanned\" integer, " +
                "ADD COLUMN IF NOT EXISTS \"LanguagesJson\" text;");
            // Marketing/lead capture moved to the separate website project;
            // clean up tables a briefly-shipped build may have created.
            await db.Database.ExecuteSqlRawAsync(
                """
                DROP TABLE IF EXISTS "NewsletterSubscribers";
                DROP TABLE IF EXISTS "MarketingEvents";
                """);
            log.LogInformation("database ready");
            return;
        }
        catch (Exception ex) when (attempt <= 15)
        {
            log.LogWarning("database not ready (attempt {Attempt}): {Message}", attempt, ex.Message);
            await Task.Delay(2000);
        }
    }
}
