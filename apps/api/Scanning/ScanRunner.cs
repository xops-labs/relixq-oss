// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RelixQ.Contracts;
using RelixQ.OssApi.Data;
using RelixQ.OssApi.Domain;

namespace RelixQ.OssApi.Scanning;

/// <summary>Config for the scan runner — paths to the bundled engine + rules + samples.</summary>
public sealed class ScanOptions
{
    public string ScannerBin { get; set; } = "relixq-scan-code";
    public string RulesDir { get; set; } = "rules";
    public string FixturesDir { get; set; } = "fixtures";
    /// <summary>Host directory mounted into the container; "local" sources are subpaths under it.</summary>
    public string LocalRoot { get; set; } = "/scan";
    /// <summary>Where uploaded source archives ("upload" sources) are stored for (re-)scans.</summary>
    public string UploadsDir { get; set; } = "/app/uploads";
    /// <summary>Cap on total uncompressed bytes when extracting an uploaded archive (zip-bomb guard).</summary>
    public long MaxExtractBytes { get; set; } = 1L * 1024 * 1024 * 1024; // 1 GiB
    public string GitBin { get; set; } = "git";
    public int TimeoutSeconds { get; set; } = 300;
}

/// <summary>
/// Executes one scan end-to-end: materialize the source (bundled sample or git
/// clone) → shell the OSS <c>relixq-scan-code</c> engine → parse JSONL findings
/// → score each via <see cref="ScoringService"/> → persist. Runs as a fire-and-
/// forget background task in its own DI scope (single-replica self-host; no
/// queue — deliberately avoiding a cross-container handoff).
/// </summary>
public sealed class ScanRunner(AppDbContext db, ScoringService scoring, ScanOptions opts, ILogger<ScanRunner> log)
{
    private static readonly JsonSerializerOptions SnakeCase = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
    };

    public async Task ExecuteAsync(Guid scanRunId, CancellationToken ct = default)
    {
        var scan = await db.ScanRuns.FirstOrDefaultAsync(s => s.Id == scanRunId, ct);
        if (scan is null) return;
        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == scan.ProjectId, ct);
        if (project is null) { await FailAsync(scan, "project not found", ct); return; }

        string? cloneDir = null;
        var findingsPath = Path.Combine(Path.GetTempPath(), $"relixq-{scanRunId:N}.jsonl");
        var agilityPath = Path.Combine(Path.GetTempPath(), $"relixq-{scanRunId:N}.agility.json");
        var summaryPath = Path.Combine(Path.GetTempPath(), $"relixq-{scanRunId:N}.summary.json");
        try
        {
            var (scanDir, isClone) = await MaterializeSourceAsync(project, ct);
            if (isClone) cloneDir = scanDir;

            await RunEngineAsync(scanDir, findingsPath, agilityPath, summaryPath, ct);

            var findings = ParseFindings(findingsPath);
            var worst = 0;
            foreach (var cf in findings)
            {
                var result = scoring.Score(cf);
                if (result.Score > worst) worst = result.Score;
                db.Findings.Add(new FindingRecord
                {
                    ScanRunId = scan.Id,
                    ProjectId = scan.ProjectId,
                    RuleId = cf.RuleId,
                    Language = cf.Language,
                    Algorithm = cf.Algorithm,
                    UsageType = cf.UsageType,
                    QuantumSafety = cf.QuantumSafety,
                    Severity = cf.Severity,
                    KeySize = cf.KeySize,
                    FilePath = cf.FilePath,
                    LineNumber = cf.LineNumber,
                    Snippet = cf.Snippet,
                    Category = cf.Category,
                    Message = cf.Message,
                    Recommendation = cf.Recommendation,
                    Score = result.Score,
                    ScoreLevel = result.Level.ToString(),
                });
            }

            scan.FindingCount = findings.Count;
            scan.Score = findings.Count == 0 ? 0 : worst;
            scan.ScoreLevel = ScoringService.LevelForScore(scan.Score ?? 0).ToString();
            ReadAgility(agilityPath, scan);
            ReadSummary(summaryPath, scan);
            scan.Status = "succeeded";
            scan.CompletedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
            log.LogInformation("scan {Id} succeeded: {Count} findings, score {Score}", scan.Id, scan.FindingCount, scan.Score);
        }
        catch (Exception ex)
        {
            await FailAsync(scan, ex.Message, ct);
            log.LogError(ex, "scan {Id} failed", scanRunId);
        }
        finally
        {
            TryDelete(findingsPath);
            TryDelete(agilityPath);
            TryDelete(summaryPath);
            if (cloneDir is not null) TryDeleteDir(cloneDir);
        }
    }

    private async Task<(string dir, bool isClone)> MaterializeSourceAsync(Project p, CancellationToken ct)
    {
        if (string.Equals(p.SourceKind, "git", StringComparison.OrdinalIgnoreCase))
        {
            var url = p.SourceValue.Trim();
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("git source must be an http(s) URL");

            // For private repos: inject the token as HTTP basic auth without storing it in the
            // clone's remote (so it doesn't linger on disk) and redact it from any error output.
            var token = string.IsNullOrWhiteSpace(p.SourceToken) ? null : p.SourceToken!.Trim();
            string[] args = token is null
                ? ["clone", "--depth", "1", url]
                : ["-c", $"http.extraheader=Authorization: Basic {BasicAuth(token)}", "clone", "--depth", "1", url];

            var dir = Path.Combine(Path.GetTempPath(), $"relixq-clone-{Guid.NewGuid():N}");
            await RunProcessAsync(opts.GitBin, [.. args, dir], ct, secret: token);
            return (dir, true);
        }

        if (string.Equals(p.SourceKind, "local", StringComparison.OrdinalIgnoreCase))
        {
            // SourceValue is a relative subpath under LocalRoot (already traversal-checked at
            // creation; re-verify here so the scanner can never escape the mounted root).
            var root = Path.GetFullPath(opts.LocalRoot);
            var rel = p.SourceValue.Trim().Replace('\\', '/').Trim('/');
            var full = Path.GetFullPath(Path.Combine(root, rel));
            var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
            if (full != root && !full.StartsWith(rootPrefix, StringComparison.Ordinal))
                throw new InvalidOperationException("local path escapes the mounted scan root");
            if (!Directory.Exists(full))
                throw new InvalidOperationException(
                    $"local path '{rel}' not found under the mounted scan directory ({opts.LocalRoot})");
            return (full, false);
        }

        if (string.Equals(p.SourceKind, "upload", StringComparison.OrdinalIgnoreCase))
        {
            // SourceValue is the upload id; the archive lives at {UploadsDir}/{id}.zip and is
            // kept so re-scans don't need a re-upload. Extract to a temp dir scanned then deleted.
            if (!Guid.TryParseExact(p.SourceValue.Trim(), "N", out var uploadId))
                throw new InvalidOperationException("invalid upload id");
            var zipPath = Path.Combine(opts.UploadsDir, $"{uploadId:N}.zip");
            if (!File.Exists(zipPath))
                throw new InvalidOperationException("uploaded archive not found (re-upload the code)");
            var dir = Path.Combine(Path.GetTempPath(), $"relixq-upload-{Guid.NewGuid():N}");
            ExtractZipSafely(zipPath, dir);
            return (dir, true); // isClone => extracted copy is cleaned up after the scan
        }

        // Bundled sample. SourceValue is a simple directory name under FixturesDir.
        var name = p.SourceValue.Trim();
        if (string.IsNullOrEmpty(name) || name.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.')))
            throw new InvalidOperationException("invalid sample id");
        var sampleDir = Path.Combine(opts.FixturesDir, name);
        if (!Directory.Exists(sampleDir))
            throw new InvalidOperationException($"sample '{name}' not found");
        return (sampleDir, false);
    }

    // GitHub/GitLab accept a PAT as the basic-auth password; the username is ignored.
    private static string BasicAuth(string token) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"x-access-token:{token}"));

    /// <summary>Extract a zip, rejecting entries that would escape the destination (zip-slip)
    /// and capping total uncompressed size (zip-bomb).</summary>
    private void ExtractZipSafely(string zipPath, string destDir)
    {
        Directory.CreateDirectory(destDir);
        var root = Path.GetFullPath(destDir);
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        using var archive = ZipFile.OpenRead(zipPath);

        long total = 0;
        foreach (var entry in archive.Entries)
        {
            total += entry.Length;
            if (total > opts.MaxExtractBytes)
                throw new InvalidOperationException("uploaded archive is too large to extract");

            var full = Path.GetFullPath(Path.Combine(root, entry.FullName));
            if (full != root && !full.StartsWith(rootPrefix, StringComparison.Ordinal))
                throw new InvalidOperationException("archive entry escapes the extraction directory");

            if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\'))
            {
                Directory.CreateDirectory(full); // explicit directory entry
                continue;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            entry.ExtractToFile(full, overwrite: true);
        }
    }

    private Task RunEngineAsync(string scanDir, string findingsPath, string agilityPath, string summaryPath, CancellationToken ct) =>
        RunProcessAsync(opts.ScannerBin,
            ["-path", scanDir, "-rules", opts.RulesDir, "-output", findingsPath, "-agility", agilityPath, "-summary", summaryPath], ct);

    private async Task RunProcessAsync(string fileName, string[] args, CancellationToken ct, string? secret = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = new Process { StartInfo = psi };
        var stderr = new StringBuilder();
        proc.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
        if (!proc.Start())
            throw new InvalidOperationException($"failed to start {fileName}");
        proc.BeginErrorReadLine();
        _ = proc.StandardOutput.ReadToEndAsync(ct);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(opts.TimeoutSeconds));
        try
        {
            await proc.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(true); } catch { /* best effort */ }
            throw new InvalidOperationException($"{Path.GetFileName(fileName)} timed out after {opts.TimeoutSeconds}s");
        }

        if (proc.ExitCode != 0)
        {
            var err = stderr.ToString();
            if (!string.IsNullOrEmpty(secret)) err = err.Replace(secret, "***");
            throw new InvalidOperationException($"{Path.GetFileName(fileName)} exited {proc.ExitCode}: {Trim(err)}");
        }
    }

    private static List<CryptoFinding> ParseFindings(string path)
    {
        var list = new List<CryptoFinding>();
        if (!File.Exists(path)) return list;
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var f = JsonSerializer.Deserialize<CryptoFinding>(line, SnakeCase);
                if (f is not null) list.Add(f);
            }
            catch (JsonException) { /* skip malformed line */ }
        }
        return list;
    }

    private void ReadAgility(string path, ScanRun scan)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;
            if (root.TryGetProperty("total_score", out var ts) && ts.TryGetInt32(out var score))
                scan.AgilityScore = score;
            if (root.TryGetProperty("grade", out var g) && g.ValueKind == JsonValueKind.String)
                scan.AgilityGrade = g.GetString();
        }
        catch (JsonException) { /* agility is optional; ignore */ }
    }

    private void ReadSummary(string path, ScanRun scan)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;
            if (root.TryGetProperty("files_scanned", out var fs) && fs.TryGetInt32(out var n))
                scan.FilesScanned = n;
            if (root.TryGetProperty("files_by_language", out var langs) && langs.ValueKind == JsonValueKind.Object)
                scan.LanguagesJson = langs.GetRawText();
        }
        catch (JsonException) { /* summary is optional; ignore */ }
    }

    private async Task FailAsync(ScanRun scan, string error, CancellationToken ct)
    {
        scan.Status = "failed";
        scan.Error = Trim(error);
        scan.CompletedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    private static string Trim(string s) => s.Length > 500 ? s[..500] : s.Trim();
    private static void TryDelete(string p) { try { if (File.Exists(p)) File.Delete(p); } catch { } }
    private static void TryDeleteDir(string p) { try { if (Directory.Exists(p)) Directory.Delete(p, true); } catch { } }
}
