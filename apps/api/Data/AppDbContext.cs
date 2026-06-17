// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using Microsoft.EntityFrameworkCore;
using RelixQ.OssApi.Domain;

namespace RelixQ.OssApi.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<ScanRun> ScanRuns => Set<ScanRun>();
    public DbSet<FindingRecord> Findings => Set<FindingRecord>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>().HasIndex(u => u.Email).IsUnique();
        b.Entity<Session>().HasIndex(s => s.TokenHash).IsUnique();
        b.Entity<Project>().HasIndex(p => p.Slug).IsUnique();
        b.Entity<ScanRun>().HasIndex(s => s.ProjectId);
        b.Entity<FindingRecord>().HasIndex(f => f.ScanRunId);
        b.Entity<FindingRecord>().HasIndex(f => f.ProjectId);
    }
}
