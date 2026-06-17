# syntax=docker/dockerfile:1
# Build context is the repo root (see docker-compose.yml).

# ---- Stage 1: build the Go scanner engine WITH CGO (full AST coverage) ----
# Debian-based golang so the cgo binary links glibc, matching the aspnet runtime
# below. CGO_ENABLED=1 + the bundled gcc compile the Tree-sitter grammar runners
# (C/C++, Java, Ruby, Rust, Swift, Julia, Scala, Kotlin); without cgo these would
# be no-op stubs and those languages would fall back to the regex floor.
FROM golang:1.25-bookworm AS engine
WORKDIR /src
COPY packages/go ./packages/go
RUN cd packages/go && CGO_ENABLED=1 go build -o /out/relixq-scan-code ./cmd/relixq-scan-code

# ---- Stage 2: publish the .NET API (consumes the OSS packages) ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS apibuild
WORKDIR /src
COPY packages/dotnet ./packages/dotnet
COPY apps/api ./apps/api
RUN dotnet publish apps/api/RelixQ.OssApi.csproj -c Release -o /app/publish /p:UseAppHost=false

# ---- Stage 3: publish the relixq-roslyn C# AST subprocess ----
# Framework-dependent linux-x64 apphost; the .NET 8 runtime is present in the
# aspnet runtime image below, so the engine can exec it directly.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS roslyn
WORKDIR /src
COPY packages/go/detectors/csharpast/tools/relixq-roslyn ./relixq-roslyn
RUN dotnet publish relixq-roslyn/relixq-roslyn.csproj -c Release -o /roslyn

# ---- Stage 4: runtime ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
# git: clone the "git URL" project source. ca-certificates: TLS for git over https.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=apibuild /app/publish ./
COPY --from=engine /out/relixq-scan-code /app/bin/relixq-scan-code
COPY --from=roslyn /roslyn /app/roslyn
COPY packages/go/rules-community /app/rules
COPY fixtures /app/fixtures
ENV Scan__ScannerBin=/app/bin/relixq-scan-code \
    Scan__RulesDir=/app/rules \
    Scan__FixturesDir=/app/fixtures \
    Scan__LocalRoot=/scan \
    Scan__UploadsDir=/app/uploads \
    Scan__GitBin=git \
    RELIXQ_ROSLYN_BIN=/app/roslyn/relixq-roslyn \
    ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080
ENTRYPOINT ["dotnet", "RelixQ.OssApi.dll"]
