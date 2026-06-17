import type { Metadata } from 'next';
import Link from 'next/link';

const GITHUB_URL = 'https://github.com/xops-labs/relixq-oss';

export const metadata: Metadata = {
  title: 'About Relix-Q OSS — Open-Source Post-Quantum Cryptography Scanner',
  description:
    'Relix-Q OSS finds quantum-vulnerable cryptography (RSA, ECDSA, DH, weak hashes) across source code, dependencies, TLS endpoints, and certificates. 47 rule packs, 31 languages, SARIF CI gating, self-hosted.',
  keywords: [
    'post-quantum cryptography',
    'PQC scanner',
    'quantum-vulnerable cryptography',
    'crypto inventory',
    'CBOM',
    'RSA detection',
    'ECDSA detection',
    'harvest now decrypt later',
    'ML-KEM',
    'ML-DSA',
    'SARIF',
    'open source security scanner',
    'crypto agility',
  ],
  openGraph: {
    title: 'Relix-Q OSS — Open-Source Post-Quantum Cryptography Scanner',
    description:
      'Find quantum-vulnerable crypto across code, dependencies, TLS, and certificates before quantum computers find it for you. Self-hosted, Apache-2.0.',
    type: 'website',
  },
};

const LANGUAGES = [
  'Python', 'JavaScript', 'TypeScript', 'Go', 'Java', 'C#', 'C', 'C++', 'Rust', 'Ruby',
  'PHP', 'Kotlin', 'Swift', 'Scala', 'Dart', 'Elixir', 'Erlang', 'F#', 'Clojure', 'Perl',
  'Julia', 'Objective-C', 'Shell', 'Ada', 'Q#', 'Solidity', 'Vyper', 'Move', 'Verilog',
  'VHDL', 'IEC 61131-3 (PLC/SCADA)',
];

const CONFIG_FORMATS = [
  'nginx', 'Apache httpd', 'OpenSSL config', 'OpenSSH (sshd_config / ssh_config)',
  'Dockerfile', 'Docker Compose', 'Kubernetes', 'Helm', 'Ansible', 'Terraform',
  'CloudFormation', 'Azure ARM', 'Bicep', 'Envoy', 'X.509 certificates & keys (.pem/.crt/.der/.key)',
  'Jupyter notebooks',
];

const STATS: { value: string; label: string }[] = [
  { value: '725+', label: 'detection rules' },
  { value: '47', label: 'rule packs' },
  { value: '31', label: 'programming languages' },
  { value: '0', label: 'false positives on PQC code' },
];

const FEATURES: { title: string; body: string }[] = [
  {
    title: 'Source-code crypto detection',
    body:
      '725+ rules across 47 packs find quantum-vulnerable crypto APIs — with a regex recall floor everywhere and AST precision (Go, JS/TS, PHP always; tree-sitter languages and Roslyn C# in the Docker build).',
  },
  {
    title: 'Dependency scanning',
    body:
      'relixq scan deps reads requirements.txt, package.json, go.mod, Pipfile, and pyproject.toml and flags packages that implement quantum-vulnerable crypto — offline, from an embedded knowledge base.',
  },
  {
    title: 'TLS & certificate scanning',
    body:
      'relixq scan tls probes live endpoints for classical key exchange, weak cipher suites, deprecated TLS 1.0/1.1, and expiring or self-signed certs. Certificate files on disk are parsed for both the public-key and the signature algorithm.',
  },
  {
    title: 'Hand-rolled crypto detection',
    body:
      'A FindCrypt-style constant-fingerprint pack (AES S-boxes, SHA constants, RFC 3526 primes, RSA exponents) plus multi-signal promotion surfaces hand-written crypto that has no library API to match.',
  },
  {
    title: 'Risk scoring & crypto agility',
    body:
      'Every finding is scored; every scan gets a 0–100 risk score and a crypto-agility grade, so you can rank what to migrate first and track readiness over time.',
  },
  {
    title: 'CI gating with SARIF',
    body:
      'A GitHub Action and slim scanner image emit SARIF 2.1.0 for GitHub Code Scanning, with severity gates (--exit-on), baselines for new-findings-only PR checks, and JSON/JSONL/Markdown/HTML outputs.',
  },
  {
    title: 'Coverage you can audit',
    body:
      'A labeled ground-truth corpus gates every build (recall, precision, and zero false positives on PQC code), every rule carries inline self-tests, and a coverage sentinel flags files that use crypto libraries the rules did not recognize.',
  },
  {
    title: 'Self-hosted & private',
    body:
      'docker compose up gives you Postgres, the API, and this web UI on your own machine. Your code never leaves your infrastructure — no SaaS, no telemetry, no external dependencies.',
  },
];

const VULN_GROUPS: { title: string; accent: string; dot: string; items: string[] }[] = [
  {
    title: 'Quantum-broken (Shor’s algorithm)',
    accent: 'border-rose-500/30 bg-rose-500/[0.06]',
    dot: 'bg-rose-400',
    items: [
      'RSA — key generation, encryption, signatures, key transport',
      'Elliptic-curve crypto — ECDSA, ECDH, EdDSA (Ed25519/Ed448), X25519',
      'Finite-field crypto — Diffie-Hellman, DSA',
      'Classical TLS key exchange and cipher-suite pins',
      'SSH host keys, key-exchange and accepted-key algorithms',
      'JWT RS*/ES*/PS* signing algorithms',
      'X.509 certificates — both the public key and the signature algorithm',
      'Hardcoded private keys and inline PEM blocks',
    ],
  },
  {
    title: 'Quantum-weakened (Grover’s algorithm)',
    accent: 'border-amber-500/30 bg-amber-500/[0.06]',
    dot: 'bg-amber-400',
    items: [
      'AES-128 and other ≤128-bit symmetric ciphers',
      '3DES / Triple-DES',
      'Hash usage where halved preimage strength matters',
    ],
  },
  {
    title: 'Broken today (no quantum computer required)',
    accent: 'border-slate-500/30 bg-slate-500/[0.08]',
    dot: 'bg-slate-400',
    items: [
      'MD5, SHA-1, MD4, MD2 hashing',
      'RC4, RC2, and single DES ciphers',
      'Deprecated TLS 1.0 / 1.1 and SSLv3 configuration',
    ],
  },
];

/** Dark "quantum" band: deep indigo gradient + cyan/violet orbital glows. */
function DarkBand({ id, children, className = '' }: { id?: string; children: React.ReactNode; className?: string }) {
  return (
    <section
      id={id}
      className={`relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-950 via-indigo-950 to-slate-900 text-slate-100 ${className}`}
    >
      <div aria-hidden className="pointer-events-none absolute -left-24 -top-24 h-72 w-72 rounded-full bg-cyan-500/20 blur-3xl" />
      <div aria-hidden className="pointer-events-none absolute -bottom-32 -right-16 h-80 w-80 rounded-full bg-violet-600/20 blur-3xl" />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.07]"
        style={{
          backgroundImage:
            'linear-gradient(to right, currentColor 1px, transparent 1px), linear-gradient(to bottom, currentColor 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />
      <div className="relative">{children}</div>
    </section>
  );
}

/** Light "reliability" band: clean slate surface with an indigo hairline accent. */
function LightBand({ id, title, kicker, children }: { id: string; title: string; kicker: string; children: React.ReactNode }) {
  return (
    <section id={id} className="rounded-3xl border border-slate-200 bg-slate-50/80 p-6 sm:p-10">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-indigo-600">{kicker}</p>
      <h2 className="mt-1 text-xl font-semibold tracking-tight text-slate-900 sm:text-2xl">{title}</h2>
      <div className="mt-5">{children}</div>
    </section>
  );
}

export default function AboutPage() {
  return (
    <article className="mx-auto max-w-5xl space-y-8">
      {/* ---- Hero: quantum dark ---- */}
      <DarkBand>
        <header className="px-6 py-14 text-center sm:px-12 sm:py-20">
          <p className="mx-auto mb-4 inline-block rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-xs font-medium tracking-wide text-cyan-300">
            Open source · Self-hosted · Apache-2.0
          </p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-5xl">
            Find{' '}
            <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-violet-400 bg-clip-text text-transparent">
              quantum-vulnerable
            </span>{' '}
            cryptography
            <br className="hidden sm:block" /> before quantum computers find it for you.
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-lg text-slate-300">
            Relix-Q OSS is an open-source, self-hosted post-quantum cryptography (PQC) risk scanner. It inventories
            every weak crypto usage across your source code, dependencies, TLS endpoints, and certificates — then
            scores the risk and gates your CI.
          </p>
          <div className="mt-7 flex justify-center gap-3">
            <a
              href={GITHUB_URL}
              className="rounded-md bg-cyan-400 px-5 py-2.5 text-sm font-semibold text-slate-950 shadow-lg shadow-cyan-500/20 hover:bg-cyan-300 focus-ring"
            >
              Star on GitHub
            </a>
            <Link
              href="/signup"
              className="rounded-md border border-slate-500/60 px-5 py-2.5 text-sm font-semibold text-slate-100 hover:border-slate-300 hover:bg-white/5 focus-ring"
            >
              Get started — it&apos;s free
            </Link>
          </div>

          {/* Reliability stats strip */}
          <dl className="mx-auto mt-12 grid max-w-3xl grid-cols-2 gap-px overflow-hidden rounded-xl border border-white/10 bg-white/10 sm:grid-cols-4">
            {STATS.map((s) => (
              <div key={s.label} className="bg-slate-950/60 px-4 py-4">
                <dd className="font-mono text-2xl font-semibold text-cyan-300">{s.value}</dd>
                <dt className="mt-1 text-xs text-slate-400">{s.label}</dt>
              </div>
            ))}
          </dl>
        </header>
      </DarkBand>

      {/* ---- Why: urgency, light surface with vulnerability accent ---- */}
      <LightBand id="why" kicker="The threat" title="Why post-quantum readiness can't wait">
        <div className="rounded-2xl border-l-4 border-rose-500 bg-white p-5 shadow-sm">
          <p className="text-slate-600">
            Encrypted traffic and signed artifacts are being recorded <em>today</em> to be decrypted the day a
            cryptographically relevant quantum computer exists — the &ldquo;harvest now, decrypt later&rdquo; attack.
            Shor&rsquo;s algorithm breaks RSA, elliptic-curve, and Diffie-Hellman cryptography outright;
            Grover&rsquo;s algorithm halves symmetric strength. NIST has already standardized the replacements
            (ML-KEM / FIPS 203, ML-DSA / FIPS 204, SLH-DSA / FIPS 205), and migration deadlines are landing in
            compliance frameworks now. <strong className="text-slate-900">You cannot migrate what you cannot find</strong> —
            and most organizations have no inventory of where their cryptography lives. That inventory is exactly
            what Relix-Q builds.
          </p>
        </div>
      </LightBand>

      {/* ---- What it does ---- */}
      <LightBand id="what" kicker="The pipeline" title="What Relix-Q OSS does">
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {[
            ['Discovers', 'every cryptographic usage — library calls, configuration directives, certificates, dependency declarations, even hand-rolled implementations.'],
            ['Classifies', 'each finding on a three-tier quantum-risk taxonomy: quantum-broken (Shor), quantum-weakened (Grover), or classically broken.'],
            ['Scores', 'the risk per finding and per scan, with a crypto-agility grade that measures how hard migration will be.'],
            ['Gates', 'your CI: SARIF for GitHub Code Scanning, severity thresholds, and baselines that block only new vulnerable crypto.'],
            ['Recommends', 'the PQC replacement — ML-KEM for key exchange, ML-DSA / SLH-DSA for signatures, AES-256 for symmetric.'],
          ].map(([verb, rest], i) => (
            <li key={verb} className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
              <span className="font-mono text-xs text-indigo-500">0{i + 1}</span>
              <h3 className="mt-1 font-semibold text-slate-900">{verb}</h3>
              <p className="mt-1 text-sm text-slate-600">{rest}</p>
            </li>
          ))}
        </ol>
      </LightBand>

      {/* ---- Features ---- */}
      <LightBand id="features" kicker="Capabilities" title="Features">
        <div className="grid gap-4 sm:grid-cols-2">
          {FEATURES.map((f) => (
            <div key={f.title} className="group rounded-2xl border border-slate-200 bg-white p-5 shadow-sm transition-colors hover:border-indigo-300">
              <h3 className="font-semibold text-slate-900">
                <span aria-hidden className="mr-2 inline-block h-2 w-2 rounded-full bg-gradient-to-r from-cyan-400 to-violet-500 align-middle" />
                {f.title}
              </h3>
              <p className="mt-2 text-sm text-slate-600">{f.body}</p>
            </div>
          ))}
        </div>
      </LightBand>

      {/* ---- Coverage ---- */}
      <LightBand id="languages" kicker="Coverage" title="Language & format coverage">
        <p className="text-slate-600">
          <strong className="text-slate-900">{LANGUAGES.length} programming languages</strong> — from web backends
          to smart contracts to industrial PLCs:
        </p>
        <ul className="mt-3 flex flex-wrap gap-2">
          {LANGUAGES.map((l) => (
            <li key={l} className="rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1 font-mono text-xs text-indigo-900">
              {l}
            </li>
          ))}
        </ul>
        <p className="mt-6 text-slate-600">
          Plus <strong className="text-slate-900">configuration, infrastructure, and artifacts</strong> — where
          crypto policy actually lives:
        </p>
        <ul className="mt-3 flex flex-wrap gap-2">
          {CONFIG_FORMATS.map((l) => (
            <li key={l} className="rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1 font-mono text-xs text-cyan-900">
              {l}
            </li>
          ))}
        </ul>
      </LightBand>

      {/* ---- What it finds: vulnerability tones on quantum dark ---- */}
      <DarkBand id="vulnerabilities">
        <div className="px-6 py-10 sm:px-10 sm:py-12">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-rose-300">The vulnerabilities</p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight sm:text-2xl">What it finds</h2>
          <div className="mt-6 grid gap-4 lg:grid-cols-3">
            {VULN_GROUPS.map((g) => (
              <div key={g.title} className={`rounded-2xl border p-5 backdrop-blur ${g.accent}`}>
                <h3 className="flex items-center gap-2 font-semibold text-slate-100">
                  <span aria-hidden className={`h-2.5 w-2.5 rounded-full ${g.dot}`} />
                  {g.title}
                </h3>
                <ul className="mt-3 space-y-2 text-sm text-slate-300">
                  {g.items.map((i) => (
                    <li key={i} className="flex gap-2">
                      <span aria-hidden className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-slate-500" />
                      {i}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <p className="mt-6 rounded-2xl border border-emerald-400/30 bg-emerald-400/10 p-4 text-sm text-emerald-200">
            <strong className="text-emerald-100">Quantum-safe crypto is never flagged:</strong> ML-KEM, ML-DSA,
            SLH-DSA, SPHINCS+, hybrid suites like X25519MLKEM768, AES-256, and SHA-3 pass clean — verified
            continuously by a ground-truth validation corpus with a zero-false-positive gate.
          </p>
        </div>
      </DarkBand>

      {/* ---- Security checks ---- */}
      <LightBand id="security-checks" kicker="Defense in depth" title="Security checks, end to end">
        <ul className="grid gap-3 sm:grid-cols-2">
          {[
            'Static code analysis — regex recall floor plus AST precision, with per-file panic isolation.',
            'Dependency manifest analysis against a curated crypto knowledge base (no network needed).',
            'Live TLS handshake probing — protocol versions, key exchange, cipher suites, certificate health.',
            'At-rest certificate and key-material inspection (public key AND signature algorithm).',
            'Config-only crypto: web-server cipher lists, SSH daemon policy, OpenSSL defaults, IaC crypto settings.',
            'Hardcoded-secret detection for committed private keys (CWE-798).',
            'A coverage sentinel that reports files using crypto libraries the rules didn’t recognize — the scanner tells you about its own blind spots instead of staying silent.',
          ].map((item) => (
            <li key={item} className="flex gap-3 rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm">
              <span aria-hidden className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-indigo-100 font-mono text-[10px] font-bold text-indigo-700">
                ✓
              </span>
              {item}
            </li>
          ))}
        </ul>
      </LightBand>

      {/* ---- Community ---- */}
      <LightBand id="community" kicker="Open source" title="Community & GitHub">
        <p className="text-slate-600">
          Relix-Q OSS is Apache-2.0 licensed and developed in the open. The entire stack — Go scanner engine, rule
          packs, .NET API, and this web UI — lives in one repository, and a fresh clone runs end-to-end with a
          single <code className="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-xs text-slate-800">docker compose up</code>.
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          {[
            ['Repository', 'Source, releases, and the GitHub Action.', GITHUB_URL],
            ['Issues', 'Report missed crypto, false positives, or request a language — every new rule ships with inline self-tests.', `${GITHUB_URL}/issues`],
            ['Changelog', 'What shipped, release by release.', `${GITHUB_URL}/blob/main/CHANGELOG.md`],
          ].map(([title, body, href]) => (
            <a
              key={title}
              href={href}
              className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition-colors hover:border-indigo-300 focus-ring"
            >
              <h3 className="font-semibold text-indigo-700">{title} ↗</h3>
              <p className="mt-1 text-sm text-slate-600">{body}</p>
            </a>
          ))}
        </div>
      </LightBand>

      {/* ---- Closing CTA: quantum dark ---- */}
      <DarkBand>
        <footer className="px-6 py-12 text-center sm:px-12">
          <h2 className="text-2xl font-bold tracking-tight">
            Start your{' '}
            <span className="bg-gradient-to-r from-cyan-400 to-violet-400 bg-clip-text text-transparent">
              post-quantum inventory
            </span>{' '}
            today
          </h2>
          <p className="mx-auto mt-2 max-w-xl text-sm text-slate-300">
            Scan the bundled vulnerable sample in under a minute, then point Relix-Q at your own repositories,
            dependencies, and endpoints.
          </p>
          <div className="mt-6 flex justify-center gap-3">
            <Link
              href="/signup"
              className="rounded-md bg-cyan-400 px-5 py-2.5 text-sm font-semibold text-slate-950 shadow-lg shadow-cyan-500/20 hover:bg-cyan-300 focus-ring"
            >
              Create a project
            </Link>
            <a
              href={GITHUB_URL}
              className="rounded-md border border-slate-500/60 px-5 py-2.5 text-sm font-semibold text-slate-100 hover:border-slate-300 hover:bg-white/5 focus-ring"
            >
              View on GitHub
            </a>
          </div>
        </footer>
      </DarkBand>
    </article>
  );
}
