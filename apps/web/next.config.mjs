import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Self-contained server bundle: traces only the production deps actually
  // used, so the Docker image ships ~minimal node_modules instead of the full
  // dev tree. The trace root is the monorepo root so workspace packages and
  // hoisted node_modules resolve.
  output: 'standalone',
  outputFileTracingRoot: path.join(__dirname, '../../'),
  // Compile the workspace component package from source.
  transpilePackages: ['@relix-q/web-components'],
  experimental: {
    // Allow source-archive (.zip) uploads through the "Upload code" project source.
    serverActions: { bodySizeLimit: '1024mb' },
  },
};

export default nextConfig;
