import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { NextConfig } from 'next';

const here = dirname(fileURLToPath(import.meta.url));

const config: NextConfig = {
  reactStrictMode: true,
  // Ship a self-contained server with only the dependencies actually imported, so the pilot image is
  // a runtime rather than a checkout.
  output: 'standalone',
  // In a pnpm workspace the file tracer has to be told where the root is, or it follows the symlinked
  // node_modules out of the app and traces the whole monorepo.
  outputFileTracingRoot: join(here, '..', '..'),
  // The review page renders attacker-influenced text (commit messages, tool arguments). A strict CSP
  // with no inline script is the backstop behind React's own escaping (threat T04, T23).
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ];
  },
};

export default config;
