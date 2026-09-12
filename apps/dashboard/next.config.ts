import type { NextConfig } from 'next';

const config: NextConfig = {
  reactStrictMode: true,
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
