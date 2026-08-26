/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // 'export' is only needed for FastAPI static hosting.
  // In dev mode (next dev) we run as a real server so NEXT_PUBLIC_API_URL
  // is read from .env.local at startup — do not set output:'export' here.
  ...(process.env.NEXT_STATIC_EXPORT === '1' ? {
    output: 'export',
    trailingSlash: true,
  } : {}),
};

module.exports = nextConfig;
