import "./globals.css";

export const metadata = {
  title: "Tesht (Pramana)",
  description:
    "Portable identity and scoped authorization for AI agents. W3C DIDs, verifiable credentials, instant revocation.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: 0, padding: 24 }}>
        {children}
      </body>
    </html>
  );
}
