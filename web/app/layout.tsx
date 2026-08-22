import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AIROM Enterprise AI Governance & Statutory Compliance",
  description: "Continuous statutory compliance, shadow AI detection, and tamper-evident state ledger for enterprise AI assets.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-gray-950 text-gray-100 antialiased selection:bg-blue-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}
