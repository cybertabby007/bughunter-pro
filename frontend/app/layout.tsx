import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BugHunter Pro — Professional Bug Bounty Platform",
  description: "Automated security scanning for authorized bug bounty hunters and penetration testers.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full flex flex-col" style={{ background: "var(--bg)", color: "var(--body)" }}>
        {children}
      </body>
    </html>
  );
}
