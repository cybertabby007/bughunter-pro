"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Search, BookOpen, Activity } from "lucide-react";

const links = [
  { href: "/",        label: "Scanner",  icon: Search   },
  { href: "/results", label: "Results",  icon: Activity },
  { href: "/learn",   label: "Learn",    icon: BookOpen },
];

export default function Navbar() {
  const pathname = usePathname();

  return (
    <nav style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}
         className="sticky top-0 z-50 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 flex items-center h-14 gap-8">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2 font-bold text-lg no-underline">
          <div className="w-7 h-7 rounded flex items-center justify-center"
               style={{ background: "var(--accent)" }}>
            <Shield size={15} color="white" />
          </div>
          <span style={{ color: "white" }}>BugHunter</span>
          <span style={{ color: "var(--accent)" }}>Pro</span>
        </Link>

        {/* Links */}
        <div className="flex items-center gap-1 ml-4">
          {links.map(({ href, label, icon: Icon }) => {
            const active = pathname === href;
            return (
              <Link key={href} href={href}
                className="flex items-center gap-2 px-3 py-1.5 rounded text-sm no-underline transition-colors"
                style={{
                  color: active ? "var(--accent)" : "var(--muted)",
                  background: active ? "rgba(127,119,221,0.12)" : "transparent",
                }}>
                <Icon size={14} />
                {label}
              </Link>
            );
          })}
        </div>

        {/* Version badge */}
        <div className="ml-auto text-xs px-2 py-1 rounded"
             style={{ background: "var(--surface-2)", color: "var(--muted)", border: "1px solid var(--border)" }}>
          v1.0.0
        </div>
      </div>
    </nav>
  );
}
