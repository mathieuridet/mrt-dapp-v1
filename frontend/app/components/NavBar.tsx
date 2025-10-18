"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ConnectButton } from "@rainbow-me/rainbowkit";

const links = [
  { href: "/nft", label: "NFT" },
  { href: "/token/claim", label: "Claim" },
  { href: "/token/stake", label: "Stake" },
];

export default function NavBar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b bg-white/70 backdrop-blur supports-[backdrop-filter]:bg-white/60">
      <div className="mx-auto max-w-5xl flex items-center justify-between gap-3 p-3">
        <Link href="/" className="text-base font-semibold tracking-tight">MRT dApp</Link>

        {/* Desktop nav */}
        <nav className="hidden md:flex items-center gap-1">
          {links.map(({ href, label }) => {
            const active =
              pathname === href || (href !== "/nft" && pathname?.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                className={[
                  "rounded-lg px-3 py-2 text-sm transition-colors",
                  active ? "bg-black text-white" : "text-gray-700 hover:bg-gray-100",
                ].join(" ")}
              >
                {label}
              </Link>
            );
          })}
        </nav>

        <div className="flex items-center gap-2">
          <ConnectButton accountStatus="address" chainStatus="icon" showBalance={false} />
          <button
            className="md:hidden rounded border px-3 py-2 text-sm"
            onClick={() => setOpen((v) => !v)}
            aria-label="Toggle menu"
          >
            Menu
          </button>
        </div>
      </div>

      {/* Mobile nav */}
      {open && (
        <nav className="md:hidden border-t">
          {links.map(({ href, label }) => {
            const active =
              pathname === href || (href !== "/nft" && pathname?.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                onClick={() => setOpen(false)}
                className={[
                  "block px-4 py-3 text-sm",
                  active ? "bg-black text-white" : "hover:bg-gray-100",
                ].join(" ")}
              >
                {label}
              </Link>
            );
          })}
        </nav>
      )}
    </header>
  );
}
