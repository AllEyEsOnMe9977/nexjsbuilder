"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ThemeToggle } from "@/components/ThemeToggle";
import { BookOpenIcon, MenuIcon, XIcon, SparklesIcon } from "@/components/Icons";

const NAV_LINKS = [
  { href: "/", label: "Articles" },
  { href: "/category/Architecture", label: "Architecture" },
  { href: "/category/Design", label: "Design" },
  { href: "/about", label: "About" },
];

export function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-40 w-full border-b border-zinc-200/80 bg-white/80 backdrop-blur-md transition-colors dark:border-zinc-800/80 dark:bg-zinc-950/80">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <Link href="/" className="group flex items-center gap-2.5 transition-opacity hover:opacity-90">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 text-white shadow-xs transition-transform group-hover:scale-105">
            <BookOpenIcon className="h-5 w-5" />
          </div>
          <div className="flex flex-col">
            <span className="font-bold tracking-tight text-zinc-900 transition-colors dark:text-zinc-50 text-base sm:text-lg flex items-center gap-1.5">
              Chronicle
              <span className="inline-flex items-center rounded-full bg-blue-50 dark:bg-blue-950/60 px-1.5 py-0.5 text-[10px] font-semibold text-blue-600 dark:text-blue-400 border border-blue-200/60 dark:border-blue-800/60">
                v2
              </span>
            </span>
          </div>
        </Link>

        <nav className="hidden md:flex items-center gap-1 text-sm font-medium text-zinc-600 dark:text-zinc-300">
          {NAV_LINKS.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`rounded-lg px-3 py-1.5 transition-colors ${
                  isActive
                    ? "bg-zinc-100 text-zinc-950 dark:bg-zinc-800 dark:text-white font-semibold"
                    : "hover:bg-zinc-100/70 hover:text-zinc-900 dark:hover:bg-zinc-900 dark:hover:text-white"
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>

        <div className="flex items-center gap-2 sm:gap-3">
          <ThemeToggle />

          <Link
            href="/#newsletter"
            className="hidden sm:inline-flex items-center gap-1.5 rounded-xl bg-zinc-900 px-3.5 py-2 text-xs font-semibold text-white shadow-xs transition-all hover:bg-zinc-800 active:scale-95 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
          >
            <SparklesIcon className="h-3.5 w-3.5 text-blue-400 dark:text-blue-600" />
            <span>Subscribe</span>
          </Link>

          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="inline-flex md:hidden h-9 w-9 items-center justify-center rounded-xl border border-zinc-200 text-zinc-600 transition-colors hover:bg-zinc-100 hover:text-zinc-900 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900 dark:hover:text-white"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <XIcon className="h-5 w-5" /> : <MenuIcon className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {mobileMenuOpen && (
        <div className="md:hidden border-b border-zinc-200 bg-white/95 px-4 pt-3 pb-5 backdrop-blur-lg dark:border-zinc-800 dark:bg-zinc-950/95">
          <nav className="flex flex-col gap-1.5">
            {NAV_LINKS.map((link) => {
              const isActive = pathname === link.href;
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-zinc-100 text-zinc-950 font-semibold dark:bg-zinc-800 dark:text-white"
                      : "text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-900 dark:hover:text-white"
                  }`}
                >
                  {link.label}
                </Link>
              );
            })}
            <div className="pt-2 border-t border-zinc-100 dark:border-zinc-800/80 mt-1">
              <Link
                href="/#newsletter"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center justify-center gap-2 rounded-xl bg-zinc-900 px-4 py-2.5 text-xs font-semibold text-white dark:bg-zinc-100 dark:text-zinc-900"
              >
                <SparklesIcon className="h-4 w-4" />
                Subscribe to Newsletter
              </Link>
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
