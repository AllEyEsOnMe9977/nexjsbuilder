import React from "react";
import Link from "next/link";
import { BookOpenIcon, GithubIcon, TwitterIcon, LinkedinIcon } from "@/components/Icons";

export function Footer() {
  const currentYear = 2026;

  return (
    <footer className="mt-auto border-t border-zinc-200/80 bg-zinc-50/50 transition-colors dark:border-zinc-800/80 dark:bg-zinc-950/50">
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-8 md:grid-cols-4 lg:gap-12">
          <div className="md:col-span-2 flex flex-col gap-3">
            <Link href="/" className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white">
                <BookOpenIcon className="h-4 w-4" />
              </div>
              <span className="text-lg font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
                The Modern Chronicle
              </span>
            </Link>
            <p className="max-w-sm text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed">
              In-depth engineering notes, modern web architecture explorations, and interface design essays. Built with Next.js and Tailwind CSS.
            </p>
            <div className="flex items-center gap-3 pt-2 text-zinc-500 dark:text-zinc-400">
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="GitHub"
                className="rounded-lg p-1.5 transition-colors hover:bg-zinc-200/60 hover:text-zinc-900 dark:hover:bg-zinc-800 dark:hover:text-white"
              >
                <GithubIcon className="h-4 w-4" />
              </a>
              <a
                href="https://twitter.com"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Twitter / X"
                className="rounded-lg p-1.5 transition-colors hover:bg-zinc-200/60 hover:text-zinc-900 dark:hover:bg-zinc-800 dark:hover:text-white"
              >
                <TwitterIcon className="h-4 w-4" />
              </a>
              <a
                href="https://linkedin.com"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="LinkedIn"
                className="rounded-lg p-1.5 transition-colors hover:bg-zinc-200/60 hover:text-zinc-900 dark:hover:bg-zinc-800 dark:hover:text-white"
              >
                <LinkedinIcon className="h-4 w-4" />
              </a>
            </div>
          </div>

          <div className="flex flex-col gap-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-900 dark:text-zinc-100">
              Topics
            </h4>
            <ul className="flex flex-col gap-2 text-sm text-zinc-600 dark:text-zinc-400">
              <li>
                <Link href="/category/Architecture" className="transition-colors hover:text-zinc-900 dark:hover:text-white">
                  Architecture & Systems
                </Link>
              </li>
              <li>
                <Link href="/category/Design" className="transition-colors hover:text-zinc-900 dark:hover:text-white">
                  Design Systems & UI
                </Link>
              </li>
              <li>
                <Link href="/category/AI%20&%20Systems" className="transition-colors hover:text-zinc-900 dark:hover:text-white">
                  Generative Interfaces
                </Link>
              </li>
              <li>
                <Link href="/category/Performance" className="transition-colors hover:text-zinc-900 dark:hover:text-white">
                  Performance & Turbopack
                </Link>
              </li>
            </ul>
          </div>

          <div className="flex flex-col gap-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-900 dark:text-zinc-100">
              Publication
            </h4>
            <ul className="flex flex-col gap-2 text-sm text-zinc-600 dark:text-zinc-400">
              <li>
                <Link href="/about" className="transition-colors hover:text-zinc-900 dark:hover:text-white">
                  About Editorial
                </Link>
              </li>
              <li>
                <Link href="/#newsletter" className="transition-colors hover:text-zinc-900 dark:hover:text-white">
                  Newsletter Archive
                </Link>
              </li>
              <li>
                <Link href="/api/seed" className="transition-colors hover:text-zinc-900 dark:hover:text-white text-xs text-blue-600 dark:text-blue-400 font-medium">
                  Initialize Demo Data
                </Link>
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-12 flex flex-col items-center justify-between gap-4 border-t border-zinc-200/80 pt-8 sm:flex-row dark:border-zinc-800/80 text-xs text-zinc-500 dark:text-zinc-400">
          <p>© {currentYear} The Modern Chronicle. All rights reserved.</p>
          <div className="flex items-center gap-4">
            <span>Built with Next.js & Tailwind CSS</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
