import React from "react";
import Image from "next/image";
import Link from "next/link";
import { BookOpenIcon, CheckIcon, ArrowLeftIcon } from "@/components/Icons";

export const metadata = {
  title: "About The Publication | The Modern Chronicle",
  description: "Learn about the mission, engineering philosophy, and editorial principles behind The Modern Chronicle.",
};

export default function AboutPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-12 lg:px-8">
      <div className="mb-6">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-500 hover:text-zinc-900 transition-colors dark:text-zinc-400 dark:hover:text-white"
        >
          <ArrowLeftIcon className="h-3.5 w-3.5" />
          <span>Back to Articles</span>
        </Link>
      </div>

      <header className="mb-10">
        <h1 className="text-3xl font-extrabold tracking-tight text-zinc-900 sm:text-5xl dark:text-white">
          About The Modern Chronicle
        </h1>
        <p className="mt-3 text-lg text-zinc-600 dark:text-zinc-400">
          An engineering journal dedicated to modern web architecture, pragmatic performance tuning, and thoughtful interface design.
        </p>
      </header>

      <div className="relative aspect-16/8 w-full overflow-hidden rounded-3xl border border-zinc-200/80 bg-zinc-100 dark:border-zinc-800/80 dark:bg-zinc-900 mb-10">
        <Image
          src="/images/post-nextjs-arch.svg"
          alt="Engineering Architecture"
          fill
          priority
          sizes="(max-width: 1024px) 100vw, 896px"
          className="object-cover"
        />
      </div>

      <div className="space-y-8 text-zinc-700 dark:text-zinc-300 leading-relaxed">
        <section className="space-y-3">
          <h2 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
            Editorial Philosophy
          </h2>
          <p>
            The software industry is awash with shallow buzzwords and synthetic boilerplate. The Modern Chronicle was created to cut through the noise with deep, battle-tested explorations of systems engineering and frontend craft.
          </p>
          <p>
            Every guide, benchmark, and essay is constructed from direct production experience: measuring Core Web Vitals at scale, configuring edge runtimes, building accessible design systems, and deploying AI workflows that solve genuine human problems.
          </p>
        </section>

        <section className="rounded-2xl border border-zinc-200/80 bg-white p-6 sm:p-8 dark:border-zinc-800/80 dark:bg-zinc-900/60 space-y-4">
          <h3 className="text-lg font-bold text-zinc-900 dark:text-white">
            Core Standards & Principles
          </h3>
          <ul className="space-y-3 text-sm">
            <li className="flex items-start gap-2.5">
              <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-blue-100 text-blue-600 dark:bg-blue-950 dark:text-blue-400">
                <CheckIcon className="h-3 w-3" />
              </div>
              <span><strong>Sub-100ms TTFB:</strong> We build with streaming React Server Components and edge caching.</span>
            </li>
            <li className="flex items-start gap-2.5">
              <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-blue-100 text-blue-600 dark:bg-blue-950 dark:text-blue-400">
                <CheckIcon className="h-3 w-3" />
              </div>
              <span><strong>Zero AI Slop:</strong> All insights are grounded in tangible technical architectures and verified source patterns.</span>
            </li>
            <li className="flex items-start gap-2.5">
              <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-blue-100 text-blue-600 dark:bg-blue-950 dark:text-blue-400">
                <CheckIcon className="h-3 w-3" />
              </div>
              <span><strong>Accessible By Default:</strong> Full contrast adherence, keyboard navigation, and instant responsive layouts.</span>
            </li>
          </ul>
        </section>
      </div>
    </div>
  );
}
