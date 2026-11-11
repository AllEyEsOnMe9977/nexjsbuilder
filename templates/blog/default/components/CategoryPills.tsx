"use client";

import React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

interface CategoryPillsProps {
  categories: string[];
}

export function CategoryPills({ categories }: CategoryPillsProps) {
  const searchParams = useSearchParams();
  const activeCategory = searchParams.get("category") || "All";

  return (
    <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none sm:flex-wrap">
      {categories.map((category) => {
        const isActive = activeCategory === category;
        const href = category === "All" ? "/" : `/?category=${encodeURIComponent(category)}`;

        return (
          <Link
            key={category}
            href={href}
            className={`shrink-0 rounded-xl px-3.5 py-1.5 text-xs font-semibold transition-all ${
              isActive
                ? "bg-zinc-900 text-white shadow-xs dark:bg-white dark:text-zinc-900"
                : "border border-zinc-200/90 bg-white text-zinc-600 hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-900 dark:border-zinc-800 dark:bg-zinc-900/60 dark:text-zinc-400 dark:hover:border-zinc-700 dark:hover:bg-zinc-800 dark:hover:text-zinc-200"
            }`}
          >
            {category}
          </Link>
        );
      })}
    </div>
  );
}
