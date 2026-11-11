"use client";

import React, { useState, useTransition } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { SearchIcon, XIcon } from "@/components/Icons";

export function SearchBar() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const currentSearch = searchParams.get("search") || "";
  const [searchTerm, setSearchTerm] = useState(currentSearch);
  const [isPending, startTransition] = useTransition();

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const params = new URLSearchParams(searchParams.toString());
    if (searchTerm.trim()) {
      params.set("search", searchTerm.trim());
    } else {
      params.delete("search");
    }
    startTransition(() => {
      router.push(`/?${params.toString()}`);
    });
  };

  const handleClear = () => {
    setSearchTerm("");
    const params = new URLSearchParams(searchParams.toString());
    params.delete("search");
    startTransition(() => {
      router.push(`/?${params.toString()}`);
    });
  };

  return (
    <form onSubmit={handleSearch} className="relative w-full max-w-md">
      <div className="relative flex items-center">
        <SearchIcon className="pointer-events-none absolute left-3.5 h-4 w-4 text-zinc-400" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search articles, keywords, topics..."
          className="w-full rounded-2xl border border-zinc-200/90 bg-white/80 py-2.5 pl-10 pr-10 text-sm text-zinc-900 shadow-xs backdrop-blur-xs transition-all placeholder:text-zinc-400 focus:border-blue-500 focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-blue-500/20 dark:border-zinc-800 dark:bg-zinc-900/80 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-blue-500 dark:focus:bg-zinc-900"
        />
        {searchTerm && (
          <button
            type="button"
            onClick={handleClear}
            className="absolute right-3 rounded-full p-1 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
            aria-label="Clear search"
          >
            <XIcon className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      {isPending && (
        <span className="absolute right-10 top-3 text-[10px] text-zinc-400 animate-pulse">
          Filtering...
        </span>
      )}
    </form>
  );
}
