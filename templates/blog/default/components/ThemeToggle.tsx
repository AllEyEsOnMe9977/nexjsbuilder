"use client";

import React, { useEffect, useState } from "react";
import { useTheme } from "@/components/ThemeProvider";
import { SunIcon, MoonIcon } from "@/components/Icons";

export function ThemeToggle({ className = "" }: { className?: string }) {
  const { theme, toggleTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div
        className={`h-9 w-9 rounded-xl border border-zinc-200/80 bg-zinc-100 dark:border-zinc-800/80 dark:bg-zinc-900 ${className}`}
        aria-hidden="true"
      />
    );
  }

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      className={`relative inline-flex h-9 w-9 items-center justify-center rounded-xl border border-zinc-200 bg-white/90 text-zinc-700 shadow-xs backdrop-blur-xs transition-all hover:border-zinc-300 hover:bg-zinc-100 hover:text-zinc-900 active:scale-95 dark:border-zinc-800 dark:bg-zinc-900/90 dark:text-zinc-300 dark:hover:border-zinc-700 dark:hover:bg-zinc-800 dark:hover:text-white ${className}`}
    >
      {theme === "dark" ? (
        <SunIcon className="h-4 w-4 text-amber-400 transition-transform duration-300 rotate-0 hover:rotate-45" />
      ) : (
        <MoonIcon className="h-4 w-4 text-zinc-700 transition-transform duration-300 hover:-rotate-12" />
      )}
    </button>
  );
}
