"use client";

import React, { useState } from "react";
import { SparklesIcon, CheckIcon, SendIcon } from "@/components/Icons";

export function NewsletterBox() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [message, setMessage] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) {
      setStatus("error");
      setMessage("Please enter a valid email address.");
      return;
    }

    setStatus("loading");
    setMessage("");

    try {
      const res = await fetch("/api/newsletter", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data = await res.json();
      if (res.ok) {
        setStatus("success");
        setMessage(data.message || "Thank you for subscribing! Check your inbox soon.");
        setEmail("");
      } else {
        setStatus("error");
        setMessage(data.error || "Unable to subscribe. Please try again.");
      }
    } catch {
      setStatus("error");
      setMessage("Network error. Please try again later.");
    }
  };

  return (
    <section id="newsletter" className="relative overflow-hidden rounded-3xl border border-zinc-200/80 bg-gradient-to-b from-zinc-50 to-white p-8 sm:p-12 dark:border-zinc-800/80 dark:from-zinc-900/50 dark:to-zinc-950/50">
      <div className="relative z-10 mx-auto max-w-2xl text-center">
        <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/20 bg-blue-50/50 px-3 py-1 text-xs font-semibold text-blue-600 dark:border-blue-400/20 dark:bg-blue-950/40 dark:text-blue-400 mb-4">
          <SparklesIcon className="h-3.5 w-3.5" />
          <span>Curated Weekly Digest</span>
        </div>

        <h2 className="text-2xl font-bold tracking-tight text-zinc-900 sm:text-3xl dark:text-zinc-50">
          Stay Ahead of Modern Web Shifts
        </h2>

        <p className="mt-3 text-sm sm:text-base text-zinc-600 dark:text-zinc-400 leading-relaxed">
          Deep dives into Next.js architecture, Tailwind v4 design tokens, edge optimization, and engineering leadership. No spam, ever.
        </p>

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col sm:flex-row gap-2.5 justify-center max-w-md mx-auto">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={status === "loading" || status === "success"}
            placeholder="Enter your email address..."
            className="flex-1 rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm text-zinc-900 shadow-xs placeholder:text-zinc-400 focus:border-blue-500 focus:outline-hidden focus:ring-2 focus:ring-blue-500/20 disabled:opacity-60 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder:text-zinc-500"
            required
          />
          <button
            type="submit"
            disabled={status === "loading" || status === "success"}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white shadow-xs transition-all hover:bg-blue-500 active:scale-95 disabled:opacity-60"
          >
            {status === "loading" ? (
              <span>Subscribing...</span>
            ) : status === "success" ? (
              <span className="flex items-center gap-1.5"><CheckIcon className="h-4 w-4" /> Joined</span>
            ) : (
              <span className="flex items-center gap-1.5">Subscribe <SendIcon className="h-3.5 w-3.5" /></span>
            )}
          </button>
        </form>

        {message && (
          <p
            className={`mt-3 text-xs sm:text-sm font-medium ${
              status === "success" ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"
            }`}
          >
            {message}
          </p>
        )}
      </div>
    </section>
  );
}
