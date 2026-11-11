import React, { Suspense } from "react";
import Link from "next/link";
import { getPosts, getCategories, BlogPost } from "@/lib/blog";
import { PostCard } from "@/components/PostCard";
import { CategoryPills } from "@/components/CategoryPills";
import { SearchBar } from "@/components/SearchBar";
import { NewsletterBox } from "@/components/NewsletterBox";
import { SparklesIcon, BookOpenIcon } from "@/components/Icons";

export const dynamic = "force-dynamic";

interface HomePageProps {
  searchParams?: Promise<{ search?: string; category?: string }>;
}

export default async function HomePage({ searchParams }: HomePageProps) {
  const resolvedParams = searchParams ? await searchParams : {};
  const currentCategory = resolvedParams.category || "All";
  const currentSearch = resolvedParams.search || "";

  const [posts, categories] = await Promise.all([
    getPosts({ category: currentCategory, search: currentSearch }),
    getCategories(),
  ]);

  const featuredPost: BlogPost | undefined =
    currentCategory === "All" && !currentSearch
      ? posts.find((p) => p.featured) || posts[0]
      : undefined;

  const standardPosts = featuredPost
    ? posts.filter((p) => p.id !== featuredPost.id)
    : posts;

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 sm:py-12 lg:px-8">
      {/* Hero Welcome Header */}
      <section className="mb-10 sm:mb-12">
        <div className="flex flex-col gap-4 text-center sm:text-left">
          <div className="inline-flex items-center gap-2 self-center sm:self-start rounded-full border border-blue-500/20 bg-blue-50/60 px-3.5 py-1 text-xs font-semibold text-blue-600 dark:border-blue-400/20 dark:bg-blue-950/40 dark:text-blue-400">
            <SparklesIcon className="h-3.5 w-3.5" />
            <span>Modern Engineering & Design Notes</span>
          </div>
          <h1 className="text-3xl font-black tracking-tight text-zinc-900 sm:text-5xl dark:text-white">
            Thoughts, Architecture & Digital Craft
          </h1>
          <p className="max-w-2xl text-base text-zinc-600 sm:text-lg dark:text-zinc-400">
            A high-performance publication exploring the modern web, distributed systems, Tailwind CSS styling engines, and aesthetic developer experiences.
          </p>
        </div>
      </section>

      {/* Featured Story */}
      {featuredPost && (
        <section className="mb-12">
          <PostCard post={featuredPost} featured={true} />
        </section>
      )}

      {/* Filter and Search Bar */}
      <section className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-zinc-200/80 pb-6 dark:border-zinc-800/80">
        <Suspense fallback={<div className="h-8 w-48 animate-pulse rounded-lg bg-zinc-200 dark:bg-zinc-800" />}>
          <CategoryPills categories={categories} />
        </Suspense>

        <Suspense fallback={<div className="h-10 w-full sm:w-64 animate-pulse rounded-xl bg-zinc-200 dark:bg-zinc-800" />}>
          <SearchBar />
        </Suspense>
      </section>

      {/* Post Grid or Zero State */}
      <section className="mb-16">
        {posts.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-3xl border border-dashed border-zinc-300 p-12 text-center dark:border-zinc-800">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-zinc-100 text-zinc-400 dark:bg-zinc-900 dark:text-zinc-500 mb-4">
              <BookOpenIcon className="h-6 w-6" />
            </div>
            <h3 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">
              No matching articles found
            </h3>
            <p className="mt-1 max-w-sm text-sm text-zinc-500 dark:text-zinc-400">
              {currentSearch
                ? `No articles matched "${currentSearch}". Try another keyword or browse all categories.`
                : "No posts published yet in this category. You can initialize demo data below."}
            </p>
            <div className="mt-5 flex items-center gap-3">
              {currentSearch && (
                <Link
                  href="/"
                  className="rounded-xl border border-zinc-200 bg-white px-4 py-2 text-xs font-semibold text-zinc-700 hover:bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300"
                >
                  Clear Search
                </Link>
              )}
              <Link
                href="/api/seed"
                className="rounded-xl bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500"
              >
                Seed Starter Articles
              </Link>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {standardPosts.map((post) => (
              <PostCard key={post.id} post={post} />
            ))}
          </div>
        )}
      </section>

      {/* Newsletter Signup */}
      <NewsletterBox />
    </div>
  );
}
