import React from "react";
import Link from "next/link";
import { getPosts, getCategories } from "@/lib/blog";
import { PostCard } from "@/components/PostCard";
import { ArrowLeftIcon } from "@/components/Icons";

export const dynamic = "force-dynamic";

interface CategoryPageProps {
  params: Promise<{ category: string }>;
}

export default async function CategoryPage({ params }: CategoryPageProps) {
  const { category } = await params;
  const decodedCategory = decodeURIComponent(category);
  const [posts, categories] = await Promise.all([
    getPosts({ category: decodedCategory }),
    getCategories(),
  ]);

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 sm:py-12 lg:px-8">
      <div className="mb-6">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-500 hover:text-zinc-900 transition-colors dark:text-zinc-400 dark:hover:text-white"
        >
          <ArrowLeftIcon className="h-3.5 w-3.5" />
          <span>All Articles</span>
        </Link>
      </div>

      <header className="mb-8 border-b border-zinc-200/80 pb-6 dark:border-zinc-800/80">
        <h1 className="text-3xl font-extrabold tracking-tight text-zinc-900 sm:text-4xl dark:text-white">
          Category: {decodedCategory}
        </h1>
        <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
          Showing {posts.length} {posts.length === 1 ? "article" : "articles"} filed under {decodedCategory}.
        </p>

        <div className="mt-4 flex flex-wrap gap-2">
          {categories.map((cat) => (
            <Link
              key={cat}
              href={cat === "All" ? "/" : `/category/${encodeURIComponent(cat)}`}
              className={`rounded-xl px-3 py-1 text-xs font-semibold transition-colors ${
                cat.toLowerCase() === decodedCategory.toLowerCase()
                  ? "bg-zinc-900 text-white dark:bg-white dark:text-zinc-900"
                  : "border border-zinc-200 bg-white text-zinc-600 hover:bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800"
              }`}
            >
              {cat}
            </Link>
          ))}
        </div>
      </header>

      {posts.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-zinc-300 p-12 text-center dark:border-zinc-800">
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            No articles found in this category.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {posts.map((post) => (
            <PostCard key={post.id} post={post} />
          ))}
        </div>
      )}
    </div>
  );
}
