import React from "react";
import Link from "next/link";
import Image from "next/image";
import { BlogPost } from "@/lib/blog";
import { CalendarIcon, ClockIcon, ArrowRightIcon } from "@/components/Icons";

interface PostCardProps {
  post: BlogPost;
  featured?: boolean;
}

export function PostCard({ post, featured = false }: PostCardProps) {
  const formattedDate = new Date(post.publishedAt).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });

  if (featured) {
    return (
      <article className="group relative overflow-hidden rounded-3xl border border-zinc-200/80 bg-white shadow-xs transition-all duration-300 hover:border-zinc-300 hover:shadow-xl dark:border-zinc-800/80 dark:bg-zinc-900/60 dark:hover:border-zinc-700">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-0">
          <div className="relative aspect-16/10 lg:aspect-auto lg:col-span-7 overflow-hidden bg-zinc-100 dark:bg-zinc-800/50">
            <Image
              src={post.coverImage || "/images/post-nextjs-arch.svg"}
              alt={post.title}
              fill
              sizes="(max-width: 1024px) 100vw, 60vw"
              priority
              className="object-cover object-center transition-transform duration-500 ease-out group-hover:scale-105"
            />
            <div className="absolute top-4 left-4 z-10">
              <span className="inline-flex items-center rounded-full bg-blue-600/90 px-3 py-1 text-xs font-semibold text-white shadow-xs backdrop-blur-xs">
                Featured Story
              </span>
            </div>
          </div>

          <div className="flex flex-col justify-between p-6 sm:p-8 lg:col-span-5 lg:p-10">
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-3 text-xs font-medium text-zinc-500 dark:text-zinc-400">
                <span className="rounded-md bg-zinc-100 px-2.5 py-1 font-semibold text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200">
                  {post.category}
                </span>
                <span className="flex items-center gap-1">
                  <ClockIcon className="h-3.5 w-3.5" />
                  {post.readTime}
                </span>
              </div>

              <h2 className="text-2xl font-bold tracking-tight text-zinc-900 transition-colors group-hover:text-blue-600 dark:text-zinc-50 dark:group-hover:text-blue-400 sm:text-3xl">
                <Link href={`/posts/${post.slug}`}>
                  <span className="absolute inset-0" aria-hidden="true" />
                  {post.title}
                </Link>
              </h2>

              <p className="line-clamp-3 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400 sm:text-base">
                {post.excerpt}
              </p>
            </div>

            <div className="mt-6 flex items-center justify-between border-t border-zinc-100 pt-5 dark:border-zinc-800/80">
              <div className="flex items-center gap-2.5">
                <div className="relative h-9 w-9 overflow-hidden rounded-full ring-2 ring-zinc-100 dark:ring-zinc-800">
                  <Image
                    src={post.authorAvatar || "/images/author-avatar.svg"}
                    alt={post.authorName}
                    fill
                    sizes="36px"
                    className="object-cover"
                  />
                </div>
                <div className="flex flex-col">
                  <span className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                    {post.authorName}
                  </span>
                  <span className="text-[11px] text-zinc-500 dark:text-zinc-400">
                    {formattedDate}
                  </span>
                </div>
              </div>

              <span className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 transition-transform group-hover:translate-x-1 dark:text-blue-400">
                Read story <ArrowRightIcon className="h-3.5 w-3.5" />
              </span>
            </div>
          </div>
        </div>
      </article>
    );
  }

  return (
    <article className="group relative flex flex-col overflow-hidden rounded-2xl border border-zinc-200/80 bg-white shadow-xs transition-all duration-300 hover:-translate-y-1 hover:border-zinc-300 hover:shadow-lg dark:border-zinc-800/80 dark:bg-zinc-900/60 dark:hover:border-zinc-700">
      <div className="relative aspect-16/10 w-full overflow-hidden bg-zinc-100 dark:bg-zinc-800/50">
        <Image
          src={post.coverImage || "/images/post-nextjs-arch.svg"}
          alt={post.title}
          fill
          sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
          className="object-cover object-center transition-transform duration-500 ease-out group-hover:scale-105"
        />
        <div className="absolute top-3 left-3 z-10">
          <span className="inline-flex items-center rounded-lg bg-black/60 px-2.5 py-1 text-[11px] font-semibold text-white backdrop-blur-xs">
            {post.category}
          </span>
        </div>
      </div>

      <div className="flex flex-1 flex-col justify-between p-5 sm:p-6">
        <div className="flex flex-col gap-2.5">
          <div className="flex items-center gap-3 text-xs text-zinc-500 dark:text-zinc-400">
            <span className="flex items-center gap-1">
              <CalendarIcon className="h-3.5 w-3.5" />
              {formattedDate}
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <ClockIcon className="h-3.5 w-3.5" />
              {post.readTime}
            </span>
          </div>

          <h3 className="text-lg font-bold tracking-tight text-zinc-900 transition-colors group-hover:text-blue-600 dark:text-zinc-100 dark:group-hover:text-blue-400 sm:text-xl line-clamp-2">
            <Link href={`/posts/${post.slug}`}>
              <span className="absolute inset-0" aria-hidden="true" />
              {post.title}
            </Link>
          </h3>

          <p className="line-clamp-2 text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed">
            {post.excerpt}
          </p>
        </div>

        <div className="mt-5 flex items-center justify-between border-t border-zinc-100 pt-4 dark:border-zinc-800/80">
          <div className="flex items-center gap-2">
            <div className="relative h-7 w-7 overflow-hidden rounded-full ring-1 ring-zinc-200 dark:ring-zinc-700">
              <Image
                src={post.authorAvatar || "/images/author-avatar.svg"}
                alt={post.authorName}
                fill
                sizes="28px"
                className="object-cover"
              />
            </div>
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">
              {post.authorName}
            </span>
          </div>

          <span className="inline-flex items-center gap-1 text-xs font-semibold text-zinc-600 group-hover:text-blue-600 dark:text-zinc-400 dark:group-hover:text-blue-400 transition-colors">
            Read <ArrowRightIcon className="h-3 w-3 transition-transform group-hover:translate-x-0.5" />
          </span>
        </div>
      </div>
    </article>
  );
}
