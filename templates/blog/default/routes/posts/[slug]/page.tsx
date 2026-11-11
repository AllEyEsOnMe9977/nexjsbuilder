import React from "react";
import Image from "next/image";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getPostBySlug, getPosts } from "@/lib/blog";
import { CalendarIcon, ClockIcon, ArrowLeftIcon, TagIcon } from "@/components/Icons";
import { ReadingProgressBar } from "@/components/ReadingProgressBar";
import { CommentSection } from "@/components/CommentSection";
import { PostCard } from "@/components/PostCard";

export const dynamic = "force-dynamic";

interface PostPageProps {
  params: Promise<{ slug: string }>;
}

export default async function PostPage({ params }: PostPageProps) {
  const { slug } = await params;
  const post = await getPostBySlug(slug);

  if (!post) {
    notFound();
  }

  const allPosts = await getPosts();
  const relatedPosts = allPosts
    .filter((p) => p.slug !== post.slug && (p.category === post.category || p.tags.includes(post.category)))
    .slice(0, 3);

  const formattedDate = new Date(post.publishedAt).toLocaleDateString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  });

  const tagList = post.tags
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  return (
    <article className="min-h-screen">
      <ReadingProgressBar />

      <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-12 lg:px-8">
        {/* Back Link */}
        <div className="mb-6">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-500 hover:text-zinc-900 transition-colors dark:text-zinc-400 dark:hover:text-white"
          >
            <ArrowLeftIcon className="h-3.5 w-3.5" />
            <span>Back to all articles</span>
          </Link>
        </div>

        {/* Header Meta */}
        <header className="flex flex-col gap-4">
          <div className="flex items-center gap-3 text-xs font-medium text-zinc-500 dark:text-zinc-400">
            <Link
              href={`/category/${encodeURIComponent(post.category)}`}
              className="rounded-md bg-blue-50 px-2.5 py-1 font-semibold text-blue-700 hover:bg-blue-100 transition-colors dark:bg-blue-950/60 dark:text-blue-300 dark:hover:bg-blue-900/60"
            >
              {post.category}
            </Link>
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

          <h1 className="text-3xl font-extrabold tracking-tight text-zinc-900 sm:text-5xl dark:text-white leading-tight">
            {post.title}
          </h1>

          <p className="text-lg text-zinc-600 dark:text-zinc-300 leading-relaxed font-normal">
            {post.excerpt}
          </p>

          {/* Author Badge */}
          <div className="flex items-center gap-3 border-y border-zinc-200/80 py-4 dark:border-zinc-800/80 my-2">
            <div className="relative h-11 w-11 overflow-hidden rounded-full ring-2 ring-zinc-200 dark:ring-zinc-800">
              <Image
                src={post.authorAvatar || "/images/author-avatar.svg"}
                alt={post.authorName}
                fill
                sizes="44px"
                className="object-cover"
              />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                {post.authorName}
              </span>
              <span className="text-xs text-zinc-500 dark:text-zinc-400">
                {post.authorRole}
              </span>
            </div>
          </div>
        </header>

        {/* Cover Image */}
        <div className="relative my-8 aspect-16/9 w-full overflow-hidden rounded-3xl border border-zinc-200/80 bg-zinc-100 dark:border-zinc-800/80 dark:bg-zinc-900">
          <Image
            src={post.coverImage || "/images/post-nextjs-arch.svg"}
            alt={post.title}
            fill
            priority
            sizes="(max-width: 1024px) 100vw, 896px"
            className="object-cover"
          />
        </div>

        {/* Article Body */}
        <div className="prose prose-zinc dark:prose-invert max-w-none text-zinc-800 dark:text-zinc-200 leading-relaxed space-y-6">
          {post.content.split(/\n\s*\n/).map((block, idx) => {
            const trimmed = block.trim();
            if (!trimmed) return null;

            if (trimmed.startsWith("### ")) {
              return (
                <h3 key={idx} className="text-xl font-bold tracking-tight text-zinc-900 dark:text-white mt-8 mb-3">
                  {trimmed.replace("### ", "")}
                </h3>
              );
            }

            if (trimmed.startsWith("```")) {
              const codeLines = trimmed.split(/\r?\n/).filter((l) => !l.startsWith("```"));
              return (
                <pre
                  key={idx}
                  className="overflow-x-auto rounded-2xl border border-zinc-800 bg-zinc-950 p-4 text-xs font-mono text-zinc-200 shadow-inner"
                >
                  <code>{codeLines.join("\n")}</code>
                </pre>
              );
            }

            if (trimmed.startsWith("- ")) {
              const items = trimmed.split(/\r?\n/).map((line) => line.replace(/^-\s*/, ""));
              return (
                <ul key={idx} className="list-disc list-inside space-y-1.5 pl-2 text-zinc-700 dark:text-zinc-300">
                  {items.map((item, itemIdx) => (
                    <li key={itemIdx}>{item}</li>
                  ))}
                </ul>
              );
            }

            return (
              <p key={idx} className="text-base text-zinc-700 dark:text-zinc-300 leading-relaxed">
                {trimmed}
              </p>
            );
          })}
        </div>

        {/* Tags */}
        {tagList.length > 0 && (
          <div className="mt-10 flex flex-wrap items-center gap-2 border-t border-zinc-200/80 pt-6 dark:border-zinc-800/80">
            <span className="flex items-center gap-1 text-xs font-semibold text-zinc-500 dark:text-zinc-400 mr-1">
              <TagIcon className="h-3.5 w-3.5" />
              Tags:
            </span>
            {tagList.map((tag) => (
              <span
                key={tag}
                className="rounded-lg border border-zinc-200 bg-white px-2.5 py-1 text-xs font-medium text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300"
              >
                #{tag}
              </span>
            ))}
          </div>
        )}

        {/* Discussion */}
        <CommentSection postId={post.id} initialComments={post.comments} />

        {/* Related Posts */}
        {relatedPosts.length > 0 && (
          <div className="mt-16 border-t border-zinc-200/80 pt-10 dark:border-zinc-800/80">
            <h3 className="text-xl font-bold tracking-tight text-zinc-900 dark:text-white mb-6">
              More Stories You Might Enjoy
            </h3>
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {relatedPosts.map((related) => (
                <PostCard key={related.id} post={related} />
              ))}
            </div>
          </div>
        )}
      </div>
    </article>
  );
}
