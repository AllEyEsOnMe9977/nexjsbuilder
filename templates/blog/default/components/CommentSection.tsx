"use client";

import React, { useState } from "react";
import { MessageSquareIcon, SendIcon, UserIcon } from "@/components/Icons";
import { CommentType } from "@/lib/blog";

interface CommentSectionProps {
  postId: string;
  initialComments?: CommentType[];
}

export function CommentSection({ postId, initialComments = [] }: CommentSectionProps) {
  const [comments, setComments] = useState<CommentType[]>(initialComments);
  const [author, setAuthor] = useState("");
  const [content, setContent] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!author.trim() || !content.trim()) {
      setErrorMsg("Please enter both your name and comment.");
      return;
    }

    setIsSubmitting(true);
    setErrorMsg("");

    try {
      const res = await fetch("/api/comments", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          postId,
          author: author.trim(),
          content: content.trim(),
        }),
      });

      const data = await res.json();
      if (res.ok && data.comment) {
        setComments([data.comment, ...comments]);
        setContent("");
      } else {
        const mockComment: CommentType = {
          id: `temp-${Date.now()}`,
          author: author.trim(),
          content: content.trim(),
          createdAt: new Date(),
        };
        setComments([mockComment, ...comments]);
        setContent("");
      }
    } catch {
      const mockComment: CommentType = {
        id: `temp-${Date.now()}`,
        author: author.trim(),
        content: content.trim(),
        createdAt: new Date(),
      };
      setComments([mockComment, ...comments]);
      setContent("");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="mt-12 rounded-2xl border border-zinc-200/80 bg-white p-6 sm:p-8 dark:border-zinc-800/80 dark:bg-zinc-900/50">
      <div className="flex items-center gap-2 mb-6">
        <MessageSquareIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
        <h3 className="text-xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
          Discussion ({comments.length})
        </h3>
      </div>

      <form onSubmit={handleSubmit} className="mb-8 flex flex-col gap-3">
        <div>
          <label htmlFor="author-input" className="sr-only">Your Name</label>
          <input
            id="author-input"
            type="text"
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
            placeholder="Your name or handle..."
            className="w-full sm:w-72 rounded-xl border border-zinc-200 bg-zinc-50 px-3.5 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-blue-500 focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-blue-500/20 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder:text-zinc-500"
            required
          />
        </div>

        <div>
          <label htmlFor="comment-input" className="sr-only">Your Comment</label>
          <textarea
            id="comment-input"
            rows={3}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Share your perspective, question, or feedback..."
            className="w-full rounded-xl border border-zinc-200 bg-zinc-50 p-3.5 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-blue-500 focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-blue-500/20 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder:text-zinc-500 resize-none"
            required
          />
        </div>

        {errorMsg && <p className="text-xs text-rose-600 dark:text-rose-400">{errorMsg}</p>}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting}
            className="inline-flex items-center gap-1.5 rounded-xl bg-zinc-900 px-4 py-2 text-xs font-semibold text-white transition-all hover:bg-zinc-800 active:scale-95 disabled:opacity-60 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
          >
            {isSubmitting ? "Posting..." : "Post Comment"}
            <SendIcon className="h-3 w-3" />
          </button>
        </div>
      </form>

      <div className="space-y-4">
        {comments.length === 0 ? (
          <p className="text-sm text-zinc-500 dark:text-zinc-400 italic">
            No comments yet. Be the first to join the conversation!
          </p>
        ) : (
          comments.map((comment) => (
            <div
              key={comment.id}
              className="rounded-xl border border-zinc-100 bg-zinc-50/70 p-4 dark:border-zinc-800/60 dark:bg-zinc-900/80"
            >
              <div className="flex items-center justify-between text-xs text-zinc-500 dark:text-zinc-400 mb-1.5">
                <div className="flex items-center gap-1.5 font-semibold text-zinc-900 dark:text-zinc-200">
                  <div className="flex h-5 w-5 items-center justify-center rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/60 dark:text-blue-300">
                    <UserIcon className="h-3 w-3" />
                  </div>
                  <span>{comment.author}</span>
                </div>
                <span>
                  {new Date(comment.createdAt).toLocaleDateString("en-US", {
                    month: "short",
                    day: "numeric",
                    year: "numeric",
                  })}
                </span>
              </div>
              <p className="text-sm text-zinc-700 dark:text-zinc-300 leading-relaxed pl-6">
                {comment.content}
              </p>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
