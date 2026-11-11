import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function POST(req: Request) {
  try {
    const { postId, author, content } = await req.json();

    if (!postId || !author || !content) {
      return NextResponse.json(
        { error: "postId, author, and content are required." },
        { status: 400 }
      );
    }

    const postExists = await prisma.post.findUnique({ where: { id: postId } });

    if (!postExists) {
      return NextResponse.json({
        comment: {
          id: `preview-${Date.now()}`,
          author,
          content,
          createdAt: new Date().toISOString(),
        },
      });
    }

    const comment = await prisma.comment.create({
      data: {
        postId,
        author: author.trim(),
        content: content.trim(),
      },
    });

    return NextResponse.json({ comment }, { status: 201 });
  } catch (error) {
    console.error("Comment submission error:", error);
    return NextResponse.json(
      { error: "Failed to post comment." },
      { status: 500 }
    );
  }
}
