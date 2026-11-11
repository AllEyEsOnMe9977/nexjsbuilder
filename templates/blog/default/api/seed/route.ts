import { NextResponse } from "next/server";
import { seedInitialPosts } from "@/lib/blog";

export async function GET() {
  try {
    const count = await seedInitialPosts();
    return NextResponse.json({
      success: true,
      message: `Database successfully seeded with ${count} articles.`,
    });
  } catch (error) {
    console.error("Seeding error:", error);
    return NextResponse.json(
      { error: "Failed to seed demo database." },
      { status: 500 }
    );
  }
}

export async function POST() {
  return GET();
}
