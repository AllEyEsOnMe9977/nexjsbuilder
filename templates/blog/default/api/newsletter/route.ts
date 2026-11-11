import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function POST(req: Request) {
  try {
    const { email } = await req.json();

    if (!email || typeof email !== "string" || !email.includes("@")) {
      return NextResponse.json(
        { error: "A valid email address is required." },
        { status: 400 }
      );
    }

    const cleanEmail = email.toLowerCase().trim();

    await prisma.newsletterSubscriber.upsert({
      where: { email: cleanEmail },
      update: {},
      create: { email: cleanEmail },
    });

    return NextResponse.json({
      message: "Thank you for subscribing to The Modern Chronicle!",
    });
  } catch (error) {
    console.error("Newsletter subscription error:", error);
    return NextResponse.json(
      { error: "Failed to record subscription." },
      { status: 500 }
    );
  }
}
