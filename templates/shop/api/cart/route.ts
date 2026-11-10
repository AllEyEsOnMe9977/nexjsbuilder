import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function GET() {
  try {
    const items = await prisma.cartItem.findMany({
      include: { product: true },
      orderBy: { createdAt: "desc" },
    });
    return NextResponse.json({ items });
  } catch (err) {
    console.error("[cart:GET] failed to load cart", err);
    return NextResponse.json({ error: "Failed to load cart" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    let productId: string | null = null;
    const contentType = req.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
      const body = await req.json();
      productId = body.productId;
    } else {
      const form = await req.formData();
      productId = form.get("productId")?.toString() ?? null;
    }

    if (!productId) {
      return NextResponse.json({ error: "productId is required" }, { status: 400 });
    }

    const product = await prisma.product.findUnique({ where: { id: productId } });
    if (!product) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    const existing = await prisma.cartItem.findFirst({ where: { productId } });
    const cartItem = existing
      ? await prisma.cartItem.update({
          where: { id: existing.id },
          data: { quantity: { increment: 1 } },
        })
      : await prisma.cartItem.create({
          data: { productId, quantity: 1 },
        });

    if (!contentType.includes("application/json")) {
      const baseUrl = process.env.NEXT_PUBLIC_SITE_URL || req.nextUrl.origin;
      return NextResponse.redirect(new URL("/?added=1", baseUrl), { status: 303 });
    }

    return NextResponse.json({ item: cartItem }, { status: 201 });
  } catch (err) {
    console.error("[cart:POST] failed to add item", err);
    return NextResponse.json({ error: "Failed to add item to cart" }, { status: 500 });
  }
}