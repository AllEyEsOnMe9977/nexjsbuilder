import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";

// GET /api/cart — list current cart items with product details
export async function GET() {
  try {
    const items = await prisma.cartItem.findMany({
      include: { product: true },
      orderBy: { createdAt: "desc" },
    });
    return NextResponse.json({ items });
  } catch (err) {
    console.error("[cart:GET] failed to load cart", err);
    return NextResponse.json(
      { error: "Failed to load cart" },
      { status: 500 }
    );
  }
}

// POST /api/cart — add a product to the cart
// Accepts either JSON body { productId } or form-encoded (from the <form> on
// the product detail page).
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
      return NextResponse.json(
        { error: "productId is required" },
        { status: 400 }
      );
    }

    const product = await prisma.product.findUnique({
      where: { id: productId },
    });
    if (!product) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    const cartItem = await prisma.cartItem.create({
      data: { productId },
    });

    console.log(`[cart:POST] added product ${productId} to cart`);

    // Form submissions expect a redirect back to a page; JSON callers get JSON.
    if (!contentType.includes("application/json")) {
      return NextResponse.redirect(new URL("/", req.url), { status: 303 });
    }
    return NextResponse.json({ item: cartItem }, { status: 201 });
  } catch (err) {
    console.error("[cart:POST] failed to add item", err);
    return NextResponse.json(
      { error: "Failed to add item to cart" },
      { status: 500 }
    );
  }
}
