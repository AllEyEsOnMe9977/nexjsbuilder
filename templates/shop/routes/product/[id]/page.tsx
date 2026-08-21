import { prisma } from "@/lib/db";
import { notFound } from "next/navigation";

export default async function ProductPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const product = await prisma.product.findUnique({ where: { id } });

  if (!product) {
    notFound();
  }

  return (
    <main className="min-h-screen bg-gray-50 py-16">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        <a href="/" className="text-blue-600 hover:underline text-sm">
          &larr; Back to products
        </a>
        <div className="bg-white rounded-lg shadow-md overflow-hidden mt-4">
          <div className="h-64 bg-gray-200" />
          <div className="p-6">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              {product.name}
            </h1>
            <p className="text-gray-600 mb-4">{product.description}</p>
            <div className="flex justify-between items-center">
              <span className="text-2xl font-bold text-gray-900">
                ${product.price.toFixed(2)}
              </span>
              <form action={`/api/cart`} method="post">
                <input type="hidden" name="productId" value={product.id} />
                <button
                  type="submit"
                  className="bg-blue-600 text-white px-6 py-3 rounded hover:bg-blue-700 transition-colors"
                >
                  Add to Cart
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
