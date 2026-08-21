import { prisma } from "@/lib/db";
import { ProductCard } from "@/components/ProductCard";

// Server component: fetch products at request time. Revalidate frequently
// since this is a demo/test template, not a production caching strategy.
export const revalidate = 0;

export default async function Home() {
  const products = await prisma.product.findMany({
    orderBy: { createdAt: "desc" },
  });

  return (
    <main className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <h1 className="text-2xl font-bold text-gray-900">Shop</h1>
            <nav className="flex gap-6">
              <a href="/" className="text-gray-600 hover:text-gray-900">Products</a>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="bg-gradient-to-r from-blue-600 to-indigo-700 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-5xl font-bold mb-4">Welcome to Our Store</h2>
          <p className="text-xl mb-8">Discover amazing products at great prices</p>
        </div>
      </section>

      {/* Products Grid */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <h3 className="text-3xl font-bold text-gray-900 mb-8">Featured Products</h3>

        {products.length === 0 ? (
          <p className="text-gray-500">
            No products yet — insert rows into the Product table to see them here.
          </p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6">
            {products.map((product) => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        )}
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-8 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <p>&copy; 2026 Shop. All rights reserved.</p>
        </div>
      </footer>
    </main>
  );
}
