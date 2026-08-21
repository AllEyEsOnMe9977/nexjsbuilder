import Link from "next/link";
import { ShoppingCart } from "lucide-react";

// Minimal shape used by the card — matches the Prisma Product model fields
// that the homepage and product API actually select.
export type ProductCardData = {
  id: string;
  name: string;
  description: string | null;
  price: number;
};

export function ProductCard({ product }: { product: ProductCardData }) {
  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden hover:shadow-lg transition-shadow">
      <Link href={`/product/${product.id}`}>
        <div className="h-48 bg-gray-200" />
        <div className="p-4">
          <h4 className="font-semibold text-gray-900 mb-1">{product.name}</h4>
          <p className="text-gray-600 text-sm mb-4 line-clamp-2">
            {product.description}
          </p>
          <div className="flex justify-between items-center">
            <span className="text-lg font-bold text-gray-900">
              ${product.price.toFixed(2)}
            </span>
            <span className="flex items-center gap-1 text-blue-600 text-sm font-medium">
              <ShoppingCart size={16} />
              View
            </span>
          </div>
        </div>
      </Link>
    </div>
  );
}
