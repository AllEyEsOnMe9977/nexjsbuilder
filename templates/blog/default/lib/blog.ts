import { prisma } from "@/lib/db";

export interface CommentType {
  id: string;
  postId?: string;
  author: string;
  content: string;
  createdAt: Date | string;
}

export interface BlogPost {
  id: string;
  slug: string;
  title: string;
  excerpt: string;
  content: string;
  coverImage: string;
  category: string;
  tags: string;
  readTime: string;
  featured: boolean;
  published: boolean;
  authorName: string;
  authorRole: string;
  authorAvatar: string;
  publishedAt: Date | string;
  createdAt?: Date | string;
  updatedAt?: Date | string;
  comments?: CommentType[];
}

export const SAMPLE_POSTS: BlogPost[] = [
  {
    id: "sample-1",
    slug: "modern-web-architecture-edge-runtimes",
    title: "The Architecture of Modern Web Applications: From Monoliths to Edge Runtimes",
    excerpt: "How server components, distributed caching layers, and instant edge hydration redefine resilience and perceived speed across modern web stacks.",
    category: "Architecture",
    tags: "Next.js, Edge, System Design, RSC",
    readTime: "6 min read",
    featured: true,
    published: true,
    authorName: "Krisna Jane",
    authorRole: "Lead Systems Architect",
    authorAvatar: "/images/author-avatar.svg",
    publishedAt: new Date("2026-03-15T09:00:00Z"),
    coverImage: "/images/post-nextjs-arch.svg",
    content: `Modern web architecture has reached an inflection point. For the past decade, developer mindshare oscillated between heavy single-page application (SPA) client bundles and rigid server-rendered traditional monoliths. Today, a unified paradigm has emerged: unified server-client primitives powered by React Server Components (RSC) and edge distribution.

### The Problem with Traditional Bundles

When applications ship hundreds of kilobytes of client-side JavaScript, mobile devices and slow connections bear the brunt:
- Prolonged Time-to-Interactive (TTI) due to main-thread parsing locks.
- Cascading waterfall requests for nested data queries.
- Ballooning bundle sizes as internal utility libraries proliferate.

Server Components turn this problem inside out. By keeping heavy parsing engines, database connectors, and markdown formatters on the server, the browser receives zero unnecessary JavaScript for static view layers.

### Moving Execution to the Edge

Locating compute physically closer to users eliminates round-trip latency to centralized origins. When paired with streaming HTML rendering:

1. **Initial paint occurs in sub-50 milliseconds**, transmitting critical document heads and structural layout skeletons.
2. **Server components stream dynamic slices** as asynchronous database operations resolve.
3. **Client hydration is surgical**, binding event listeners exclusively to interactive buttons, toggles, and modals.

\`\`\`typescript
// Server Component streaming example
export default async function FeedSection() {
  const feed = await fetchEdgeFeed();
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      {feed.map((item) => (
        <FeedCard key={item.id} data={item} />
      ))}
    </div>
  );
}
\`\`\`

### Architectural Principles for 2026

To build resilient platforms that survive traffic surges and flaky network conditions:

- **Decouple Data Retrieval from UI Hydration**: Treat database queries as server-only operations. Never expose connection strings or query builders to client trees.
- **Adopt Granular Cache Tags**: Leverage on-demand revalidation to keep content instantly fresh without serving stale renders.
- **Respect Device Constraints**: Never download libraries the browser does not actively require. Let static HTML carry the weight.`,
    comments: [
      {
        id: "c-1",
        author: "Devon Vance",
        content: "The breakdown of streaming server components vs client hydration is spot on. Sub-50ms TTFB has transformed our mobile metrics.",
        createdAt: new Date("2026-03-16T14:30:00Z"),
      },
    ],
  },
  {
    id: "sample-2",
    slug: "rethinking-design-systems-tailwind-v4",
    title: "Rethinking Design Systems with Tailwind CSS v4 and Modern Tokens",
    excerpt: "Exploring the speed and elegance of CSS-first configurations, cascade layer ergonomics, and lightning-fast Turbopack styling pipelines.",
    category: "Design",
    tags: "Tailwind CSS, UI/UX, Design Tokens",
    readTime: "5 min read",
    featured: false,
    published: true,
    authorName: "Marcus Sterling",
    authorRole: "Principal UI Engineer",
    authorAvatar: "/images/author-avatar.svg",
    publishedAt: new Date("2026-03-10T11:30:00Z"),
    coverImage: "/images/post-tailwind-v4.svg",
    content: `Design systems have historically suffered from configuration fatigue. Developers juggled sprawling JavaScript configuration files, custom PostCSS plugins, and rigid preprocessors just to establish consistent color palettes and spacing scales.

With Tailwind CSS v4, the paradigm shifts entirely back into standard CSS. By embracing modern CSS specifications—such as @theme, @custom-variant, and native cascade layers—styling becomes faster to compile, simpler to parse, and effortless to maintain.

### The Power of CSS-First Design Tokens

Instead of compiling JavaScript objects into utility strings, Tailwind v4 treats standard CSS custom properties as first-class citizens:

\`\`\`css
@import "tailwindcss";

@theme inline {
  --color-primary: #09090b;
  --color-accent: #2563eb;
  --font-brand: "Geist", -apple-system, sans-serif;
}
\`\`\`

This eliminates context-switching between CSS files and JS config files. What you define in your stylesheets is immediately reflected in autocomplete and Turbopack hot reloads.`,
    comments: [],
  },
  {
    id: "sample-3",
    slug: "crafting-intuitive-generative-ai-interfaces",
    title: "Crafting Intuitive Interfaces for Conversational and Generative AI",
    excerpt: "Moving beyond chat bubbles: Designing spatial canvases, contextual sidebars, and real-time streaming feedback loops.",
    category: "AI & Systems",
    tags: "AI, Interaction Design, Streaming UI",
    readTime: "7 min read",
    featured: false,
    published: true,
    authorName: "Aria Thorne",
    authorRole: "Head of Product Design",
    authorAvatar: "/images/author-avatar.svg",
    publishedAt: new Date("2026-03-05T16:45:00Z"),
    coverImage: "/images/post-ai-interfaces.svg",
    content: `When AI assistants first entered the mainstream, the universal interface was a single text prompt and a vertical message history. While chat is great for quick Q&A, it falls short for iterative creation, code generation, and complex document authoring.

Today's highest-leverage AI products treat machine intelligence as a co-creator rather than a chatbot.

### Beyond the Chat Stream: The Canvas Model

To build software people genuinely love using:
1. **Side-by-Side Artifact Viewers**: Give generated code, markdown documents, and graphics their own persistent canvas alongside the conversation.
2. **Context-Aware In-Line Actions**: Allow users to highlight a specific paragraph or line and instruct the model directly without having to copy-paste.
3. **Predictive Diff Visualizations**: Clearly illustrate what was inserted, revised, or removed using clean syntax-highlighted diffs.`,
    comments: [],
  },
  {
    id: "sample-4",
    slug: "zero-latency-engineering-turbopack-edge-caching",
    title: "Zero-Latency Engineering: Profiling Turbopack and Edge Caching",
    excerpt: "A deep dive into sub-second page loads, stale-while-revalidate caching semantics, and asset optimization pipelines.",
    category: "Performance",
    tags: "Performance, Turbopack, Core Web Vitals",
    readTime: "4 min read",
    featured: false,
    published: true,
    authorName: "Krisna Jane",
    authorRole: "Lead Systems Architect",
    authorAvatar: "/images/author-avatar.svg",
    publishedAt: new Date("2026-02-28T10:15:00Z"),
    coverImage: "/images/post-edge-perf.svg",
    content: `Speed is not merely a technical benchmark; it is a fundamental user interface feature. Studies continually prove that even a 100ms decrease in latency produces a measurable uptick in user engagement, retention, and comprehension.

### Next.js Turbopack: Compilation at the Speed of Rust

Turbopack redefines the local developer and production compilation cycles:
- **Incremental Computation**: Files that have not changed are never re-evaluated.
- **Function-Level Cache Memory**: Memory footprint remains flat even in massive monorepos.
- **Instant Hot Module Replacement (HMR)**: Changes are reflected in milliseconds.`,
    comments: [],
  },
];

function filterSamplePosts(posts: BlogPost[], params?: { search?: string; category?: string }): BlogPost[] {
  let result = [...posts];

  if (params?.category && params.category !== "All") {
    result = result.filter(
      (p) => p.category.toLowerCase() === params.category?.toLowerCase()
    );
  }

  if (params?.search && params.search.trim() !== "") {
    const q = params.search.toLowerCase().trim();
    result = result.filter(
      (p) =>
        p.title.toLowerCase().includes(q) ||
        p.excerpt.toLowerCase().includes(q) ||
        p.tags.toLowerCase().includes(q) ||
        p.category.toLowerCase().includes(q)
    );
  }

  return result;
}

export async function getPosts(params?: { search?: string; category?: string }): Promise<BlogPost[]> {
  try {
    const where: Record<string, unknown> = { published: true };

    if (params?.category && params.category !== "All") {
      where.category = params.category;
    }

    if (params?.search && params.search.trim() !== "") {
      const q = params.search.trim();
      where.OR = [
        { title: { contains: q } },
        { excerpt: { contains: q } },
        { tags: { contains: q } },
      ];
    }

    const dbPosts = await prisma.post.findMany({
      where,
      orderBy: { publishedAt: "desc" },
      include: {
        comments: {
          orderBy: { createdAt: "desc" },
        },
      },
    });

    if (dbPosts.length > 0) {
      return dbPosts as unknown as BlogPost[];
    }

    const totalCount = await prisma.post.count().catch(() => 0);
    if (totalCount === 0) {
      return filterSamplePosts(SAMPLE_POSTS, params);
    }

    return [];
  } catch {
    return filterSamplePosts(SAMPLE_POSTS, params);
  }
}

export async function getPostBySlug(slug: string): Promise<BlogPost | null> {
  try {
    const dbPost = await prisma.post.findUnique({
      where: { slug },
      include: {
        comments: {
          orderBy: { createdAt: "desc" },
        },
      },
    });

    if (dbPost) {
      return dbPost as unknown as BlogPost;
    }

    const sample = SAMPLE_POSTS.find((p) => p.slug === slug);
    return sample || null;
  } catch {
    const sample = SAMPLE_POSTS.find((p) => p.slug === slug);
    return sample || null;
  }
}

export async function getCategories(): Promise<string[]> {
  const defaults = ["All", "Architecture", "Design", "AI & Systems", "Performance"];
  try {
    const rows = await prisma.post.findMany({
      where: { published: true },
      select: { category: true },
      distinct: ["category"],
    });

    if (rows && rows.length > 0) {
      return Array.from(new Set(["All", ...rows.map((r) => r.category)]));
    }
  } catch {}
  return defaults;
}

export async function seedInitialPosts(): Promise<number> {
  let createdCount = 0;
  for (const item of SAMPLE_POSTS) {
    const existing = await prisma.post.findUnique({ where: { slug: item.slug } });
    if (!existing) {
      await prisma.post.create({
        data: {
          slug: item.slug,
          title: item.title,
          excerpt: item.excerpt,
          content: item.content,
          coverImage: item.coverImage,
          category: item.category,
          tags: item.tags,
          readTime: item.readTime,
          featured: item.featured,
          published: item.published,
          authorName: item.authorName,
          authorRole: item.authorRole,
          authorAvatar: item.authorAvatar,
          publishedAt: new Date(item.publishedAt),
        },
      });
      createdCount++;
    }
  }
  return createdCount;
}
