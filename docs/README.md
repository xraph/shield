# Shield docs site

This is the documentation site for [Shield](https://github.com/xraph/shield), the AI safety policies and guardrail configuration for Go. It's a [Fumadocs](https://fumadocs.dev) site on Next.js, and the pages you edit are MDX files under `content/docs/`.

## Run it

You need Node and [pnpm](https://pnpm.io).

```bash
cd docs
pnpm install    # postinstall runs fumadocs-mdx to generate the content sources
pnpm dev        # next dev, on http://localhost:3000
```

The other scripts in `package.json`:

| Script | What it does |
|--------|--------------|
| `pnpm build` | `next build`, a production build |
| `pnpm start` | `next start`, serves that build |
| `pnpm types:check` | regenerates the MDX sources and Next types, then runs `tsc --noEmit` |
| `pnpm lint` | `biome check` |
| `pnpm format` | `biome format --write` |

## Where things live

| Path | What it holds |
|------|---------------|
| `content/docs/` | the MDX pages, one folder per section |
| `content/docs/**/meta.json` | page order and section titles for the sidebar |
| `src/app/(home)/` | the landing page, built from `src/components/landing/` |
| `src/app/docs/` | the docs layout and page route |
| `src/app/api/search/route.ts` | the search endpoint |
| `src/app/llms.txt`, `src/app/llms-full.txt`, `src/app/llms.mdx` | plain-text exports of the docs for LLM tools |
| `src/app/og/` | Open Graph images for docs pages |

When you add or rename a page, update the `meta.json` in its folder and fix every link to the old path. The repo's own [README](../README.md) is the most current summary of the Go API, so check a page against it (and the code) when the two disagree.
