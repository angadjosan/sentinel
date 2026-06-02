Things to think about

- Dev experience: How to manage cloud runs, parallelism, ease of developer use (login to API, switch models, good Cli + skill, minimizing token use). Storing session traces really well. How to build replicable pentest runner

- how to fit into context. Manage large and small diffs. Manage token efficiency. Large enterprises don't have very large diffs, so it's okay to think in terms of loading everything into context, loading the context graph in as well, and doing it in terms of small diffs now. To do, think about how Claude Code and CodeCodex handle large diffs and large codebases. We might have to do some grepping.

- How to build/query the graph. Think about graph as a better version of AST. Reverse engineer - how would we query/attack it? Think about access controls as metadata in the graph. Security roles built into the graph on TOP of the AST. https://tree-sitter.github.io/tree-sitter/

Here's how other people do it:
Good, now I have a clear picture. Let me search for similar projects.Here's a rundown of the most notable similar projects in this space, organized by approach:

---

## Close Alternatives to codebase-memory-mcp

### 🔴 Closest Competitors (same niche, active)

**[GitNexus](https://github.com/nxpatterns/gitnexus)** — The most direct rival. Tree-sitter AST parsing, pre-computed dependency structure, single-call blast radius analysis, 7 MCP tools including `detect_changes`, `rename`, and `generate_map` for Mermaid architecture diagrams. Also has a web UI, wiki generation, and multi-repo support. Very widely forked (appears to be one of the most cloned projects in the space). Available via `npm install -g gitnexus`.

**[code-graph-mcp](https://github.com/sdsrss/code-graph-mcp)** — Hybrid BM25 + vector semantic search via sqlite-vec with Reciprocal Rank Fusion, BLAKE3 Merkle tree for incremental re-indexing (dirty propagation regenerates downstream callers on signature change), first-class Claude Code plugin with `/understand`, `/trace`, `/impact` slash commands, and StatusLine integration. Newer but highly capable.

**[graphify](https://github.com/safishamsi/graphify)** — Broader scope: code, SQL schemas, R scripts, docs, papers, images, and videos into a queryable knowledge graph. AST via tree-sitter runs locally with no API calls. Exports to SVG, GraphML (Gephi/yEd), Neo4j Cypher, or starts an MCP stdio server. Claims 71.5x fewer tokens per query vs raw files, with auto-sync via `--watch`.

---

### 🟡 Solid but More Narrowly Scoped

**[CartographAI/mcp-server-codegraph](https://github.com/CartographAI/mcp-server-codegraph)** — Indexes the codebase into a graph of entities and relationships, available via `npx @cartographai/mcp-server-codegraph`. Simpler/lighter than the others, good for quick setup.

**[CodeGraphContext](https://github.com/CodeGraphContext/CodeGraphContext)** — Uses an external graph database (Neo4j-style), stores credentials in `~/.codegraphcontext/.env`, watches for file changes for real-time updates. Excels at call chain tracing across hundreds of files — impact analysis, debugging execution paths, cross-file dependency tracking.

**[code-review-graph](https://github.com/tirth8205/code-review-graph)** — Local-first, SQLite-backed, Tree-sitter parsing, auto-detects Claude Code / Cursor / etc., generates interactive HTML graph visualizations. Focused specifically on code review workflows.

**[code-grapher](https://github.com/mufasadb/code-grapher)** — Full AST analysis, git-diff surgical updates, hybrid semantic + structural retrieval, local Ollama support for fully private processing.

---

### Quick Comparison

| Project | Language | Storage | Semantic Search | Highlights |
|---|---|---|---|---|
| **codebase-memory-mcp** | C (binary) | SQLite | Bundled embeddings | 155 langs, fastest indexing, zero deps |
| **GitNexus** | Node.js | SQLite | Optional embeddings | Wiki gen, web UI, most forks |
| **code-graph-mcp** | TypeScript | SQLite+vec | BM25+vector hybrid | Best Claude Code integration |
| **graphify** | Python | SQLite | TF-IDF | Multi-format export, broadest input types |
| **CartographAI codegraph** | TypeScript | In-memory | No | Simplest setup |
| **CodeGraphContext** | Node.js | External DB | No | Best call chain depth |

The main differentiators to look for are: **language breadth** (codebase-memory-mcp wins), **semantic search quality** (code-graph-mcp's RRF hybrid is strong), **zero-setup** (codebase-memory-mcp's static binary vs. npm/pip installs), and **input diversity** (graphify handles non-code files too).