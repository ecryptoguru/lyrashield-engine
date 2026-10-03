import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";
import { fileURLToPath } from "node:url";

// Exercise every owned Markdown surface through Vite's TSX and alias handling.
const vite = await createServer({
  root: fileURLToPath(new URL("..", import.meta.url)),
  server: { middlewareMode: true, hmr: false },
  optimizeDeps: { noDiscovery: true, include: [] },
});
try {
  const { ContentSection } = await vite.ssrLoadModule("/src/components/vulnerability/ContentSection.tsx");
  const { PocBlock } = await vite.ssrLoadModule("/src/components/vulnerability/PocBlock.tsx");
  const { default: Markdown } = await vite.ssrLoadModule("/src/components/live/tool-renderers/Markdown.tsx");
  const { default: NotesRenderer } = await vite.ssrLoadModule("/src/components/live/tool-renderers/NotesRenderer.tsx");
  const markdown = [
    "Safe prose. ![sentinel image](https://image-probe.invalid/image.svg)",
    "",
    "![reference image][tracker]",
    "",
    "[tracker]: https://image-probe.invalid/reference.svg",
    '<img src="https://image-probe.invalid/raw-html.svg">',
  ].join("\n");
  const surfaces = [
    ["report", ContentSection, { content: markdown }],
    ["poc", PocBlock, { description: markdown }],
    ["transcript", Markdown, { text: markdown }],
    ["notes", NotesRenderer, { toolName: "create_note", args: { content: markdown }, result: null }],
  ];
  for (const [name, component, props] of surfaces) {
    const rendered = renderToStaticMarkup(createElement(component, props));
    assert.doesNotMatch(rendered, /<img\b|<link\b[^>]*rel="preload"/i, `${name} must not request Markdown images`);
    assert.match(rendered, /sentinel image/, `${name} keeps image alt text`);
  }
  console.log("PASS: report, PoC, transcript and notes render Markdown images inert");
} finally {
  await vite.close();
}
