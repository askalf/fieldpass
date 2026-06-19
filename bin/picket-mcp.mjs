#!/usr/bin/env node
/**
 * picket MCP server (stdio). Add to an MCP client config, e.g. Claude Desktop /
 * Claude Code `.mcp.json`:
 *
 *   {
 *     "mcpServers": {
 *       "picket": {
 *         "command": "npx",
 *         "args": ["-y", "@askalf/picket", "picket-mcp"],
 *         "env": {
 *           "PICKET_ALLOWLIST": "example.com,acme.example",
 *           "PICKET_CDP": "http://127.0.0.1:9222",
 *           "PICKET_JUDGE": "dario"
 *         }
 *       }
 *     }
 *   }
 *
 * Env: PICKET_ALLOWLIST (comma-separated host suffixes), PICKET_CDP (live URL
 * fetches; omit for html-only), PICKET_JUDGE ("dario" | "claude" | unset),
 * PICKET_TASK (default trusted task).
 *
 * stdout is the MCP channel — all human-readable logging goes to stderr.
 */
import { readFileSync } from 'node:fs';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createPicketServer } from '../src/mcp.mjs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const allowlist = (process.env.PICKET_ALLOWLIST || '').split(',').map((s) => s.trim()).filter(Boolean);

const { server } = createPicketServer({
  version: pkg.version,
  allowlist,
  task: process.env.PICKET_TASK || '',
  judge: process.env.PICKET_JUDGE || null,
  cdp: process.env.PICKET_CDP || null,
});

const transport = new StdioServerTransport();
await server.connect(transport);

console.error(
  `picket MCP server ready (v${pkg.version}) · ` +
  `allowlist=[${allowlist.join(', ') || '∗ (open)'}] · ` +
  `cdp=${process.env.PICKET_CDP || 'none — html-only'} · ` +
  `judge=${process.env.PICKET_JUDGE || 'off'}`
);
