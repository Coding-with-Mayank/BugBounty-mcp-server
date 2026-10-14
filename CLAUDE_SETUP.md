# Claude Setup Guide

## Claude Desktop

### Step 1: Make sure the container is running
```bash
make up
# Verify:
docker ps | grep bugbounty-mcp
```

### Step 2: Find your config file

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

### Step 3: Edit the config

If the file doesn't exist, create it. If it does, merge the `mcpServers` block.

```json
{
  "mcpServers": {
    "bugbounty": {
      "command": "docker",
      "args": ["exec", "-i", "bugbounty-mcp", "python", "-m", "mcp_server"],
      "env": {}
    }
  }
}
```

If you already have other MCP servers, just add the `"bugbounty"` key inside `"mcpServers"`.

### Step 4: Restart Claude Desktop

Fully quit and relaunch — not just close the window.

### Step 5: Verify

In Claude Desktop, look for the 🔌 (plug) icon or tools indicator. You should see `bugbounty` listed.

Try: *"List the available bug bounty tools"* — Claude should respond with the tool list.

---

## Claude CLI

### Automatic (run once)
```bash
claude mcp add bugbounty -- docker exec -i bugbounty-mcp python -m mcp_server
```

### Verify
```bash
claude mcp list
# Should show:
# bugbounty: docker exec -i bugbounty-mcp python -m mcp_server
```

### Remove (if you need to re-add)
```bash
claude mcp remove bugbounty
claude mcp add bugbounty -- docker exec -i bugbounty-mcp python -m mcp_server
```

### Use it
```bash
claude
# Then in the session:
> Run full_recon on example.com
> What subdomains does example.com have?
> Scan https://example.com for high and critical vulnerabilities
```

---

## Troubleshooting

**"bugbounty server not found" / tools not appearing:**
1. Confirm container is running: `docker ps | grep bugbounty-mcp`
2. Test the command manually: `docker exec -i bugbounty-mcp python -m mcp_server` — it should hang (waiting for MCP input). `Ctrl+C` to exit. If it errors, run `make rebuild`.
3. Fully restart the Claude app (not just reload).

**"Connection refused" / "Container not running":**
```bash
make up
# Wait 10 seconds then retry
```

**Config file is malformed (JSON parse error):**
```bash
# Validate JSON:
python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Tools appear but calls fail:**
```bash
make logs    # Watch for Python errors
make test    # Check all tools are installed in container
make shell   # Open bash inside container for manual debugging
```

---

## Quick test from terminal
```bash
# Send a test MCP initialize message
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  | docker exec -i bugbounty-mcp python -m mcp_server 2>/dev/null | head -1
```
You should see a JSON response with `"result"` containing server info. If you do, the MCP server is working correctly.
