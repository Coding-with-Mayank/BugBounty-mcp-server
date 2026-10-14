# Gemini CLI Setup

The MCP server works with Google's Gemini CLI out of the box.

## Automatic (via setup.sh)

`setup.sh` auto-detects Gemini CLI and writes the config. If it ran successfully, skip to Step 3.

## Manual Setup

### Step 1: Make sure the container is running
```bash
make up
docker ps | grep bugbounty-mcp
```

### Step 2: Add to Gemini CLI config

Edit `~/.gemini/settings.json` (create it if it doesn't exist):

```json
{
  "mcpServers": {
    "bugbounty": {
      "command": "docker",
      "args": ["exec", "-i", "bugbounty-mcp", "python", "-m", "mcp_server"]
    }
  }
}
```

If you already have a `settings.json`, just merge the `mcpServers` block into it.

### Step 3: Verify

Start Gemini CLI:
```bash
gemini
```

You should see `bugbounty` listed in available tools/MCPs. If not, restart the CLI session.

## Using it

```
gemini> Run subdomain_enum on example.com

gemini> Take screenshots of https://example.com and https://test.example.com

gemini> Scan example.com for vulnerabilities and tell me what's critical

gemini> I found these subdomains: [list]. Check which ones are alive and interesting.
```

Gemini will automatically invoke the right tools and return the structured output including the guidance block.

## Tips for Gemini

- Gemini often works well with explicit tool names: "use the nuclei_scan tool on..."
- For multi-step workflows, be explicit: "first run full_recon, then scan the alive hosts"
- The `analyze_findings` tool works great for summarizing a collection of results you've gathered
