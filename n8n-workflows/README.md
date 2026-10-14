# n8n Workflows

Place your n8n workflow JSON exports here. They'll be auto-imported when n8n starts.

## Included workflows (coming soon):

- `daily-recon.json` — Scheduled daily subdomain monitoring
- `vuln-alerts.json` — Slack/Telegram alert on critical findings
- `new-subdomain-scan.json` — Auto-scan new subdomains as they appear

## How to start n8n:

```bash
make n8n
# OR
docker-compose --profile automation up -d
```

Then open: http://localhost:5678
