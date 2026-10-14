"""
toolmgr — dependency/tool-version management for BugBounty-mcp-server.

Standalone on purpose (stdlib + PyYAML only): the same code runs in the
native installer, `hunt update|doctor`, the systemd timer, CI, and the
Docker build's Go stage.
"""
