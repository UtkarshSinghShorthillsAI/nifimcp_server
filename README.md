# NiFiMCP Server

MCP Server for interacting with Apache NiFi via a natural language interface.

## Overview

This server exposes Apache NiFi functionalities as "tools" that can be understood and invoked by a Large Language Model (LLM) through an MCP Client.

## Project Structure

(To be detailed further)

## Setup

1.  Clone the repository.
2.  Ensure Python 3.10+ and `uv` are installed.
3.  Create a virtual environment:
    ```bash
    uv venv
    source .venv/bin/activate # or .venv\Scripts\activate on Windows
    ```
4.  Install dependencies:
    ```bash
    uv pip install -e .[dev]
    ```
5.  Set up your NiFi connection details in a `.env` file (see `.env.example`).

## Running the Server

(To be detailed further, e.g., using `mcp run`)
```
python3 -m src.nifimcp_server.app
```

### Running the MCP inspector
```
npx @modelcontextprotocol/inspector \
  -e NIFI_MCP_USERNAME="your_nifi_user" \
  -e NIFI_MCP_PASSWORD="your_nifi_password" \
  python3 -m src.nifimcp_server.app
```

### MCP Server Config file
```
"mcpServers": {
    "nifi": {
      "command": "which uv to find out command",
      "args": [
        "--directory",
        "/Users/shtlpmac008/Developer/nifimcp_server",
        "run",
        "-m",
        "src.nifimcp_server.app"
      ],
      "env": {
        "NIFI_MCP_USERNAME": "YOUR USERNAME",
        "NIFI_MCP_PASSWORD": "YOUR PASSWORD",
        "NIFI_MCP_SSL_VERIFY": "false"
      }
    }
}
```