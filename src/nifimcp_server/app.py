"""
NiFiMCP Server – FastMCP application entry-point.

• Uses jlowin/fastmcp (which re-exports mcp.* internals)
• Maintains one NiFiApiClient per MCP session (keyed by the session object's id)
• Pulls NiFi credentials from the Initialize _meta → nifi_credentials object,
  with fallback to environment variables.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional

import anyio
import dotenv
import httpx
# Use the specific FastMCP library
from fastmcp import FastMCP
from pydantic import BaseModel, ValidationError

# Import from our sibling modules
from .nifi_api_client import NiFiApiClient, NiFiApiException, NiFiAuthException
from .nifi_models import NiFiClientCreds

# ────────────────────────────── env / logging ──────────────────────────────
# Load .env file from project root (../.. relative to this file's directory)
env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
if os.path.exists(env_path):
    dotenv.load_dotenv(dotenv_path=env_path)
    # Use standard logging temporarily to confirm env loading before full setup
    logging.info(f"--- Loaded environment variables from: {env_path} ---")
else:
    logging.warning(f"--- .env file not found at {env_path} ---")


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
# Configure standard Python logging - ensures console output
log_format = '%(asctime)s %(levelname)-8s %(name)s | %(message)s'
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=log_format,
    stream=sys.stderr, # Ensure logs go to stderr, not stdout
    force=True # Override any previous configuration
)
logger = logging.getLogger("nifimcp_server.app") # Logger specific to this module
logger.info("Python logging configured. Root level: %s", logging.getLevelName(logging.getLogger().level))
# Note: FastMCP might have its own logging integration for sending logs to the client.

# ───────────────────── per-session cache & helpers ──────────────────────
# Cache for active clients, keyed by string representation of session object ID
active_nifi_api_clients: Dict[str, NiFiApiClient] = {}
# Locks to prevent race conditions during client creation for the same session
_client_creation_locks: Dict[str, asyncio.Lock] = {}
# Global lock to protect access to the _client_creation_locks dictionary
_global_lock = asyncio.Lock()


async def _get_lock(session_id: str) -> asyncio.Lock:
    """Gets or creates an asyncio Lock for a given session ID."""
    async with _global_lock:
        # Use setdefault for atomicity
        return _client_creation_locks.setdefault(session_id, asyncio.Lock())


def _bool_from_env(val: str | None, default: bool = True) -> bool:
    """Safely converts env var string to boolean."""
    if val is None:
        return default
    return val.lower() in {"1", "true", "yes", "y"}


# ─────────────────────── client accessor (main helper) ───────────────────────
async def get_session_nifi_client(ctx: Context) -> NiFiApiClient:
    """
    Retrieves or creates an authenticated NiFiApiClient for the current MCP session.
    Uses the id() of ctx.session as the unique cache key.
    Extracts credentials from initialize request's _meta.nifi_credentials,
    falling back to environment variables.
    """
    # --- Get Session ID ---
    session_object = getattr(ctx, 'session', None)
    if not session_object:
        logger.error("CRITICAL: Cannot access ctx.session object.")
        raise NiFiApiException(0, "Server error: Could not access session object from context.")
    # Use the memory address of the session object as the unique ID
    session_id = str(id(session_object))
    # --- End Session ID ---

    logger.debug(f"Attempting to get/create NiFi client for session ID: {session_id}")

    # 1. Check cache (non-blocking read)
    cached_client = active_nifi_api_clients.get(session_id)
    if cached_client:
        logger.debug(f"Reusing cached NiFiApiClient for session {session_id}")
        return cached_client

    # 2. If not cached, acquire lock for this specific session ID
    creation_lock = await _get_lock(session_id)
    async with creation_lock:
        # 3. Double-check cache after acquiring lock
        cached_client = active_nifi_api_clients.get(session_id)
        if cached_client:
            logger.debug(f"Reusing cached NiFiApiClient for session {session_id} (after lock)")
            return cached_client

        # 4. Create new client if still not found
        logger.info(f"No cached client found. Creating new NiFiApiClient for session {session_id}.")

        # --- Extract Credentials ---
        # Target `ctx.session._client_params._meta` as the most likely location
        initialize_params: Optional[Any] = getattr(session_object, '_client_params', None)
        raw_meta: Optional[Dict[str, Any]] = None

        if initialize_params:
            raw_meta = getattr(initialize_params, '_meta', None)
            if not isinstance(raw_meta, dict):
                logger.warning(f"Attribute '_meta' on session._client_params is not a dict for session {session_id}.")
                raw_meta = None # Reset to trigger fallback

        creds_dict: Optional[Dict[str, Any]] = None
        creds_source = "environment" # Default assumption

        if raw_meta and "nifi_credentials" in raw_meta and isinstance(raw_meta["nifi_credentials"], dict):
            creds_dict = raw_meta["nifi_credentials"]
            creds_source = "_meta.nifi_credentials"
            logger.info(f"Using credentials from {creds_source} for session {session_id}.")
        else:
            logger.info(f"No 'nifi_credentials' in initialize _meta for session {session_id}. Checking environment variables.")
            env_user = os.getenv("NIFI_MCP_USERNAME")
            env_pass = os.getenv("NIFI_MCP_PASSWORD")
            env_tok = os.getenv("NIFI_MCP_TOKEN")
            if env_tok:
                creds_dict = {"token": env_tok}
                logger.info(f"Using NIFI_MCP_TOKEN from environment for session {session_id}.")
            elif env_user and env_pass:
                creds_dict = {"username": env_user, "password": env_pass}
                logger.info(f"Using NIFI_MCP_USERNAME/PASSWORD from environment for session {session_id}.")

        if not creds_dict:
            logger.error(f"FATAL: Unable to obtain NiFi credentials for session {session_id} from {creds_source}.")
            raise NiFiAuthException("NiFi credentials not supplied via _meta or env vars")

        # Extract config from creds_dict before validation
        # Base URL: Check _meta first, then environment
        base_url = creds_dict.get("url") or os.getenv("NIFI_BASE_URL")
        if not base_url:
            logger.error("FATAL: NIFI_BASE_URL not configured on server or provided in _meta.")
            raise NiFiApiException(0, "NIFI_BASE_URL not configured on server")

        # SSL Verify: Check _meta first, then environment
        ssl_verify = creds_dict.get("ssl_verify")
        if ssl_verify is None:
            # Default to True if env var not set
            ssl_verify = _bool_from_env(os.getenv("NIFI_MCP_SSL_VERIFY"), default=True)

        if not ssl_verify:
             logger.warning(f"!!! SSL VERIFY IS FALSE for session {session_id} based on {creds_source} or environment !!!")
        else:
             logger.info(f"SSL Verify is TRUE for session {session_id}")

        # Validate credentials structure *after* extracting URL/SSL config
        try:
            creds = NiFiClientCreds.model_validate(creds_dict)
        except ValidationError as e:
            logger.error(f"Invalid NiFi credentials structure in {creds_source} for session {session_id}: {e}")
            raise NiFiAuthException(f"Invalid NiFi credentials structure: {e}")

        # 5. Create and cache the client
        try:
            nifi_api_client = await NiFiApiClient.create(
                base_url=base_url,
                username=creds.username,
                password=creds.password,
                existing_token=creds.token,
                ssl_verify=ssl_verify # Pass the determined flag
            )
            logger.info(f"NiFiApiClient created and authenticated successfully for session {session_id}.")
            active_nifi_api_clients[session_id] = nifi_api_client
            return nifi_api_client
        except (NiFiAuthException, NiFiApiException, ValueError) as e:
            logger.error(f"Failed to create NiFiApiClient for session {session_id}: {e}")
            # Clean up lock if creation failed permanently
            async with _global_lock:
                 _client_creation_locks.pop(session_id, None)
            raise # Re-raise the exception

# ───────────────────────────── lifespan handler ─────────────────────────────
@asynccontextmanager
async def app_lifespan(app: FastMCP) -> AsyncIterator[None]:
    """Handles application-level startup and shutdown."""
    logger.info("NiFiMCP Server application starting...")
    yield # Server runs
    logger.info("NiFiMCP Server application shutting down – closing %d potential NiFi clients", len(active_nifi_api_clients))
    # Clean up any clients remaining in the cache
    clients_to_close = list(active_nifi_api_clients.values())
    active_nifi_api_clients.clear()
    _client_creation_locks.clear()

    async with anyio.create_task_group() as tg:
        for client in clients_to_close:
             # Use the close method defined on NiFiApiClient
             tg.start_soon(client.close)
             logger.debug(f"Scheduled close for cached client {id(client)}")

    logger.info("Global lifespan cleanup finished.")


# --- Session Cleanup Hook (Placeholder) ---
# --- Developer Task: Integrate Cleanup Hook ---
# Find the correct mechanism in jlowin/fastmcp to trigger this
# function when a specific MCP session ends.
async def cleanup_nifi_client_for_session(ctx: Context):
    """
    Cleans up the NiFiApiClient when an MCP session ends.
    Needs to be registered with the correct jlowin/fastmcp hook.
    """
    session_object = getattr(ctx, 'session', None)
    if not session_object:
        logger.warning("Could not get session object during cleanup hook.")
        return
    session_id = str(id(session_object))

    logger.info(f"Session end hook/logic triggered for session: {session_id}.")

    # Remove the creation lock associated with this session
    async with _global_lock:
        lock = _client_creation_locks.pop(session_id, None)
        if lock:
             logger.debug(f"Removed creation lock for session {session_id}.")

    # Remove client from cache and close it
    nifi_client = active_nifi_api_clients.pop(session_id, None)
    if nifi_client:
        try:
            await nifi_client.close() # Use the close method we defined
            logger.info(f"Successfully closed NiFiApiClient for session {session_id}.")
        except Exception as e:
            logger.error(f"Error closing NiFiApiClient for session {session_id}: {e}")
    else:
        logger.warning(f"No active NiFiApiClient found in cache to clean up for session {session_id}.")
# TODO: Register `cleanup_nifi_client_for_session` with the appropriate FastMCP hook.


# ─────────────────────────── FastMCP application ────────────────────────────
mcp_app = FastMCP(
    name="NiFiMCP Server",
    # version="1.0", # Consider making dynamic later
    instructions=(
        "This server exposes tools that wrap Apache NiFi’s REST API so that an "
        "LLM client can create, query, and modify data-flow components."
    ),
    dependencies=["httpx", "pydantic", "pydantic-settings"],
    lifespan=app_lifespan, # Register the global lifespan handler
)




# ───────────────────────────── tool registration ────────────────────────────
def register_tools() -> None:
    """Imports tool modules and calls their registration functions."""
    logger.info("Attempting to register tools...")
    modules_registered = []
    try:
        # Import modules first
        from .tools import access
        from .tools import process_groups
        from .tools import processors
        from .tools import connections
        from .tools import input_ports
        from .tools import output_ports
        from .tools import flow
        from .tools import controller_services # NEW IMPORT
        logger.info("Successfully imported tool modules.")

        # Explicitly call registration functions
        if hasattr(access, 'register_access_tools'):
            access.register_access_tools(mcp_app)
            modules_registered.append("access")
        else: logger.warning("register_access_tools not found in tools.access")

        if hasattr(process_groups, 'register_process_group_tools'):
            process_groups.register_process_group_tools(mcp_app)
            modules_registered.append("process_groups")
        else: logger.warning("register_process_group_tools not found in tools.process_groups")

        if hasattr(processors, 'register_processor_tools'):
            processors.register_processor_tools(mcp_app)
            modules_registered.append("processors")
        else: logger.warning("register_processor_tools not found in tools.processors")

        if hasattr(connections, 'register_connection_tools'):
            connections.register_connection_tools(mcp_app)
            modules_registered.append("connections")
        else: logger.warning("register_connection_tools not found in tools.connections")

        if hasattr(input_ports, 'register_input_port_tools'):
            input_ports.register_input_port_tools(mcp_app)
            modules_registered.append("input_ports")
        else: logger.warning("register_input_port_tools not found in tools.input_ports")

        if hasattr(output_ports, 'register_output_port_tools'):
            output_ports.register_output_port_tools(mcp_app)
            modules_registered.append("output_ports")
        else: logger.warning("register_output_port_tools not found in tools.output_ports")

        if hasattr(flow, 'register_flow_tools'):
            flow.register_flow_tools(mcp_app)
            modules_registered.append("flow")
        else: logger.warning("register_flow_tools not found in tools.flow")

        # NEW REGISTRATION CALL
        if hasattr(controller_services, 'register_controller_service_tools'):
            controller_services.register_controller_service_tools(mcp_app)
            modules_registered.append("controller_services")
        else: logger.warning("register_controller_service_tools not found in tools.controller_services")

        logger.info(f"Tool registration process completed for modules: {', '.join(modules_registered)}")

    except ImportError as exc:
        logger.error("Tool registration failed during import: %s", exc)
    except Exception as exc:
        logger.exception("Unexpected error during tool registration: %s", exc)

    # --- Log Registered Tools (Developer Task 4: Inspect/Verify) ---
    registered_tools_list = []
    tool_manager = getattr(mcp_app, "_tool_manager", None) # Check common internal name
    if tool_manager and hasattr(tool_manager, "list_tools") and callable(tool_manager.list_tools):
        try:
            registered_tools_list = [tool.name for tool in tool_manager.list_tools()]
        except Exception as exc:
            logger.warning("Could not list registered tools from _tool_manager: %s", exc)
    else:
        logger.warning("Could not retrieve list of registered tools: _tool_manager not found or has no list_tools method.")
    logger.info("Tools currently registered with mcp_app: %s", registered_tools_list)
    # --- End Task 4 ---

# Exported for CLI entry-point in pyproject.toml
mcp_app_for_cli = mcp_app

# ────────────────────────────── main (stdio) ────────────────────────────────
if __name__ == "__main__":
    logger.info("Executing main block (__name__ == '__main__')")
    register_tools() # Register tools explicitly when run directly
    logger.info("Starting NiFiMCP Server (stdio transport)…")
    mcp_app.run() # Start the server using stdio