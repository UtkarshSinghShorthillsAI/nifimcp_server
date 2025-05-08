"""
MCP Tools for interacting with NiFi Access/Authentication endpoints.
"""
import logging
import os
from typing import Optional

import httpx
from fastmcp import Context, FastMCP
# Use the specific ToolError from fastmcp if it exists, otherwise a general Exception
try:
    from fastmcp.exceptions import ToolError
except ImportError:
    # Fallback if a specific ToolError isn't defined in this version
    class ToolError(Exception):
        pass
from pydantic import Field

# Import API client and specific exceptions
from ..nifi_api_client import NiFiApiClient, NiFiApiException, NiFiAuthException
# Import utility to get session client (though not used by this specific tool)
# from ..app import get_session_nifi_client
# Import the specific response model
from ..nifi_models import AuthenticationConfigurationEntity
# Import utility to get session client
from ..app import get_session_nifi_client

# Logger for this module
tool_logger = logging.getLogger(__name__)

# --- Tool Implementations ---

async def create_nifi_access_token_impl(
    ctx: Context, # Context is available, even if not used for NiFi client here
    username: str = Field(..., description="NiFi username"),
    password: str = Field(..., description="NiFi password")
) -> str:
    """
    Requests a NiFi access token (JWT) using username and password.

    This tool directly calls the NiFi authentication endpoint to generate
    a new token based on the provided username and password. The resulting
    token is returned.

    Args:
        ctx: The MCP Context (not used for NiFi client creation in this specific tool).
        username: The username for NiFi authentication.
        password: The password for NiFi authentication.

    Returns:
        The generated JWT access token string.

    Raises:
        ToolError: If authentication fails, configuration is missing, or an API error occurs.
    """
    tool_logger.info(f"Tool 'create_nifi_access_token' called for user '{username}'.")
    try:
        nifi_base_url = os.getenv("NIFI_BASE_URL")
        if not nifi_base_url:
            tool_logger.error("NIFI_BASE_URL environment variable is not set.")
            raise ToolError("Server configuration error: NIFI_BASE_URL not set.")

        # --- ADD SSL Verification Control ---
        ssl_verify_str = os.getenv("NIFI_MCP_SSL_VERIFY", "true").lower()
        ssl_verify = ssl_verify_str not in ("false", "0", "no", "f")
        if not ssl_verify:
            tool_logger.warning("SSL certificate verification is DISABLED for create_nifi_access_token tool.")
        # --- End SSL Verification Control ---
        # Create a temporary httpx client specifically for this authentication request
        async with httpx.AsyncClient(verify=ssl_verify) as temp_client:
            # Instantiate NiFiApiClient only to use its internal _authenticate method
            # This does *not* use or affect the cached session client
            temp_api_instance = NiFiApiClient(nifi_base_url, temp_client)
            try:
                # Directly call the private method that performs POST /access/token
                # We pass username/password received as tool arguments.
                # This returns the plain text token on success (status 201).
                token = await temp_api_instance._authenticate(username, password)
                tool_logger.info(f"Successfully obtained token for user '{username}' via tool.")
                # This token is returned to the LLM/Client via the tool result.
                return token
            except NiFiAuthException as e:
                tool_logger.error(f"NiFi authentication failed via tool: {e}")
                # Re-raise as ToolError for MCP
                raise ToolError(f"NiFi Authentication Failed: {e}") from e
            except NiFiApiException as e:
                 # Catch API errors specifically from _authenticate if it raises them
                 tool_logger.error(f"NiFi API exception during token creation via tool: {e}")
                 raise ToolError(f"NiFi API Error during authentication: {e}") from e

    except ToolError: # Re-raise ToolErrors directly
        raise
    except Exception as e:
        tool_logger.exception(f"Unexpected error in create_nifi_access_token_impl: {e}")
        # Wrap unexpected errors in ToolError
        raise ToolError(f"An unexpected error occurred: {e}")

# --- NEW TOOL IMPLEMENTATION ---
async def get_nifi_authentication_configuration_impl(ctx: Context) -> AuthenticationConfigurationEntity:
    """
    Retrieves the NiFi server's authentication configuration.
    Requires the session to be authenticated (e.g., via client providing credentials
    during initialize, or potentially via a previous call to create_nifi_access_token
    if the client stored and reused the token - which this server doesn't manage automatically).
    """
    tool_logger.info("Tool 'get_nifi_authentication_configuration' called.")
    try:
        # Get the authenticated NiFi client for this session
        nifi_client = await get_session_nifi_client(ctx)

        # Call the corresponding method on the client
        auth_config_entity = await nifi_client.get_nifi_authentication_configuration()

        tool_logger.info("Successfully retrieved NiFi authentication configuration.")
        return auth_config_entity # Return the Pydantic model directly

    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to get NiFi authentication configuration: {e}")
        # Raise ToolError for MCP client
        raise ToolError(f"Failed to get NiFi authentication configuration: {e}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in get_nifi_authentication_configuration_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {e}")


# Inside src/nifimcp_server/tools/access.py

# ... (imports and logger setup remain the same) ...

async def inspect_mcp_context_impl(ctx: Context) -> str:
    """Implementation for inspecting the MCP context object using standard logging."""
    tool_logger.info("--- tool_logger.info: Entered inspect_mcp_context_impl ---")

    try:
        tool_logger.info(f"--- Context object id: {id(ctx)} ---")

        session_obj = None
        if hasattr(ctx, 'session'):
            session_obj = ctx.session
            tool_logger.info(f"--- ctx.session object id: {id(session_obj)} ---")
            tool_logger.info(f"--- ctx.session type: {type(session_obj)} ---")
            # Log attributes again, maybe we missed something simple
            tool_logger.info(f"--- ctx.session attributes: {dir(session_obj)} ---")
            # Specifically check for attributes that might hold an ID
            for attr_name in ['id', '_id', 'conn_id', 'connection_id', 'transport_id', 'client_id']:
                 if hasattr(session_obj, attr_name):
                     tool_logger.info(f"--- Found potential session ID on ctx.session.{attr_name}: {getattr(session_obj, attr_name)} ---")

        else:
             tool_logger.warning("ctx has no 'session' attribute.")

        request_context_obj = None
        if hasattr(ctx, 'request_context'):
            request_context_obj = ctx.request_context
            tool_logger.info(f"--- ctx.request_context object id: {id(request_context_obj)} ---")
            tool_logger.info(f"--- ctx.request_context type: {type(request_context_obj)} ---")
            # Log attributes again
            tool_logger.info(f"--- ctx.request_context attributes: {dir(request_context_obj)} ---")
             # Specifically check for attributes that might hold an ID
            for attr_name in ['id', '_id', 'conn_id', 'connection_id', 'transport_id', 'client_id', 'session_id']:
                 if hasattr(request_context_obj, attr_name):
                     tool_logger.info(f"--- Found potential session ID on ctx.request_context.{attr_name}: {getattr(request_context_obj, attr_name)} ---")
            # Also log the contained session object's ID again for comparison
            if hasattr(request_context_obj, 'session'):
                tool_logger.info(f"--- ID of session within request_context: {id(request_context_obj.session)} ---")


        else:
             tool_logger.warning("ctx has no 'request_context' attribute.")


        tool_logger.info("--- tool_logger.info: BEFORE returning ---")
        return "Context details logged. Check server logs/Inspector UI for session ID candidates."

    except Exception as e:
        tool_logger.exception(f"--- EXCEPTION inside inspect_mcp_context_impl: {e} ---")
        return f"ERROR in tool inspect_mcp_context_impl: {e}" # Return error string

    finally:
        tool_logger.info("--- tool_logger.info: FINALLY block ---")

# # --- Tool Registration ---
# def register_access_tools(app: FastMCP):
#     """Registers access/authentication tools with the FastMCP app."""
#     registration_logger = logging.getLogger(__name__ + ".registration")
#     registration_logger.info("Registering Access tools...")
#     # Temporarily register ONLY the inspect tool for focused debugging
#     app.tool(name="inspect_mcp_context")(inspect_mcp_context_impl)
#     # app.tool(name="create_nifi_access_token")(create_nifi_access_token_impl) # Comment out for now
#     registration_logger.info("Inspect Context tool registered.")

# # --- Tool Registration ---
def register_access_tools(app: FastMCP):
    """Registers access/authentication tools with the FastMCP app."""
    registration_logger = logging.getLogger(__name__ + ".registration")
    registration_logger.info("Registering Access tools...")

    # Register the actual authentication tool
    # The name 'create_nifi_access_token' aligns with our convention
    app.tool(name="create_nifi_access_token")(create_nifi_access_token_impl)
    # --- ADD REGISTRATION FOR THE NEW TOOL ---
    app.tool(name="get_nifi_authentication_configuration")(get_nifi_authentication_configuration_impl)

    # We removed the inspect_mcp_context tool registration
    registration_logger.info("Access tools registration complete.")