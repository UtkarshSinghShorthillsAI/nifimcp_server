"""
MCP Tools for interacting with NiFi Process Groups.
"""
import logging
from typing import Any, Optional

# Use the specific FastMCP version
from fastmcp import FastMCP, Context

# Import our Pydantic models
from ..nifi_models import ProcessGroupEntity, RevisionDTO, NiFiApiException, NiFiAuthException
from pydantic import Field

# Import utility to get session client
from ..app import get_session_nifi_client # Assuming get_session_nifi_client is in app.py

# Logger for this module
tool_logger = logging.getLogger(__name__)

# --- Tool Implementations (Placeholders) ---

async def create_nifi_process_group_impl(ctx: Context, parent_id: str, pg_entity_payload: ProcessGroupEntity) -> Optional[ProcessGroupEntity]:
    """Placeholder: Creates a new process group."""
    tool_logger.info(f"Tool 'create_nifi_process_group' called for parent {parent_id}.")
    # nifi_client = await get_session_nifi_client(ctx)
    # # Implementation using nifi_client.create_process_group...
    # return await nifi_client.create_process_group(parent_id, pg_entity_payload)
    tool_logger.warning("create_nifi_process_group_impl not fully implemented.")
    return None # Placeholder

async def get_nifi_process_group_details_impl(
    ctx: Context,
    process_group_id: str = Field(..., description="The ID of the process group to retrieve.")
) -> Optional[ProcessGroupEntity]:
    """
    Retrieves the details of a specific NiFi Process Group by its ID.
    Returns the process group details if found, otherwise None.
    """
    tool_logger.info(f"Tool 'get_nifi_process_group_details' called for ID {process_group_id}.")
    try:
        # Get the authenticated NiFi client for this session
        nifi_client = await get_session_nifi_client(ctx)

        # Call the corresponding method on the API client
        pg_entity = await nifi_client.get_process_group(process_group_id)

        if pg_entity is None:
            tool_logger.info(f"Process Group {process_group_id} not found.")
            # Returning None is valid if the tool is defined to return Optional[...]
            # Alternatively, could raise ToolError("Process Group not found")
            return None
        else:
            tool_logger.info(f"Successfully retrieved details for Process Group {process_group_id}.")
            return pg_entity # Return the Pydantic model directly

    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to get NiFi process group details for {process_group_id}: {e}")
        raise ToolError(f"Failed to get process group details: {e}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in get_nifi_process_group_details_impl for {process_group_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {e}")

async def update_nifi_process_group_impl(ctx: Context, process_group_id: str, pg_entity_payload: ProcessGroupEntity) -> Optional[ProcessGroupEntity]:
    """Placeholder: Updates an existing process group."""
    tool_logger.info(f"Tool 'update_nifi_process_group' called for ID {process_group_id}.")
    # nifi_client = await get_session_nifi_client(ctx)
    # # GET LATEST REVISION FIRST
    # current_entity = await nifi_client.get_process_group(process_group_id)
    # if not current_entity or not current_entity.revision:
    #     raise ValueError("Cannot update process group: Not found or no revision.")
    # # Apply updates from payload to current_entity, ensuring revision is set
    # payload_with_revision = pg_entity_payload.model_copy(update={"revision": current_entity.revision})
    # return await nifi_client.update_process_group(process_group_id, payload_with_revision)
    tool_logger.warning("update_nifi_process_group_impl not fully implemented.")
    return None # Placeholder

async def delete_nifi_process_group_impl(ctx: Context, process_group_id: str, client_id: Optional[str] = None, disconnected_node_acknowledged: bool = False) -> Optional[ProcessGroupEntity]:
    """Placeholder: Deletes a process group."""
    tool_logger.info(f"Tool 'delete_nifi_process_group' called for ID {process_group_id}.")
    # nifi_client = await get_session_nifi_client(ctx)
    # # GET LATEST REVISION FIRST
    # current_entity = await nifi_client.get_process_group(process_group_id)
    # if not current_entity or not current_entity.revision:
    #      raise ValueError("Cannot delete process group: Not found or no revision.")
    # revision = current_entity.revision
    # if client_id: # Allow override from tool if needed
    #    revision.client_id = client_id
    # return await nifi_client.delete_process_group(process_group_id, revision, disconnected_node_acknowledged)
    tool_logger.warning("delete_nifi_process_group_impl not fully implemented.")
    return None # Placeholder


# # --- Tool Registration ---
# def register_process_group_tools(app: FastMCP):
#     """Registers process group tools with the FastMCP app."""
#     tool_logger.info("Registering Process Group tools...")
#     app.tool(name="create_nifi_process_group")(create_nifi_process_group_impl)
#     app.tool(name="get_nifi_process_group_details")(get_nifi_process_group_details_impl)
#     app.tool(name="update_nifi_process_group")(update_nifi_process_group_impl)
#     app.tool(name="delete_nifi_process_group")(delete_nifi_process_group_impl)
#     tool_logger.info("Process Group tools registration complete.")


# --- Tool Registration ---
def register_process_group_tools(app: FastMCP):
    """Registers process group tools with the FastMCP app."""
    registration_logger = logging.getLogger(__name__ + ".registration")
    registration_logger.info("Registering Process Group tools...")

    app.tool(name="create_nifi_process_group")(create_nifi_process_group_impl)
    app.tool(name="get_nifi_process_group_details")(get_nifi_process_group_details_impl) # Use the real impl
    app.tool(name="update_nifi_process_group")(update_nifi_process_group_impl)
    app.tool(name="delete_nifi_process_group")(delete_nifi_process_group_impl)

    registration_logger.info("Process Group tools registration complete (partially).") # Update log