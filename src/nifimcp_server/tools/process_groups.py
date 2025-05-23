"""
MCP Tools for interacting with NiFi Process Groups.
"""
import logging
from typing import Any, Optional
import asyncio
# Use the specific FastMCP version
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError
# Import our Pydantic models
from ..nifi_models import (
    ProcessGroupEntity,
    RevisionDTO, 
    NiFiApiException, 
    NiFiAuthException, 
    ProcessGroupDTO, 
    PositionDTO,
    ProcessGroupsEntity,           # NEW
    ProcessorsEntity,              # NEW - For master tool
    ConnectionsEntity,             # NEW - For master tool
    ConnectionEntity, ProcessorEntity, # For types in ProcessGroupContentOverviewDTO
    ProcessGroupContentOverviewDTO # NEW
    )
from pydantic import Field, BaseModel

# Import utility to get session client
from ..app import get_session_nifi_client # Assuming get_session_nifi_client is in app.py

# Logger for this module
tool_logger = logging.getLogger(__name__)

# --- Tool Implementations (Placeholders) ---


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

# --- Tool Implementations --
# Model for the 'component' part of the create request, specific to what the user provides
class CreateProcessGroupComponentPayload(BaseModel):
    name: str = Field(..., description="The name for the new process group.")
    position_x: float = Field(description="The X coordinate for the process group's position on the canvas.")
    position_y: float = Field(description="The Y coordinate for the process group's position on the canvas.")
    comments: Optional[str] = Field(None, description="Optional comments for the process group.")
    # Add other creatable fields here if needed by the LLM, e.g., parameter_context_name

class CreateProcessGroupPayload(BaseModel):
    parent_id: str = Field(..., description="The ID of the parent process group where the new group will be created.")
    component: CreateProcessGroupComponentPayload = Field(description="Details of the process group to create.")
    client_id: Optional[str] = Field(None, description="Optional client ID for the revision. If not provided, NiFi will generate one.")
    parameter_context_handling_strategy: Optional[str] = Field(None, description="Strategy for handling parameter contexts ('KEEP_EXISTING', 'REPLACE_EXISTING'). Only for POST.")


async def create_nifi_process_group_impl(
    ctx: Context,
    payload: CreateProcessGroupPayload # Use the new payload model
) -> ProcessGroupEntity:
    """
    Creates a new NiFi Process Group under a specified parent.
    The revision for creation is typically version 0.
    """
    tool_logger.info(f"Tool 'create_nifi_process_group' called for parent {payload.parent_id} with name '{payload.component.name}'.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        # Prepare the ProcessGroupEntity for the API request
        # Revision for creation is usually version 0
        initial_revision = RevisionDTO(clientId=payload.client_id, version=0)
        
        process_group_component_dto = ProcessGroupDTO(
            name=payload.component.name,
            position=PositionDTO(x=payload.component.position_x, y=payload.component.position_y),
            comments=payload.component.comments
            # Other settable fields from ProcessGroupDTO can be added here from payload if needed
        )
        
        api_payload = ProcessGroupEntity(
            revision=initial_revision,
            component=process_group_component_dto
        )

        created_pg_entity = await nifi_client.create_process_group(
            parent_id=payload.parent_id,
            pg_entity_payload=api_payload,
            parameter_context_handling_strategy=payload.parameter_context_handling_strategy
        )
        tool_logger.info(f"Successfully created process group '{created_pg_entity.component.name if created_pg_entity.component else 'N/A'}' with ID: {created_pg_entity.id}")
        return created_pg_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to create NiFi process group under {payload.parent_id}: {e}")
        raise ToolError(f"Failed to create process group: {e}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in create_nifi_process_group_impl for parent {payload.parent_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {e}")


# Model for the updatable 'component' part
class UpdateProcessGroupComponentPayload(BaseModel):
    name: Optional[str] = Field(None, description="New name for the process group.")
    position_x: Optional[float] = Field(None, description="New X coordinate for the process group.")
    position_y: Optional[float] = Field(None, description="New Y coordinate for the process group.")
    comments: Optional[str] = Field(None, description="New comments for the process group.")
    # Add other updatable fields from ProcessGroupDTO here as needed for LLM interaction

class UpdateProcessGroupPayload(BaseModel):
    process_group_id: str = Field(..., description="The ID of the process group to update.")
    component_updates: UpdateProcessGroupComponentPayload = Field(description="The fields to update in the process group's component.")
    client_id: Optional[str] = Field(None, description="Optional client ID for the revision. If not provided, the existing one or a NiFi-generated one might be used.")
    # disconnectedNodeAcknowledged: bool = False # NiFi API client method handles this

async def update_nifi_process_group_impl(
    ctx: Context,
    payload: UpdateProcessGroupPayload
) -> ProcessGroupEntity:
    """
    Updates an existing NiFi Process Group.
    Fetches the latest revision internally before applying updates.
    """
    tool_logger.info(f"Tool 'update_nifi_process_group' called for ID {payload.process_group_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        # 1. Get current entity to obtain the latest revision
        current_entity = await nifi_client.get_process_group(payload.process_group_id)
        if not current_entity or not current_entity.revision or not current_entity.component:
            raise ToolError(f"Process Group {payload.process_group_id} not found or has no revision/component data.")

        latest_revision = current_entity.revision
        if payload.client_id: # Allow tool input to override client_id for revision
            latest_revision.client_id = payload.client_id
        
        # 2. Prepare the component DTO with updates
        update_data = payload.component_updates.model_dump(exclude_unset=True)
        
        # Handle position separately as it's a nested Pydantic model
        position_update = {}
        if 'position_x' in update_data:
            position_update['x'] = update_data.pop('position_x')
        if 'position_y' in update_data:
            position_update['y'] = update_data.pop('position_y')
        
        current_component_dict = current_entity.component.model_dump()

        # Merge existing component data with updates
        for key, value in update_data.items():
            if value is not None: # Only update if a new value is provided
                 current_component_dict[key] = value
        
        if position_update:
            if current_component_dict.get('position'):
                current_component_dict['position'].update(position_update)
            else:
                current_component_dict['position'] = position_update # Create PositionDTO if not existing

        updated_component_dto = ProcessGroupDTO(**current_component_dict)

        # 3. Construct the full entity payload for the API
        api_payload = ProcessGroupEntity(
            revision=latest_revision,
            component=updated_component_dto,
            id=payload.process_group_id # NiFi API expects ID in component for PUT sometimes
                                        # but also in path. component.id is often part of the update.
        )
        if api_payload.component: # ensure component is not None
             api_payload.component.id = payload.process_group_id


        updated_pg_entity = await nifi_client.update_process_group(
            pg_id=payload.process_group_id,
            pg_entity_payload=api_payload
        )
        tool_logger.info(f"Successfully updated process group {payload.process_group_id}.")
        return updated_pg_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to update NiFi process group {payload.process_group_id}: {e}")
        raise ToolError(f"Failed to update process group: {e}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in update_nifi_process_group_impl for {payload.process_group_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {e}")


class DeleteProcessGroupPayload(BaseModel):
    process_group_id: str = Field(..., description="The ID of the process group to delete.")
    client_id: Optional[str] = Field(None, description="Optional client ID for the revision. If not provided, the existing one from fetched revision or a NiFi-generated one might be used.")
    disconnected_node_acknowledged: bool = Field(False, description="Acknowledge operation on a disconnected node.")

async def delete_nifi_process_group_impl(
    ctx: Context,
    payload: DeleteProcessGroupPayload
) -> ProcessGroupEntity:
    """
    Deletes a NiFi Process Group.
    Fetches the latest revision internally. Uses query parameters for version/clientId.
    """
    tool_logger.info(f"Tool 'delete_nifi_process_group' called for ID {payload.process_group_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        # 1. Get current entity to obtain the latest revision version
        current_entity = await nifi_client.get_process_group(payload.process_group_id)
        if not current_entity or not current_entity.revision or current_entity.revision.version is None:
            raise ToolError(f"Process Group {payload.process_group_id} not found or has no revision version.")

        version_str = str(current_entity.revision.version)
        # Use client_id from payload if provided, else from fetched entity, else None
        effective_client_id = payload.client_id or current_entity.revision.client_id

        deleted_pg_entity = await nifi_client.delete_process_group(
            pg_id=payload.process_group_id,
            version=version_str,
            client_id=effective_client_id,
            disconnected_node_acknowledged=payload.disconnected_node_acknowledged
        )
        tool_logger.info(f"Successfully deleted process group {payload.process_group_id}.")
        return deleted_pg_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to delete NiFi process group {payload.process_group_id}: {e}")
        raise ToolError(f"Failed to delete process group: {e}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in delete_nifi_process_group_impl for {payload.process_group_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {e}")


async def list_nifi_process_groups_in_group_impl( # NEW Tool Impl
    ctx: Context,
    parent_group_id: str = Field(..., description="The ID of the parent process group for which to list child process groups.")
) -> ProcessGroupsEntity:
    """Lists all direct child process groups within a specified parent process group."""
    tool_logger.info(f"Tool 'list_nifi_process_groups_in_group' called for parent_group_id: {parent_group_id}")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        result_entity = await nifi_client.get_process_groups_in_group(parent_group_id)
        if result_entity is None: # Handles 404 for parent_group_id or no children
            tool_logger.info(f"No child process groups found for parent {parent_group_id} or parent not found.")
            return ProcessGroupsEntity(processGroups=[]) # Return empty list
        return result_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to list child process groups for {parent_group_id}: {e}")
        raise ToolError(f"Failed to list child process groups: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in list_nifi_process_groups_in_group_impl for {parent_group_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")


async def get_nifi_process_group_content_overview_impl( # NEW Master Tool Impl
    ctx: Context,
    process_group_id: str = Field(..., description="The ID of the process group to get an overview of its content (child PGs, processors, connections).")
) -> ProcessGroupContentOverviewDTO:
    """
    Retrieves an overview of the direct content of a specified process group,
    including its child process groups, processors, and connections.
    """
    tool_logger.info(f"Tool 'get_nifi_process_group_content_overview' called for PG ID: {process_group_id}")
    errors_encountered: List[str] = []
    
    # Initialize with default empty values or None
    child_pgs_list_for_dto: Optional[List[ProcessGroupEntity]] = []
    processors_list_for_dto: Optional[List[ProcessorEntity]] = []
    connections_list_for_dto: Optional[List[ConnectionEntity]] = []

    try:
        nifi_client = await get_session_nifi_client(ctx)

        results = await asyncio.gather(
            nifi_client.get_process_groups_in_group(process_group_id),
            nifi_client.get_processors_in_group(process_group_id, include_descendant_groups=False),
            nifi_client.get_connections_in_process_group(process_group_id),
            return_exceptions=True # Allow individual calls to fail without stopping others
        )

        # Process child process groups
        child_pgs_result = results[0]
        if isinstance(child_pgs_result, Exception):
            error_msg = f"Error fetching child process groups: {str(child_pgs_result)}"
            tool_logger.error(error_msg)
            errors_encountered.append(error_msg)
        elif child_pgs_result and child_pgs_result.process_groups:
            # No model_dump needed here if ProcessGroupContentOverviewDTO expects List[ProcessGroupEntity]
            # Pydantic can handle assignment of compatible Pydantic model instances.
            # The issue was likely that the list itself might have been None or the items weren't correctly typed before.
            # If further validation issues occur, this is where .model_dump(by_alias=True) would be used:
            child_pgs_list_for_dto = [pg.model_dump(by_alias=True) for pg in child_pgs_result.process_groups]
            # child_pgs_list_for_dto = child_pgs_result.process_groups


        # Process processors
        processors_result = results[1]
        if isinstance(processors_result, Exception):
            error_msg = f"Error fetching processors: {str(processors_result)}"
            tool_logger.error(error_msg)
            errors_encountered.append(error_msg)
        elif processors_result and processors_result.processors:
            # processors_list_for_dto = [p.model_dump(by_alias=True) for p in processors_result.processors]
            processors_list_for_dto = processors_result.processors


        # Process connections
        connections_result = results[2]
        if isinstance(connections_result, Exception):
            error_msg = f"Error fetching connections: {str(connections_result)}"
            tool_logger.error(error_msg)
            errors_encountered.append(error_msg)
        elif connections_result and connections_result.connections:
            # connections_list_for_dto = [c.model_dump(by_alias=True) for c in connections_result.connections]
            connections_list_for_dto = connections_result.connections

        return ProcessGroupContentOverviewDTO(
            process_group_id=process_group_id,
            child_process_groups=child_pgs_list_for_dto if child_pgs_list_for_dto is not None else [],
            processors=processors_list_for_dto if processors_list_for_dto is not None else [],
            connections=connections_list_for_dto if connections_list_for_dto is not None else [],
            errors=errors_encountered if errors_encountered else None
        )

    except (NiFiAuthException, NiFiApiException) as e: # Catch errors from get_session_nifi_client or initial setup
        tool_logger.error(f"API/Auth error during content overview setup for PG {process_group_id}: {e}")
        # If nifi_client itself fails, we can't proceed.
        raise ToolError(f"Failed to get content overview due to API/Auth issue: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in get_nifi_process_group_content_overview_impl for PG {process_group_id}: {e}")
        # This catches broader issues, potentially before or after the gather call.
        raise ToolError(f"An unexpected error occurred fetching content overview: {str(e)}") from e
# --- Tool Registration ---
# (register_process_group_tools function remains the same, ensuring these _impl functions are registered)

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
    app.tool(name="list_nifi_process_groups_in_group")(list_nifi_process_groups_in_group_impl) # NEW
    app.tool(name="get_nifi_process_group_content_overview")(get_nifi_process_group_content_overview_impl) # NEW
    registration_logger.info("Process Group tools registration complete (partially).") # Update log