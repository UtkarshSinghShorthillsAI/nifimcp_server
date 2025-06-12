"""
MCP Tools for interacting with NiFi Input Ports.
"""
import logging
from typing import Any, Optional, List

from fastmcp import FastMCP, Context
try:
    from fastmcp.exceptions import ToolError
except ImportError:
    class ToolError(Exception): pass
from pydantic import BaseModel, Field

from ..nifi_models import (
    PortEntity,
    RevisionDTO,
    PortDTO,
    PositionDTO,
    NiFiApiException,
    NiFiAuthException,
)
from ..app import get_session_nifi_client

tool_logger = logging.getLogger(__name__)

# --- Tool Input Models ---

class CreateInputPortComponentPayload(BaseModel):
    name: str = Field(..., description="The name for the new input port.")
    position_x: Optional[float] = Field(None, description="The X coordinate for the port's position on the canvas.")
    position_y: Optional[float] = Field(None, description="The Y coordinate for the port's position on the canvas.")
    comments: Optional[str] = Field(None, description="Optional comments for the input port.")
    allow_remote_access: Optional[bool] = Field(None, description="Whether this port is available for remote access.")

class CreateInputPortPayload(BaseModel):
    parent_group_id: str = Field(..., description="The ID of the process group where the input port will be created.")
    component: CreateInputPortComponentPayload
    client_id: Optional[str] = Field(None, description="Optional client ID for the revision.")

class UpdateInputPortComponentPayload(BaseModel):
    name: Optional[str] = Field(None, description="New name for the input port.")
    position_x: Optional[float] = Field(None, description="New X coordinate for the port's position.")
    position_y: Optional[float] = Field(None, description="New Y coordinate for the port's position.")
    comments: Optional[str] = Field(None, description="New comments for the input port.")
    state: Optional[str] = Field(None, description="New state for the port ('RUNNING', 'STOPPED', 'DISABLED').")
    allow_remote_access: Optional[bool] = Field(None, description="Set whether this port is available for remote access.")
    concurrently_schedulable_task_count: Optional[int] = Field(None, description="New count for concurrently schedulable tasks.")

class UpdateInputPortPayload(BaseModel):
    port_id: str = Field(..., description="The ID of the input port to update.")
    component_updates: UpdateInputPortComponentPayload
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node.")

class DeleteInputPortPayload(BaseModel):
    port_id: str = Field(..., description="The ID of the input port to delete.")
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node.")

# --- Tool Implementations ---

async def create_nifi_input_port_impl(ctx: Context, payload: CreateInputPortPayload) -> PortEntity:
    """Creates a new NiFi Input Port within a specified process group."""
    tool_logger.info(f"Tool 'create_nifi_input_port' called for parent group {payload.parent_group_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        initial_revision = RevisionDTO(clientId=payload.client_id, version=0)
        
        position = None
        if payload.component.position_x is not None and payload.component.position_y is not None:
            position = PositionDTO(x=payload.component.position_x, y=payload.component.position_y)
        
        component_dto = PortDTO(
            name=payload.component.name,
            position=position,
            comments=payload.component.comments,
            allowRemoteAccess=payload.component.allow_remote_access,
            type='INPUT_PORT'
        )
        
        api_payload = PortEntity(revision=initial_revision, component=component_dto)
        
        created_entity = await nifi_client.create_input_port(payload.parent_group_id, api_payload)
        tool_logger.info(f"Successfully created input port '{created_entity.component.name if created_entity.component else 'N/A'}' with ID: {created_entity.id}")
        return created_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to create input port: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in create_nifi_input_port_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def get_nifi_input_port_details_impl(ctx: Context, port_id: str = Field(..., description="The ID of the input port to retrieve.")) -> Optional[PortEntity]:
    """Retrieves the details of a specific NiFi Input Port by its ID."""
    tool_logger.info(f"Tool 'get_nifi_input_port_details' called for ID {port_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        port_entity = await nifi_client.get_input_port(port_id)
        if port_entity is None:
            tool_logger.info(f"Input Port {port_id} not found.")
            return None
        tool_logger.info(f"Successfully retrieved details for Input Port {port_id}.")
        return port_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to get input port details: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in get_nifi_input_port_details_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def update_nifi_input_port_impl(ctx: Context, payload: UpdateInputPortPayload) -> PortEntity:
    """Updates an existing NiFi Input Port. Fetches the latest revision internally."""
    tool_logger.info(f"Tool 'update_nifi_input_port' called for ID {payload.port_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        current_entity = await nifi_client.get_input_port(payload.port_id)
        if not current_entity or not current_entity.revision or not current_entity.component:
            raise ToolError(f"Input Port {payload.port_id} not found or has no revision/component data.")

        latest_revision = current_entity.revision
        if payload.client_id:
            latest_revision.client_id = payload.client_id

        updated_component_dto = current_entity.component.model_copy(deep=True)
        update_data = payload.component_updates.model_dump(exclude_unset=True)

        position_update = {}
        if 'position_x' in update_data: position_update['x'] = update_data.pop('position_x')
        if 'position_y' in update_data: position_update['y'] = update_data.pop('position_y')
        
        for field, value in update_data.items():
            setattr(updated_component_dto, field, value)
        
        if position_update:
            if updated_component_dto.position: updated_component_dto.position.model_dump().update(position_update)
            else: updated_component_dto.position = PositionDTO(**position_update)

        api_payload = PortEntity(
            revision=latest_revision,
            component=updated_component_dto,
            id=payload.port_id,
            disconnectedNodeAcknowledged=payload.disconnected_node_acknowledged
        )
        if api_payload.component: api_payload.component.id = payload.port_id

        updated_entity = await nifi_client.update_input_port(payload.port_id, api_payload)
        tool_logger.info(f"Successfully updated input port {payload.port_id}.")
        return updated_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to update input port: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in update_nifi_input_port_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def delete_nifi_input_port_impl(ctx: Context, payload: DeleteInputPortPayload) -> PortEntity:
    """Deletes a NiFi Input Port. Fetches the latest revision internally."""
    tool_logger.info(f"Tool 'delete_nifi_input_port' called for ID {payload.port_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        current_entity = await nifi_client.get_input_port(payload.port_id)
        if not current_entity or not current_entity.revision or current_entity.revision.version is None:
            raise ToolError(f"Input Port {payload.port_id} not found or has no revision version.")

        version_str = str(current_entity.revision.version)
        effective_client_id = payload.client_id or current_entity.revision.client_id

        deleted_entity = await nifi_client.delete_input_port(
            port_id=payload.port_id,
            version=version_str,
            client_id=effective_client_id,
            disconnected_node_acknowledged=payload.disconnected_node_acknowledged
        )
        tool_logger.info(f"Successfully deleted input port {payload.port_id}.")
        return deleted_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to delete input port: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in delete_nifi_input_port_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

# --- Tool Registration ---
def register_input_port_tools(app: FastMCP):
    """Registers input port tools with the FastMCP app."""
    tool_logger.info("Registering Input Port tools...")
    app.tool(name="create_nifi_input_port")(create_nifi_input_port_impl)
    app.tool(name="get_nifi_input_port_details")(get_nifi_input_port_details_impl)
    app.tool(name="update_nifi_input_port")(update_nifi_input_port_impl)
    app.tool(name="delete_nifi_input_port")(delete_nifi_input_port_impl)
    tool_logger.info("Input Port tools registration complete.")