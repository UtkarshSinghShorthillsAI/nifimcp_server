"""
MCP Tools for interacting with NiFi Output Ports.
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

class CreateOutputPortComponentPayload(BaseModel):
    name: str = Field(..., description="The name for the new output port.")
    position_x: Optional[float] = Field(None, description="The X coordinate for the port's position on the canvas.")
    position_y: Optional[float] = Field(None, description="The Y coordinate for the port's position on the canvas.")
    comments: Optional[str] = Field(None, description="Optional comments for the output port.")
    allow_remote_access: Optional[bool] = Field(None, description="Whether this port is available for remote access.")

class CreateOutputPortPayload(BaseModel):
    parent_group_id: str = Field(..., description="The ID of the process group where the output port will be created.")
    component: CreateOutputPortComponentPayload
    client_id: Optional[str] = Field(None, description="Optional client ID for the revision.")

class UpdateOutputPortComponentPayload(BaseModel):
    name: Optional[str] = Field(None, description="New name for the output port.")
    position_x: Optional[float] = Field(None, description="New X coordinate for the port's position.")
    position_y: Optional[float] = Field(None, description="New Y coordinate for the port's position.")
    comments: Optional[str] = Field(None, description="New comments for the output port.")
    state: Optional[str] = Field(None, description="New state for the port ('RUNNING', 'STOPPED', 'DISABLED').")
    allow_remote_access: Optional[bool] = Field(None, description="Set whether this port is available for remote access.")
    concurrently_schedulable_task_count: Optional[int] = Field(None, description="New count for concurrently schedulable tasks.")

class UpdateOutputPortPayload(BaseModel):
    port_id: str = Field(..., description="The ID of the output port to update.")
    component_updates: UpdateOutputPortComponentPayload
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node.")

class DeleteOutputPortPayload(BaseModel):
    port_id: str = Field(..., description="The ID of the output port to delete.")
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node.")

# --- Tool Implementations ---

async def create_nifi_output_port_impl(ctx: Context, payload: CreateOutputPortPayload) -> PortEntity:
    """Creates a new NiFi Output Port within a specified process group."""
    tool_logger.info(f"Tool 'create_nifi_output_port' called for parent group {payload.parent_group_id}.")
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
            type='OUTPUT_PORT'
        )
        
        api_payload = PortEntity(revision=initial_revision, component=component_dto)
        
        created_entity = await nifi_client.create_output_port(payload.parent_group_id, api_payload)
        tool_logger.info(f"Successfully created output port '{created_entity.component.name if created_entity.component else 'N/A'}' with ID: {created_entity.id}")
        return created_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to create output port: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in create_nifi_output_port_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def get_nifi_output_port_details_impl(ctx: Context, port_id: str = Field(..., description="The ID of the output port to retrieve.")) -> Optional[PortEntity]:
    """Retrieves the details of a specific NiFi Output Port by its ID."""
    tool_logger.info(f"Tool 'get_nifi_output_port_details' called for ID {port_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        port_entity = await nifi_client.get_output_port(port_id)
        if port_entity is None:
            tool_logger.info(f"Output Port {port_id} not found.")
            return None
        tool_logger.info(f"Successfully retrieved details for Output Port {port_id}.")
        return port_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to get output port details: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in get_nifi_output_port_details_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def update_nifi_output_port_impl(ctx: Context, payload: UpdateOutputPortPayload) -> PortEntity:
    """Updates an existing NiFi Output Port. Fetches the latest revision internally."""
    tool_logger.info(f"Tool 'update_nifi_output_port' called for ID {payload.port_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        current_entity = await nifi_client.get_output_port(payload.port_id)
        if not current_entity or not current_entity.revision or not current_entity.component:
            raise ToolError(f"Output Port {payload.port_id} not found or has no revision/component data.")

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

        updated_entity = await nifi_client.update_output_port(payload.port_id, api_payload)
        tool_logger.info(f"Successfully updated output port {payload.port_id}.")
        return updated_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to update output port: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in update_nifi_output_port_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def delete_nifi_output_port_impl(ctx: Context, payload: DeleteOutputPortPayload) -> PortEntity:
    """Deletes a NiFi Output Port. Fetches the latest revision internally."""
    tool_logger.info(f"Tool 'delete_nifi_output_port' called for ID {payload.port_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        current_entity = await nifi_client.get_output_port(payload.port_id)
        if not current_entity or not current_entity.revision or current_entity.revision.version is None:
            raise ToolError(f"Output Port {payload.port_id} not found or has no revision version.")

        version_str = str(current_entity.revision.version)
        effective_client_id = payload.client_id or current_entity.revision.client_id

        deleted_entity = await nifi_client.delete_output_port(
            port_id=payload.port_id,
            version=version_str,
            client_id=effective_client_id,
            disconnected_node_acknowledged=payload.disconnected_node_acknowledged
        )
        tool_logger.info(f"Successfully deleted output port {payload.port_id}.")
        return deleted_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to delete output port: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in delete_nifi_output_port_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

# --- Tool Registration ---
def register_output_port_tools(app: FastMCP):
    """Registers output port tools with the FastMCP app."""
    tool_logger.info("Registering Output Port tools...")
    app.tool(name="create_nifi_output_port")(create_nifi_output_port_impl)
    app.tool(name="get_nifi_output_port_details")(get_nifi_output_port_details_impl)
    app.tool(name="update_nifi_output_port")(update_nifi_output_port_impl)
    app.tool(name="delete_nifi_output_port")(delete_nifi_output_port_impl)
    tool_logger.info("Output Port tools registration complete.")