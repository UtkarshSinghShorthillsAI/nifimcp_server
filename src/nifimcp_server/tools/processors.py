"""
MCP Tools for interacting with NiFi Processors.
"""
import logging
from typing import Any, Optional, Dict, List

from fastmcp import FastMCP, Context
# Ensure fastmcp.exceptions.ToolError is the correct import path, or use a general Exception
try:
    from fastmcp.exceptions import ToolError
except ImportError:
    class ToolError(Exception): # Fallback if specific ToolError not in this version of fastmcp
        pass
from pydantic import BaseModel, Field

# Import all necessary models from your nifi_models.py
from ..nifi_models import (
    ProcessorEntity,
    RevisionDTO,
    ProcessorDTO,
    # BundleDTO, # Only if directly manipulated by tool user, usually part of ProcessorDTO's type
    PositionDTO,
    ProcessorConfigDTO, # For detailed config updates within ProcessorDTO
    ProcessorRunStatusEntity, # For updating run status
    NiFiApiException,
    NiFiAuthException,
    ProcessorsEntity, # NEW
)
from ..app import get_session_nifi_client

tool_logger = logging.getLogger(__name__)

# --- Tool Input Models ---

class CreateProcessorComponentPayload(BaseModel):
    type: str = Field(..., description="The fully qualified class name of the processor type (e.g., org.apache.nifi.processors.standard.GenerateFlowFile).")
    name: str = Field(..., description="The desired name for the new processor instance.")
    position_x: Optional[float] = Field(None, description="The X coordinate for the processor's position on the canvas.")
    position_y: Optional[float] = Field(None, description="The Y coordinate for the processor's position on the canvas.")
    # Optional: Add other simple fields from ProcessorDTO or ProcessorConfigDTO if frequently set during creation by LLM
    # e.g., comments: Optional[str] = None
    # e.g., scheduling_period: Optional[str] = None
    # e.g., scheduling_strategy: Optional[str] = None

class CreateProcessorPayload(BaseModel):
    parent_group_id: str = Field(..., description="The ID of the process group where the new processor will be created.")
    component: CreateProcessorComponentPayload = Field(description="Details of the processor to create.")
    client_id: Optional[str] = Field(None, description="Optional client ID for the revision. If not provided, NiFi may generate one.")

class UpdateProcessorComponentConfigPayload(BaseModel):
    properties: Optional[Dict[str, Optional[str]]] = Field(None, description="Processor properties to update. Set a property value to null (if field is Optional[str]) or an empty string to clear/reset it, depending on NiFi's behavior for that property.")
    scheduling_period: Optional[str] = Field(None, description="New scheduling period (e.g., '0 sec').")
    scheduling_strategy: Optional[str] = Field(None, description="New scheduling strategy (e.g., 'TIMER_DRIVEN', 'CRON_DRIVEN').")
    penalty_duration: Optional[str] = Field(None, description="New penalty duration (e.g., '30 sec').")
    yield_duration: Optional[str] = Field(None, description="New yield duration (e.g., '1 sec').")
    bulletin_level: Optional[str] = Field(None, description="New bulletin level (e.g., 'WARN', 'INFO').")
    run_duration_millis: Optional[int] = Field(None, description="New run duration in milliseconds.")
    concurrently_schedulable_task_count: Optional[int] = Field(None, description="New count for concurrently schedulable tasks.")
    comments: Optional[str] = Field(None, description="New comments for the processor configuration.") # This is config.comments
    auto_terminated_relationships: Optional[List[str]] = Field(None, description="List of relationship names to auto-terminate.")

class UpdateProcessorComponentPayload(BaseModel):
    name: Optional[str] = Field(None, description="New name for the processor.")
    position_x: Optional[float] = Field(None, description="New X coordinate for the processor's position.")
    position_y: Optional[float] = Field(None, description="New Y coordinate for the processor's position.")
    config: Optional[UpdateProcessorComponentConfigPayload] = Field(None, description="Configuration updates for the processor.")
    comments: Optional[str] = Field(None, description="New comments for the processor component itself (component.comments).")

class UpdateProcessorPayload(BaseModel):
    processor_id: str = Field(..., description="The ID of the processor to update.")
    component_updates: UpdateProcessorComponentPayload = Field(description="The fields to update in the processor's component.")
    client_id: Optional[str] = Field(None, description="Client ID for the revision. If not provided, NiFi may use the one from the fetched revision or generate one.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node. Defaults to false.")

class DeleteProcessorPayload(BaseModel):
    processor_id: str = Field(..., description="The ID of the processor to delete.")
    client_id: Optional[str] = Field(None, description="Client ID for the revision. If not provided, NiFi may use the one from the fetched revision or generate one.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node. Defaults to false.")

class UpdateProcessorRunStatusPayload(BaseModel):
    processor_id: str = Field(..., description="The ID of the processor whose run status is to be updated.")
    state: str = Field(..., description="The desired run status (e.g., 'RUNNING', 'STOPPED', 'DISABLED').")
    client_id: Optional[str] = Field(None, description="Client ID for the revision. If not provided, NiFi may use the one from the fetched revision or generate one.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node. Defaults to false.")


# --- Tool Implementations ---

async def create_nifi_processor_impl(
    ctx: Context,
    payload: CreateProcessorPayload
) -> ProcessorEntity:
    """
    Creates a new NiFi Processor within a specified parent process group.
    """
    tool_logger.info(f"Tool 'create_nifi_processor' called for parent group {payload.parent_group_id} with name '{payload.component.name}'.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        initial_revision = RevisionDTO(clientId=payload.client_id, version=0)
        
        component_data = payload.component
        
        processor_position = None
        if component_data.position_x is not None and component_data.position_y is not None:
            processor_position = PositionDTO(x=component_data.position_x, y=component_data.position_y)

        processor_component_dto = ProcessorDTO(
            name=component_data.name,
            type=component_data.type,
            position=processor_position
        )
        
        api_payload = ProcessorEntity(
            revision=initial_revision,
            component=processor_component_dto
        )

        created_processor_entity = await nifi_client.create_processor(
            parent_group_id=payload.parent_group_id,
            processor_entity_payload=api_payload
        )
        tool_logger.info(f"Successfully created processor '{created_processor_entity.component.name if created_processor_entity.component else 'N/A'}' with ID: {created_processor_entity.id}")
        return created_processor_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to create NiFi processor in group {payload.parent_group_id}: {e}")
        raise ToolError(f"Failed to create processor: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in create_nifi_processor_impl for parent group {payload.parent_group_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")


async def get_nifi_processor_details_impl(
    ctx: Context,
    processor_id: str = Field(..., description="The ID of the processor to retrieve.")
) -> Optional[ProcessorEntity]:
    """
    Retrieves the details of a specific NiFi Processor by its ID.
    """
    tool_logger.info(f"Tool 'get_nifi_processor_details' called for ID {processor_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        processor_entity = await nifi_client.get_processor(processor_id)

        if processor_entity is None:
            tool_logger.info(f"Processor {processor_id} not found.")
            return None
        else:
            tool_logger.info(f"Successfully retrieved details for Processor {processor_id}.")
            return processor_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to get NiFi processor details for {processor_id}: {e}")
        raise ToolError(f"Failed to get processor details: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in get_nifi_processor_details_impl for {processor_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def update_nifi_processor_impl(
    ctx: Context,
    payload: UpdateProcessorPayload
) -> ProcessorEntity:
    """
    Updates an existing NiFi Processor. Fetches the latest revision internally.
    """
    tool_logger.info(f"Tool 'update_nifi_processor' called for ID {payload.processor_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        current_entity = await nifi_client.get_processor(payload.processor_id)
        if not current_entity or not current_entity.revision or not current_entity.component:
            raise ToolError(f"Processor {payload.processor_id} not found or has no revision/component data for update.")

        latest_revision = current_entity.revision
        if payload.client_id is not None: # Only override if provided
            latest_revision.client_id = payload.client_id
        
        updated_component_dto = current_entity.component.model_copy(deep=True)

        if payload.component_updates.name is not None:
            updated_component_dto.name = payload.component_updates.name
        
        if payload.component_updates.position_x is not None or payload.component_updates.position_y is not None:
            if updated_component_dto.position is None:
                updated_component_dto.position = PositionDTO()
            if payload.component_updates.position_x is not None:
                updated_component_dto.position.x = payload.component_updates.position_x
            if payload.component_updates.position_y is not None:
                updated_component_dto.position.y = payload.component_updates.position_y

        if payload.component_updates.config:
            if updated_component_dto.config is None:
                updated_component_dto.config = ProcessorConfigDTO()
            
            config_updates_payload = payload.component_updates.config
            # Iterate through defined fields in UpdateProcessorComponentConfigPayload to apply updates
            for field_name, value in config_updates_payload.model_dump(exclude_unset=True).items():
                setattr(updated_component_dto.config, field_name, value)
        
        if payload.component_updates.comments is not None:
            updated_component_dto.comments = payload.component_updates.comments
            
        api_payload = ProcessorEntity(
            revision=latest_revision,
            component=updated_component_dto,
            id=payload.processor_id,
            disconnectedNodeAcknowledged=payload.disconnected_node_acknowledged
        )
        if api_payload.component:
             api_payload.component.id = payload.processor_id

        updated_processor_entity = await nifi_client.update_processor(
            processor_id=payload.processor_id,
            processor_entity_payload=api_payload
        )
        tool_logger.info(f"Successfully updated processor {payload.processor_id}.")
        return updated_processor_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to update NiFi processor {payload.processor_id}: {e}")
        raise ToolError(f"Failed to update processor: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in update_nifi_processor_impl for {payload.processor_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")


async def delete_nifi_processor_impl(
    ctx: Context,
    payload: DeleteProcessorPayload
) -> ProcessorEntity:
    """
    Deletes a NiFi Processor. Fetches the latest revision internally.
    """
    tool_logger.info(f"Tool 'delete_nifi_processor' called for ID {payload.processor_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        current_entity = await nifi_client.get_processor(payload.processor_id)
        if not current_entity: # If processor not found, consider it "deleted" or non-existent
            tool_logger.info(f"Processor {payload.processor_id} not found, cannot delete.")
            # Depending on desired behavior, could return None or raise a specific ToolError
            # For now, let's be strict and require it to exist to be deleted.
            raise ToolError(f"Processor {payload.processor_id} not found, cannot delete.")
        if not current_entity.revision or current_entity.revision.version is None:
            raise ToolError(f"Processor {payload.processor_id} has no revision version, cannot delete.")

        version_str = str(current_entity.revision.version)
        effective_client_id = payload.client_id or current_entity.revision.client_id

        deleted_processor_entity = await nifi_client.delete_processor(
            processor_id=payload.processor_id,
            version=version_str,
            client_id=effective_client_id,
            disconnected_node_acknowledged=payload.disconnected_node_acknowledged or False # Ensure bool
        )
        tool_logger.info(f"Successfully deleted processor {payload.processor_id}.")
        return deleted_processor_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to delete NiFi processor {payload.processor_id}: {e}")
        raise ToolError(f"Failed to delete processor: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in delete_nifi_processor_impl for {payload.processor_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def update_nifi_processor_run_status_impl(
    ctx: Context,
    payload: UpdateProcessorRunStatusPayload
) -> ProcessorEntity:
    """
    Updates the run status of a NiFi Processor (e.g., starts, stops, or disables it).
    """
    tool_logger.info(f"Tool 'update_nifi_processor_run_status' called for ID {payload.processor_id} to state {payload.state}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        current_entity = await nifi_client.get_processor(payload.processor_id)
        if not current_entity or not current_entity.revision:
            raise ToolError(f"Processor {payload.processor_id} not found or has no revision for run status update.")

        latest_revision = current_entity.revision
        if payload.client_id is not None:
            latest_revision.client_id = payload.client_id
        
        run_status_payload = ProcessorRunStatusEntity(
            revision=latest_revision,
            state=payload.state.upper(), 
            disconnectedNodeAcknowledged=payload.disconnected_node_acknowledged or False # Ensure bool
        )

        updated_processor_entity = await nifi_client.update_processor_run_status(
            processor_id=payload.processor_id,
            run_status_entity=run_status_payload
        )
        tool_logger.info(f"Successfully updated run status for processor {payload.processor_id} to {payload.state}.")
        return updated_processor_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to update run status for NiFi processor {payload.processor_id}: {e}")
        raise ToolError(f"Failed to update processor run status: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in update_nifi_processor_run_status_impl for {payload.processor_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def list_nifi_processors_in_group_impl( # NEW Tool Impl
    ctx: Context,
    process_group_id: str = Field(..., description="The ID of the process group for which to list processors."),
    include_descendants: bool = Field(False, description="Whether to include processors from all descendant process groups.")
) -> ProcessorsEntity:
    """Lists all processors within a specified process group."""
    tool_logger.info(f"Tool 'list_nifi_processors_in_group' called for PG ID {process_group_id}, include_descendants: {include_descendants}")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        result_entity = await nifi_client.get_processors_in_group(process_group_id, include_descendant_groups=include_descendants)
        
        if result_entity is None: # Handles 404 for process_group_id or no processors
            tool_logger.info(f"No processors found for PG {process_group_id} (include_descendants={include_descendants}) or PG not found.")
            return ProcessorsEntity(processors=[]) # Return empty list
        return result_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to list processors for PG {process_group_id}: {e}")
        raise ToolError(f"Failed to list processors: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in list_nifi_processors_in_group_impl for PG {process_group_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")
    
# --- Tool Registration ---
def register_processor_tools(app: FastMCP):
    tool_logger.info("Registering Processor tools...")
    app.tool(name="create_nifi_processor")(create_nifi_processor_impl)
    app.tool(name="get_nifi_processor_details")(get_nifi_processor_details_impl)
    app.tool(name="update_nifi_processor")(update_nifi_processor_impl)
    app.tool(name="delete_nifi_processor")(delete_nifi_processor_impl)
    app.tool(name="update_nifi_processor_run_status")(update_nifi_processor_run_status_impl)
    app.tool(name="list_nifi_processors_in_group")(list_nifi_processors_in_group_impl) # NEW
    tool_logger.info("Processor tools registration complete.")