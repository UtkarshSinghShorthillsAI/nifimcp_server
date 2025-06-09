"""
MCP Tools for interacting with general NiFi Flow and System-Level endpoints.
"""
import logging
from typing import Any, Optional, List, Dict

from fastmcp import FastMCP, Context
try:
    from fastmcp.exceptions import ToolError
except ImportError:
    class ToolError(Exception): pass
from pydantic import BaseModel, Field

from ..nifi_models import (
    ProcessorTypesEntity, # For the tool's return type
    NiFiApiException,
    NiFiAuthException
)
from ..app import get_session_nifi_client

tool_logger = logging.getLogger(__name__)
registration_logger = logging.getLogger(__name__ + ".registration")

# --- Tool Input Models ---

class ListAvailableProcessorTypesPayload(BaseModel):
    """Payload for listing available NiFi processor types with optional filters."""
    bundle_group_filter: Optional[str] = Field(None, alias="bundleGroupFilter", description="If specified, will only return types that are a member of this bundle group (e.g., 'org.apache.nifi').")
    bundle_artifact_filter: Optional[str] = Field(None, alias="bundleArtifactFilter", description="If specified, will only return types that are a member of this bundle artifact (e.g., 'nifi-standard-nar').")
    type_filter: Optional[str] = Field(None, alias="type", description="If specified, will only return types whose fully qualified classname matches this filter (e.g., 'org.apache.nifi.processors.standard.GenerateFlowFile').")

# --- Tool Implementations ---

async def list_nifi_available_processor_types_impl(
    ctx: Context,
    payload: ListAvailableProcessorTypesPayload
) -> ProcessorTypesEntity:
    """
    Retrieves the types of processors that this NiFi supports, with optional filters.
    """
    tool_logger.info(f"Tool 'list_nifi_available_processor_types' called with payload: {payload.model_dump_json(by_alias=True, exclude_none=True)}")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        
        processor_types_entity = await nifi_client.get_available_processor_types(
            bundle_group_filter=payload.bundle_group_filter,
            bundle_artifact_filter=payload.bundle_artifact_filter,
            type_filter=payload.type_filter
        )

        if processor_types_entity is None:
            tool_logger.info("No processor types returned from API client, returning empty list.")
            return ProcessorTypesEntity(processorTypes=[])
        
        count = len(processor_types_entity.processor_types) if processor_types_entity.processor_types else 0
        tool_logger.info(f"Successfully retrieved {count} available processor types.")
        return processor_types_entity

    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to list available NiFi processor types: {e}")
        raise ToolError(f"Failed to list available processor types: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in list_nifi_available_processor_types_impl: {e}")
        raise ToolError(f"An unexpected error occurred while listing processor types: {str(e)}")


# --- Tool Registration ---
def register_flow_tools(app: FastMCP):
    """Registers flow-related tools with the FastMCP app."""
    registration_logger.info("Registering Flow tools...")
    app.tool(name="list_nifi_available_processor_types")(list_nifi_available_processor_types_impl)
    registration_logger.info("Flow tools registration complete.")