"""
MCP Tools for interacting with NiFi Connections.
"""
import logging
from typing import Any, Optional, List, Dict # Added Dict, List

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
    ConnectionEntity,
    ConnectionsEntity, # For listing connections
    RevisionDTO,
    ConnectionDTO,
    ConnectableDTO,
    PositionDTO,
    NiFiApiException,
    NiFiAuthException
)
from ..app import get_session_nifi_client

tool_logger = logging.getLogger(__name__)

# --- Tool Input Models ---

class CreateConnectionConnectablePayload(BaseModel):
    """Specifies the source or destination of a connection."""
    id: str = Field(..., description="ID of the connectable component (processor, port, funnel).")
    type: str = Field(..., description="Type of the connectable component (e.g., 'PROCESSOR', 'INPUT_PORT', 'OUTPUT_PORT', 'FUNNEL', 'REMOTE_INPUT_PORT', 'REMOTE_OUTPUT_PORT'). Case-sensitive, must match NiFi's internal types.")
    group_id: str = Field(..., description="Process group ID of the connectable component.")
    name: Optional[str] = Field(None, description="Optional name of the connectable component (for clarity, NiFi primarily uses ID).")

class CreateConnectionComponentPayload(BaseModel):
    """Details for the 'component' part of a new connection."""
    name: Optional[str] = Field(None, description="Optional name for the connection.")
    source: CreateConnectionConnectablePayload = Field(..., description="The source of the connection.")
    destination: CreateConnectionConnectablePayload = Field(..., description="The destination of the connection.")
    selected_relationships: Optional[List[str]] = Field(None, description="List of relationship names to connect from the source. Required if the source is a processor and has multiple relationships. E.g., ['success', 'failure']")
    bends: Optional[List[PositionDTO]] = Field(None, description="List of bend points (x,y coordinates) for the connection's path on the canvas.")
    label_index: Optional[int] = Field(None, description="The index of the bend point (0-based) where the connection label should be placed.")
    z_index: Optional[int] = Field(None, description="The z-index for the connection, controlling its rendering order.")
    flow_file_expiration: Optional[str] = Field(None, description="The FlowFile expiration period (e.g., '0 sec', '1 hour').")
    back_pressure_object_threshold: Optional[int] = Field(None, description="The back pressure object threshold (number of flowfiles).")
    back_pressure_data_size_threshold: Optional[str] = Field(None, description="The back pressure data size threshold (e.g., '1 GB').")
    load_balance_strategy: Optional[str] = Field(None, description="Load balance strategy (e.g., 'DO_NOT_LOAD_BALANCE', 'ROUND_ROBIN', 'PARTITION_BY_ATTRIBUTE').")
    load_balance_partition_attribute: Optional[str] = Field(None, description="Attribute to use for partitioning if strategy is PARTITION_BY_ATTRIBUTE.")
    load_balance_compression: Optional[str] = Field(None, description="Compression for load balancing (e.g., 'DO_NOT_COMPRESS').")
    prioritizers: Optional[List[str]] = Field(None, description="Fully qualified class names of prioritizers for the connection.")

class CreateConnectionPayload(BaseModel):
    """Payload for creating a new NiFi connection."""
    parent_group_id: str = Field(..., description="ID of the process group where the connection will be created.")
    component: CreateConnectionComponentPayload = Field(..., description="The configuration details for the new connection.")
    client_id: Optional[str] = Field(None, description="Optional client ID for the revision. NiFi will generate one if not provided.")

class UpdateConnectionComponentPayload(BaseModel):
    """Fields that can be updated in a connection's component."""
    name: Optional[str] = Field(None, description="New name for the connection.")
    # Source and Destination are typically immutable for an existing connection.
    # selected_relationships: Optional[List[str]] = Field(None, ...) # Usually not updatable post-creation without recreating
    bends: Optional[List[PositionDTO]] = Field(None, description="New list of bend points (x,y coordinates).")
    label_index: Optional[int] = Field(None, description="New index for the connection label.")
    z_index: Optional[int] = Field(None, description="New z-index for the connection.")
    flow_file_expiration: Optional[str] = Field(None, description="New FlowFile expiration period.")
    back_pressure_object_threshold: Optional[int] = Field(None, description="New back pressure object threshold.")
    back_pressure_data_size_threshold: Optional[str] = Field(None, description="New back pressure data size threshold.")
    load_balance_strategy: Optional[str] = Field(None, description="New load balance strategy.")
    load_balance_partition_attribute: Optional[str] = Field(None, description="New attribute for PARTITION_BY_ATTRIBUTE strategy.")
    load_balance_compression: Optional[str] = Field(None, description="New compression setting for load balancing.")
    prioritizers: Optional[List[str]] = Field(None, description="New list of prioritizer class names.")
    # Add other updatable ConnectionDTO fields as needed

class UpdateConnectionPayload(BaseModel):
    """Payload for updating an existing NiFi connection."""
    connection_id: str = Field(..., description="The ID of the connection to update.")
    component_updates: UpdateConnectionComponentPayload = Field(..., description="The fields to update in the connection's component.")
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node. Defaults to false.")

class DeleteConnectionPayload(BaseModel):
    """Payload for deleting a NiFi connection."""
    connection_id: str = Field(..., description="The ID of the connection to delete.")
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node. Defaults to false.")

# --- Tool Implementations ---

async def create_nifi_connection_impl(
    ctx: Context,
    payload: CreateConnectionPayload
) -> ConnectionEntity:
    """
    Creates a new NiFi Connection within a specified parent process group.
    """
    tool_logger.info(f"Tool 'create_nifi_connection' called for parent group {payload.parent_group_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        initial_revision = RevisionDTO(clientId=payload.client_id, version=0)
        
        comp_payload = payload.component

        source_connectable = ConnectableDTO(
            id=comp_payload.source.id,
            type=comp_payload.source.type.upper(), # NiFi types are typically uppercase
            groupId=comp_payload.source.group_id,
            name=comp_payload.source.name
        )
        destination_connectable = ConnectableDTO(
            id=comp_payload.destination.id,
            type=comp_payload.destination.type.upper(), # NiFi types are typically uppercase
            groupId=comp_payload.destination.group_id,
            name=comp_payload.destination.name
        )

        connection_component_dto = ConnectionDTO(
            name=comp_payload.name,
            source=source_connectable,
            destination=destination_connectable,
            selectedRelationships=comp_payload.selected_relationships,
            bends=comp_payload.bends,
            labelIndex=comp_payload.label_index,
            zIndex=comp_payload.z_index,
            flowFileExpiration=comp_payload.flow_file_expiration,
            backPressureObjectThreshold=comp_payload.back_pressure_object_threshold,
            backPressureDataSizeThreshold=comp_payload.back_pressure_data_size_threshold,
            loadBalanceStrategy=comp_payload.load_balance_strategy,
            loadBalancePartitionAttribute=comp_payload.load_balance_partition_attribute,
            loadBalanceCompression=comp_payload.load_balance_compression,
            prioritizers=comp_payload.prioritizers,
            parentGroupId=payload.parent_group_id # Important for context
        )
        
        api_payload = ConnectionEntity(
            revision=initial_revision,
            component=connection_component_dto
        )
        # The API doc suggests ConnectionEntity also has sourceId, destinationId etc. at top level for POST response,
        # but for request, they are usually derived from component.source/destination.
        # We'll let NiFi populate those on the response.

        created_connection_entity = await nifi_client.create_connection(
            parent_group_id=payload.parent_group_id,
            connection_entity_payload=api_payload
        )
        tool_logger.info(f"Successfully created connection '{created_connection_entity.component.name if created_connection_entity.component else 'N/A'}' with ID: {created_connection_entity.id}")
        return created_connection_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to create NiFi connection in group {payload.parent_group_id}: {e}")
        raise ToolError(f"Failed to create connection: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in create_nifi_connection_impl for parent group {payload.parent_group_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def get_nifi_connection_details_impl(
    ctx: Context,
    connection_id: str = Field(..., description="The ID of the connection to retrieve.")
) -> Optional[ConnectionEntity]:
    """
    Retrieves the details of a specific NiFi Connection by its ID.
    """
    tool_logger.info(f"Tool 'get_nifi_connection_details' called for ID {connection_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        connection_entity = await nifi_client.get_connection(connection_id)

        if connection_entity is None:
            tool_logger.info(f"Connection {connection_id} not found.")
            return None
        else:
            tool_logger.info(f"Successfully retrieved details for Connection {connection_id}.")
            return connection_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to get NiFi connection details for {connection_id}: {e}")
        raise ToolError(f"Failed to get connection details: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in get_nifi_connection_details_impl for {connection_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def update_nifi_connection_impl(
    ctx: Context,
    payload: UpdateConnectionPayload
) -> ConnectionEntity:
    """
    Updates an existing NiFi Connection. Fetches the latest revision internally.
    Note: Source and Destination of a connection are typically immutable.
    """
    tool_logger.info(f"Tool 'update_nifi_connection' called for ID {payload.connection_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        current_entity = await nifi_client.get_connection(payload.connection_id)
        if not current_entity or not current_entity.revision or not current_entity.component:
            raise ToolError(f"Connection {payload.connection_id} not found or has no revision/component data for update.")

        latest_revision = current_entity.revision
        if payload.client_id is not None:
            latest_revision.client_id = payload.client_id
        
        updated_component_dto = current_entity.component.model_copy(deep=True)
        
        # Apply updates from payload.component_updates
        # Only update fields that are actually provided in the payload
        update_data = payload.component_updates.model_dump(exclude_unset=True)
        for field_name, value in update_data.items():
            if hasattr(updated_component_dto, field_name): # Check if attribute exists
                setattr(updated_component_dto, field_name, value)
            else:
                tool_logger.warning(f"Field '{field_name}' not found on ConnectionDTO during update. Skipping.")

        api_payload = ConnectionEntity(
            revision=latest_revision,
            component=updated_component_dto,
            id=payload.connection_id, # Keep ID in the entity
            disconnectedNodeAcknowledged=payload.disconnected_node_acknowledged
        )
        if api_payload.component: # Should be true
             api_payload.component.id = payload.connection_id


        updated_connection_entity = await nifi_client.update_connection(
            connection_id=payload.connection_id,
            connection_entity_payload=api_payload
        )
        tool_logger.info(f"Successfully updated connection {payload.connection_id}.")
        return updated_connection_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to update NiFi connection {payload.connection_id}: {e}")
        raise ToolError(f"Failed to update connection: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in update_nifi_connection_impl for {payload.connection_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def delete_nifi_connection_impl(
    ctx: Context,
    payload: DeleteConnectionPayload
) -> ConnectionEntity:
    """
    Deletes a NiFi Connection. Fetches the latest revision internally.
    """
    tool_logger.info(f"Tool 'delete_nifi_connection' called for ID {payload.connection_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)

        current_entity = await nifi_client.get_connection(payload.connection_id)
        if not current_entity:
            raise ToolError(f"Connection {payload.connection_id} not found, cannot delete.")
        if not current_entity.revision or current_entity.revision.version is None:
            raise ToolError(f"Connection {payload.connection_id} has no revision version, cannot delete.")

        version_str = str(current_entity.revision.version)
        effective_client_id = payload.client_id or current_entity.revision.client_id

        deleted_connection_entity = await nifi_client.delete_connection(
            connection_id=payload.connection_id,
            version=version_str,
            client_id=effective_client_id,
            disconnected_node_acknowledged=payload.disconnected_node_acknowledged or False
        )
        tool_logger.info(f"Successfully deleted connection {payload.connection_id}.")
        return deleted_connection_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to delete NiFi connection {payload.connection_id}: {e}")
        raise ToolError(f"Failed to delete connection: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in delete_nifi_connection_impl for {payload.connection_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def list_nifi_connections_in_group_impl(
    ctx: Context,
    process_group_id: str = Field(..., description="The ID of the process group for which to list connections.")
) -> ConnectionsEntity:
    """
    Lists all connections within a specified process group.
    """
    tool_logger.info(f"Tool 'list_nifi_connections_in_group' called for PG ID {process_group_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        connections_entity = await nifi_client.get_connections_in_process_group(process_group_id)
        if connections_entity is None: # Should not happen if allow_404=True used in client and PG exists
            tool_logger.warning(f"No connections entity returned for PG {process_group_id}, or PG not found.")
            return ConnectionsEntity(connections=[]) # Return empty list if PG not found or no connections
        tool_logger.info(f"Successfully listed connections for PG {process_group_id}.")
        return connections_entity
    except (NiFiAuthException, NiFiApiException) as e:
        tool_logger.error(f"Failed to list connections for PG {process_group_id}: {e}")
        raise ToolError(f"Failed to list connections: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in list_nifi_connections_in_group_impl for PG {process_group_id}: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")


# --- Tool Registration ---
def register_connection_tools(app: FastMCP):
    tool_logger.info("Registering Connection tools...")
    app.tool(name="create_nifi_connection")(create_nifi_connection_impl)
    app.tool(name="get_nifi_connection_details")(get_nifi_connection_details_impl)
    app.tool(name="update_nifi_connection")(update_nifi_connection_impl)
    app.tool(name="delete_nifi_connection")(delete_nifi_connection_impl)
    app.tool(name="list_nifi_connections_in_group")(list_nifi_connections_in_group_impl) # NEW TOOL
    tool_logger.info("Connection tools registration complete.")