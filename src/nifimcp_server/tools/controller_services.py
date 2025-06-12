"""
MCP Tools for interacting with NiFi Controller Services.
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
    ControllerServiceEntity,
    ControllerServicesEntity,
    ControllerServiceTypesEntity,
    ControllerServiceDTO,
    ControllerServiceRunStatusEntity,
    RevisionDTO,
    NiFiApiException,
    NiFiAuthException,
    DocumentedTypeDTO,
)
from ..app import get_session_nifi_client

tool_logger = logging.getLogger(__name__)

# --- Tool Input Models ---

class CreateControllerServiceComponentPayload(BaseModel):
    type: str = Field(..., description="The fully qualified class name of the controller service type (e.g., 'org.apache.nifi.dbcp.DBCPConnectionPool').")
    name: str = Field(..., description="The desired name for the new controller service instance.")
    comments: Optional[str] = Field(None, description="Optional comments for the controller service.")

class CreateControllerServicePayload(BaseModel):
    parent_group_id: str = Field(..., description="The ID of the process group where the controller service will be created.")
    component: CreateControllerServiceComponentPayload
    client_id: Optional[str] = Field(None, description="Optional client ID for the revision.")

class UpdateControllerServiceComponentPayload(BaseModel):
    name: Optional[str] = Field(None, description="New name for the controller service.")
    comments: Optional[str] = Field(None, description="New comments for the controller service.")
    properties: Optional[Dict[str, Optional[str]]] = Field(None, description="Controller service properties to update. Set a value to null or an empty string to clear/reset it.")

class UpdateControllerServicePayload(BaseModel):
    service_id: str = Field(..., description="The ID of the controller service to update.")
    component_updates: UpdateControllerServiceComponentPayload
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node.")

class UpdateControllerServiceRunStatusPayload(BaseModel):
    service_id: str = Field(..., description="The ID of the controller service to enable or disable.")
    state: str = Field(..., description="The desired state ('ENABLED' or 'DISABLED').")
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node.")

class DeleteControllerServicePayload(BaseModel):
    service_id: str = Field(..., description="The ID of the controller service to delete.")
    client_id: Optional[str] = Field(None, description="Client ID for the revision.")
    disconnected_node_acknowledged: Optional[bool] = Field(False, description="Acknowledge operation on a disconnected node.")

# --- Tool Implementations ---

async def create_nifi_controller_service_impl(ctx: Context, payload: CreateControllerServicePayload) -> ControllerServiceEntity:
    """Creates a new NiFi Controller Service within a specified process group."""
    tool_logger.info(f"Tool 'create_nifi_controller_service' called for parent group {payload.parent_group_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        initial_revision = RevisionDTO(clientId=payload.client_id, version=0)
        component_dto = ControllerServiceDTO(
            name=payload.component.name,
            type=payload.component.type,
            comments=payload.component.comments
        )
        api_payload = ControllerServiceEntity(revision=initial_revision, component=component_dto)
        
        created_entity = await nifi_client.create_controller_service(payload.parent_group_id, api_payload)
        tool_logger.info(f"Successfully created controller service '{created_entity.component.name if created_entity.component else 'N/A'}' with ID: {created_entity.id}")
        return created_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to create controller service: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in create_nifi_controller_service_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def get_nifi_controller_service_details_impl(ctx: Context, service_id: str = Field(..., description="The ID of the controller service to retrieve.")) -> Optional[ControllerServiceEntity]:
    """Retrieves the details of a specific NiFi Controller Service by its ID."""
    tool_logger.info(f"Tool 'get_nifi_controller_service_details' called for ID {service_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        service_entity = await nifi_client.get_controller_service(service_id)
        if service_entity is None:
            tool_logger.info(f"Controller Service {service_id} not found.")
            return None
        tool_logger.info(f"Successfully retrieved details for Controller Service {service_id}.")
        return service_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to get controller service details: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in get_nifi_controller_service_details_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def update_nifi_controller_service_impl(ctx: Context, payload: UpdateControllerServicePayload) -> ControllerServiceEntity:
    """Updates an existing NiFi Controller Service. Fetches the latest revision internally."""
    tool_logger.info(f"Tool 'update_nifi_controller_service' called for ID {payload.service_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        current_entity = await nifi_client.get_controller_service(payload.service_id)
        if not current_entity or not current_entity.revision or not current_entity.component:
            raise ToolError(f"Controller Service {payload.service_id} not found or has no revision/component data.")

        latest_revision = current_entity.revision
        if payload.client_id:
            latest_revision.client_id = payload.client_id
        
        updated_component_dto = current_entity.component.model_copy(deep=True)
        update_data = payload.component_updates.model_dump(exclude_unset=True)
        for field_name, value in update_data.items():
            setattr(updated_component_dto, field_name, value)

        api_payload = ControllerServiceEntity(
            revision=latest_revision,
            component=updated_component_dto,
            id=payload.service_id,
            disconnectedNodeAcknowledged=payload.disconnected_node_acknowledged
        )
        if api_payload.component:
            api_payload.component.id = payload.service_id

        updated_entity = await nifi_client.update_controller_service(payload.service_id, api_payload)
        tool_logger.info(f"Successfully updated controller service {payload.service_id}.")
        return updated_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to update controller service: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in update_nifi_controller_service_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def update_nifi_controller_service_run_status_impl(ctx: Context, payload: UpdateControllerServiceRunStatusPayload) -> ControllerServiceEntity:
    """Updates the run status of a Controller Service (enables or disables it)."""
    tool_logger.info(f"Tool 'update_nifi_controller_service_run_status' called for ID {payload.service_id} to state {payload.state}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        current_entity = await nifi_client.get_controller_service(payload.service_id)
        if not current_entity or not current_entity.revision:
            raise ToolError(f"Controller Service {payload.service_id} not found or has no revision.")

        latest_revision = current_entity.revision
        if payload.client_id:
            latest_revision.client_id = payload.client_id
        
        run_status_payload = ControllerServiceRunStatusEntity(
            revision=latest_revision,
            state=payload.state.upper(),
            disconnectedNodeAcknowledged=payload.disconnected_node_acknowledged
        )
        updated_entity = await nifi_client.update_controller_service_run_status(payload.service_id, run_status_payload)
        tool_logger.info(f"Successfully updated run status for controller service {payload.service_id} to {payload.state}.")
        return updated_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to update run status: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in update_nifi_controller_service_run_status_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def delete_nifi_controller_service_impl(ctx: Context, payload: DeleteControllerServicePayload) -> ControllerServiceEntity:
    """Deletes a NiFi Controller Service. Fetches the latest revision internally."""
    tool_logger.info(f"Tool 'delete_nifi_controller_service' called for ID {payload.service_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        current_entity = await nifi_client.get_controller_service(payload.service_id)
        if not current_entity or not current_entity.revision or current_entity.revision.version is None:
            raise ToolError(f"Controller Service {payload.service_id} not found or has no revision version.")

        version_str = str(current_entity.revision.version)
        effective_client_id = payload.client_id or current_entity.revision.client_id

        deleted_entity = await nifi_client.delete_controller_service(
            service_id=payload.service_id,
            version=version_str,
            client_id=effective_client_id,
            disconnected_node_acknowledged=payload.disconnected_node_acknowledged
        )
        tool_logger.info(f"Successfully deleted controller service {payload.service_id}.")
        return deleted_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to delete controller service: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in delete_nifi_controller_service_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def list_nifi_controller_services_in_group_impl(ctx: Context, process_group_id: str = Field(..., description="The ID of the process group for which to list controller services.")) -> ControllerServicesEntity:
    """Lists all controller services within a specified process group."""
    tool_logger.info(f"Tool 'list_nifi_controller_services_in_group' called for PG ID {process_group_id}.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        services_entity = await nifi_client.get_controller_services_in_group(process_group_id)
        if services_entity is None:
            return ControllerServicesEntity(controllerServices=[])
        return services_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to list controller services: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in list_nifi_controller_services_in_group_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

async def list_nifi_available_controller_service_types_impl(ctx: Context) -> ControllerServiceTypesEntity:
    """Retrieves the types of controller services that this NiFi supports."""
    tool_logger.info("Tool 'list_nifi_available_controller_service_types' called.")
    try:
        nifi_client = await get_session_nifi_client(ctx)
        types_entity = await nifi_client.get_available_controller_service_types()
        if types_entity is None:
            return ControllerServiceTypesEntity(controllerServiceTypes=[])
        return types_entity
    except (NiFiAuthException, NiFiApiException) as e:
        raise ToolError(f"Failed to list available controller service types: {e.message if hasattr(e, 'message') else str(e)}") from e
    except Exception as e:
        tool_logger.exception(f"Unexpected error in list_nifi_available_controller_service_types_impl: {e}")
        raise ToolError(f"An unexpected error occurred: {str(e)}")

# --- Tool Registration ---
def register_controller_service_tools(app: FastMCP):
    """Registers controller service tools with the FastMCP app."""
    tool_logger.info("Registering Controller Service tools...")
    app.tool(name="create_nifi_controller_service")(create_nifi_controller_service_impl)
    app.tool(name="get_nifi_controller_service_details")(get_nifi_controller_service_details_impl)
    app.tool(name="update_nifi_controller_service")(update_nifi_controller_service_impl)
    app.tool(name="update_nifi_controller_service_run_status")(update_nifi_controller_service_run_status_impl)
    app.tool(name="delete_nifi_controller_service")(delete_nifi_controller_service_impl)
    app.tool(name="list_nifi_controller_services_in_group")(list_nifi_controller_services_in_group_impl)
    app.tool(name="list_nifi_available_controller_service_types")(list_nifi_available_controller_service_types_impl)
    tool_logger.info("Controller Service tools registration complete.")