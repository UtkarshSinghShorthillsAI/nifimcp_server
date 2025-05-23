"""
NiFi API Client Module

This module provides the NiFiApiClient class, which is responsible for all
direct communication with the NiFi REST API. It handles HTTP requests,
authentication, and NiFi-specific API details like revision management
(though revision logic itself is largely handled by the tool functions).
"""

import httpx
import logging
from typing import Any, Dict, Optional, Union, Type, TypeVar

from pydantic import BaseModel, ValidationError

# Import from nifi_models - ensure all necessary types are listed
from .nifi_models import (
    NiFiAuthException,
    NiFiApiException,
    AuthenticationConfigurationEntity,
    ProcessGroupEntity,
    ProcessorEntity, 
    ProcessorStatusDTO, 
    ProcessorRunStatusEntity,
    ConnectionEntity,
    PortEntity,
    RevisionDTO,
    # For other processor endpoints, to be added as needed
    ConfigurationAnalysisEntity,
    ComponentStateEntity,
    PropertyDescriptorEntity,
    VerifyConfigRequestEntity,
    ProcessorsRunStatusDetailsEntity,
    RunStatusDetailsRequestEntity,
    ConnectionsEntity,             # NEW
    ConnectionStatusEntity,        # NEW
    StatusHistoryEntity,           # NEW
    ConnectionStatisticsEntity,    # NEW
    ProcessGroupsEntity,           # NEW
    ProcessorsEntity,              # NEW
)

# Initialize a logger for this module
nifi_client_logger = logging.getLogger(__name__)

# Generic type for Pydantic models used in response parsing
ResponseType = TypeVar("ResponseType", bound=BaseModel)

class NiFiApiClient:
    """
    An asynchronous client for interacting with the Apache NiFi REST API.
    """

    def __init__(
        self,
        base_url: str,
        httpx_client: httpx.AsyncClient, # This client instance holds config like ssl verification
        token: Optional[str] = None,
    ):
        """
        Initializes the NiFiApiClient.

        Args:
            base_url: The base URL of the NiFi API (e.g., "http://localhost:8080/nifi-api").
            httpx_client: An instance of httpx.AsyncClient for making requests.
            token: An optional pre-existing JWT to use for authentication.
        """
        if not base_url.endswith('/'):
            base_url += '/'
        self._base_url: str = base_url
        self._httpx_client: httpx.AsyncClient = httpx_client
        self._token: Optional[str] = token
        self._user_agent: str = "NiFiMCP Server/1.0" # TODO: Make version dynamic if needed

    @classmethod
    async def create(
        cls,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        existing_token: Optional[str] = None,
        # Allow passing a pre-configured client, useful for testing or custom configs
        external_httpx_client: Optional[httpx.AsyncClient] = None,
        ssl_verify: bool = True
    ) -> "NiFiApiClient":
        """
        Factory method to create and authenticate a NiFiApiClient instance.
        """
        httpx_client_config = {"verify": ssl_verify}
        if not ssl_verify:
             nifi_client_logger.warning("SSL certificate verification is DISABLED for NiFi API client.")

        token: Optional[str] = None
        temp_auth_client_created = False

        if existing_token:
            token = existing_token
            nifi_client_logger.info("Using existing token for NiFi API client.")
        elif username and password:
            auth_client = external_httpx_client
            if not auth_client:
                 auth_client = httpx.AsyncClient(**httpx_client_config)
                 temp_auth_client_created = True

            try:
                temp_api_instance_for_auth = cls(base_url, auth_client)
                token = await temp_api_instance_for_auth._authenticate(username, password)
                nifi_client_logger.info(f"Successfully authenticated user '{username}' with NiFi.")
            except NiFiAuthException:
                nifi_client_logger.error(f"NiFi authentication failed for user '{username}'.")
                raise
            finally:
                if temp_auth_client_created and auth_client:
                    await auth_client.aclose()
        else:
            raise ValueError("Either username/password or an existing token must be provided for NiFiApiClient.")

        instance_httpx_client = external_httpx_client
        if not instance_httpx_client:
            instance_httpx_client = httpx.AsyncClient(**httpx_client_config)

        return cls(base_url, instance_httpx_client, token)


    async def close(self):
        """
        Closes the underlying HTTP client.
        """
        if self._httpx_client and not self._httpx_client.is_closed:
            await self._httpx_client.aclose()
            nifi_client_logger.debug("NiFi API HTTP client closed.")

    async def _authenticate(self, username: str, password: str) -> str:
        """
        Authenticates with NiFi using username and password to obtain a JWT.
        """
        auth_url = f"{self._base_url.strip('/')}/access/token"
        data = {"username": username, "password": password}
        headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": self._user_agent}
        nifi_client_logger.debug(f"Attempting NiFi authentication for user '{username}' at {auth_url}.")
        try:
            response = await self._httpx_client.post(auth_url, data=data, headers=headers)
            if response.status_code == 201:
                token = response.text
                if not token:
                    raise NiFiAuthException("Authentication successful but no token received.")
                self._token = token
                nifi_client_logger.info(f"NiFi JWT token obtained for user '{username}'.")
                return token
            else:
                error_message = f"NiFi authentication failed. Status: {response.status_code}. Response: {response.text[:500]}"
                nifi_client_logger.error(error_message)
                raise NiFiAuthException(error_message)
        except httpx.RequestError as e:
            error_message = f"HTTP request error during NiFi authentication: {e}"
            nifi_client_logger.error(error_message)
            raise NiFiAuthException(error_message) from e

    def _get_auth_header(self) -> Dict[str, str]:
        """
        Constructs the Authorization header.
        """
        if not self._token:
            raise NiFiAuthException("No authentication token available. Please authenticate first.")
        return {"Authorization": f"Bearer {self._token}"}

    async def _make_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Union[BaseModel, Dict[str, Any]]] = None,
        data_body: Optional[Dict[str, str]] = None,
        response_model: Optional[Type[ResponseType]] = None,
        expect_json_response: bool = True,
        allow_404: bool = False,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Optional[Union[ResponseType, str, bytes, httpx.Response]]:
        """
        Makes an HTTP request to the NiFi API.
        """
        full_url = f"{self._base_url.strip('/')}/{path.lstrip('/')}"
        headers = {}
        if path != "access/token": # Path for auth token request itself should not have Bearer token
            try:
                 headers.update(self._get_auth_header())
            except NiFiAuthException as e:
                 raise NiFiApiException(status_code=401, message=str(e)) from e

        headers["User-Agent"] = self._user_agent
        if extra_headers:
            headers.update(extra_headers)

        json_payload: Optional[Dict[str, Any]] = None
        if json_body:
            if isinstance(json_body, BaseModel):
                json_payload = json_body.model_dump(by_alias=True, exclude_none=True)
            else:
                json_payload = json_body
            headers["Content-Type"] = "application/json"

        nifi_client_logger.debug(f"Making NiFi API request: {method} {full_url}")
        nifi_client_logger.debug(f"Params: {params}, JSON Body: {json_payload}, Data Body: {data_body}")

        try:
            response = await self._httpx_client.request(
                method, full_url, params=params, json=json_payload, data=data_body, headers=headers
            )
            nifi_client_logger.debug(f"NiFi API response: {response.status_code} {response.request.url}")

            if 200 <= response.status_code < 300:
                if not expect_json_response:
                    if response_model is str: return response.text
                    elif response_model is bytes: return response.content
                    return response
                if response.status_code == 204: return None # No Content
                try:
                    if not response.content: # Handle empty body on success
                        if response_model:
                             nifi_client_logger.warning(f"Received status {response.status_code} but no content for {method} {full_url}. Expecting {response_model}.")
                             return None
                        else: return {}
                    response_json = response.json()
                    if response_model:
                        return response_model.model_validate(response_json)
                    return response_json
                except (ValueError, ValidationError) as e: # JSONDecodeError is a subclass of ValueError
                    nifi_client_logger.error(f"Failed to parse or validate NiFi API JSON response: {e}. Response text: {response.text[:500]}")
                    raise NiFiApiException(response.status_code, f"Invalid JSON response: {e}", response.text) from e
            elif response.status_code == 404 and allow_404:
                nifi_client_logger.info(f"Resource not found (404) but allowed: {method} {full_url}")
                return None
            else: # Other errors
                error_message = f"NiFi API request failed. URL: {full_url}, Status: {response.status_code}"
                try: details = response.text; error_message += f". Details: {details[:500]}"
                except Exception: pass
                nifi_client_logger.error(error_message)
                raise NiFiApiException(response.status_code, error_message, response_text=response.text)
        except httpx.RequestError as e: # Network-level errors
            error_message = f"HTTP request error encountered for {method} {full_url}: {e}"
            nifi_client_logger.error(error_message)
            raise NiFiApiException(status_code=0, message=error_message) from e

    # --- Authentication Endpoints ---
    async def get_nifi_authentication_configuration(self) -> AuthenticationConfigurationEntity:
        """Retrieves the server’s login and logout URIs."""
        result = await self._make_request("GET", "authentication/configuration", response_model=AuthenticationConfigurationEntity)
        if not isinstance(result, AuthenticationConfigurationEntity): 
            raise NiFiApiException(0, "Invalid response for get_nifi_authentication_configuration, expected AuthenticationConfigurationEntity")
        return result

    async def logout_nifi_session(self) -> None:
        """Invalidates the current JWT."""
        await self._make_request("DELETE", "access/logout", expect_json_response=False)
        self._token = None
        nifi_client_logger.info("Successfully logged out NiFi session.")

    async def complete_nifi_logout(self) -> httpx.Response:
        """Final redirect step for browser logouts."""
        response = await self._make_request("GET", "access/logout/complete", expect_json_response=False)
        if not isinstance(response, httpx.Response): 
            raise NiFiApiException(0, "Expected httpx.Response for complete_nifi_logout")
        # NiFi usually redirects (302), but other success codes might be possible or indicate issues.
        if response.status_code != 302:
             nifi_client_logger.warning(f"Logout complete call returned unexpected status: {response.status_code}")
        return response

    # --- Process Group methods ---
    async def get_process_group(self, pg_id: str) -> Optional[ProcessGroupEntity]:
        """Gets a process group by its ID."""
        result = await self._make_request("GET", f"process-groups/{pg_id}", response_model=ProcessGroupEntity, allow_404=True)
        if result is None: return None # Handles 404 if allow_404 is True
        if not isinstance(result, ProcessGroupEntity): 
            raise NiFiApiException(0, "Invalid response type for get_process_group, expected ProcessGroupEntity")
        return result

    async def create_process_group(
        self,
        parent_id: str,
        pg_entity_payload: ProcessGroupEntity,
        parameter_context_handling_strategy: Optional[str] = None
    ) -> ProcessGroupEntity:
        """Creates a new process group."""
        path = f"process-groups/{parent_id}/process-groups"
        params: Dict[str, Any] = {}
        if parameter_context_handling_strategy:
            params["parameterContextHandlingStrategy"] = parameter_context_handling_strategy
        
        result = await self._make_request(
            method="POST", # Typically 201 Created
            path=path,
            json_body=pg_entity_payload,
            params=params if params else None,
            response_model=ProcessGroupEntity
        )
        if not isinstance(result, ProcessGroupEntity):
            raise NiFiApiException(0, "Failed to create process group or parse response correctly.")
        return result

    async def update_process_group(
        self,
        pg_id: str,
        pg_entity_payload: ProcessGroupEntity
    ) -> ProcessGroupEntity:
        """Updates an existing process group."""
        path = f"process-groups/{pg_id}"
        result = await self._make_request(
            method="PUT",
            path=path,
            json_body=pg_entity_payload,
            response_model=ProcessGroupEntity
        )
        if not isinstance(result, ProcessGroupEntity):
            raise NiFiApiException(0, "Failed to update process group or parse response correctly.")
        return result

    async def delete_process_group(
        self,
        pg_id: str,
        version: str,
        client_id: Optional[str] = None,
        disconnected_node_acknowledged: bool = False
    ) -> ProcessGroupEntity:
        """Deletes a process group."""
        path = f"process-groups/{pg_id}"
        params: Dict[str, Any] = {"version": version}
        if client_id:
            params["clientId"] = client_id
        params["disconnectedNodeAcknowledged"] = str(disconnected_node_acknowledged).lower()

        result = await self._make_request(
            method="DELETE",
            path=path,
            params=params,
            response_model=ProcessGroupEntity
        )
        if not isinstance(result, ProcessGroupEntity):
            raise NiFiApiException(0, "Failed to delete process group or parse response correctly.")
        return result

    async def get_process_groups_in_group(self, parent_group_id: str) -> Optional[ProcessGroupsEntity]: # NEW
        """Gets all child process groups within a specified parent process group."""
        path = f"process-groups/{parent_group_id}/process-groups"
        nifi_client_logger.debug(f"Attempting GET {path}")
        result = await self._make_request(method="GET", path=path, response_model=ProcessGroupsEntity, allow_404=True) # parent_group_id might 404
        if result is None: 
            nifi_client_logger.info(f"No child process groups found or parent group {parent_group_id} not found.")
            return None
        if not isinstance(result, ProcessGroupsEntity): 
            raise NiFiApiException(0, f"Invalid response for get_process_groups_in_group, expected ProcessGroupsEntity, got {type(result)}")
        return result

    async def get_processors_in_group(self, parent_group_id: str, include_descendant_groups: bool = False) -> Optional[ProcessorsEntity]: # NEW
        """Gets all processors within a specified parent process group."""
        path = f"process-groups/{parent_group_id}/processors"
        params: Dict[str, Any] = {"includeDescendantGroups": str(include_descendant_groups).lower()}
        nifi_client_logger.debug(f"Attempting GET {path} with params {params}")
        result = await self._make_request(method="GET", path=path, params=params, response_model=ProcessorsEntity, allow_404=True) # parent_group_id might 404
        if result is None: 
            nifi_client_logger.info(f"No processors found or parent group {parent_group_id} not found.")
            return None
        if not isinstance(result, ProcessorsEntity): 
            raise NiFiApiException(0, f"Invalid response for get_processors_in_group, expected ProcessorsEntity, got {type(result)}")
        return result
    
    async def get_connections_in_process_group(self, process_group_id: str) -> Optional[ConnectionsEntity]:
        """Gets all connections in a specified process group."""
        path = f"process-groups/{process_group_id}/connections"
        nifi_client_logger.debug(f"Attempting GET {path}")
        result = await self._make_request(method="GET", path=path, response_model=ConnectionsEntity, allow_404=True)
        if result is None: return None
        if not isinstance(result, ConnectionsEntity): raise NiFiApiException(0, f"Invalid response for get_connections_in_process_group, expected ConnectionsEntity, got {type(result)}")
        return result
    
    # --- Processor methods ---
    async def get_processor(self, processor_id: str) -> Optional[ProcessorEntity]:
        """Gets a processor by its ID."""
        nifi_client_logger.debug(f"Attempting GET /processors/{processor_id}")
        result = await self._make_request(
            method="GET",
            path=f"processors/{processor_id}",
            response_model=ProcessorEntity,
            allow_404=True
        )
        if result is None: # Handles 404 case where allow_404=True
            nifi_client_logger.info(f"Processor with ID {processor_id} not found (404).")
            return None
        if not isinstance(result, ProcessorEntity):
            raise NiFiApiException(0, f"Invalid response type for get_processor, expected ProcessorEntity, got {type(result)}")
        nifi_client_logger.info(f"Successfully retrieved Processor details for ID {processor_id}")
        return result

    async def create_processor(self, parent_group_id: str, processor_entity_payload: ProcessorEntity) -> ProcessorEntity:
        """Creates a new processor within the specified parent process group."""
        path = f"process-groups/{parent_group_id}/processors"
        nifi_client_logger.debug(f"Attempting POST {path} to create processor in group {parent_group_id}")
        result = await self._make_request(
            method="POST", # NiFi typically returns 201 Created for this
            path=path,
            json_body=processor_entity_payload,
            response_model=ProcessorEntity
        )
        if not isinstance(result, ProcessorEntity):
            raise NiFiApiException(0, "Failed to create processor or parse response correctly.")
        processor_name = result.component.name if result.component else "N/A"
        nifi_client_logger.info(f"Successfully created Processor '{processor_name}' with ID {result.id if result.id else 'N/A'} in parent group {parent_group_id}")
        return result

    async def update_processor(self, processor_id: str, processor_entity_payload: ProcessorEntity) -> ProcessorEntity:
        """Updates an existing processor."""
        path = f"processors/{processor_id}"
        nifi_client_logger.debug(f"Attempting PUT {path} for processor {processor_id}")
        result = await self._make_request(
            method="PUT",
            path=path,
            json_body=processor_entity_payload,
            response_model=ProcessorEntity
        )
        if not isinstance(result, ProcessorEntity):
            raise NiFiApiException(0, "Failed to update processor or parse response correctly.")
        nifi_client_logger.info(f"Successfully updated Processor ID {processor_id}")
        return result

    async def delete_processor(self, processor_id: str, version: str, client_id: Optional[str] = None, disconnected_node_acknowledged: bool = False) -> ProcessorEntity:
        """Deletes a processor."""
        path = f"processors/{processor_id}"
        params: Dict[str, Any] = {"version": version}
        if client_id:
            params["clientId"] = client_id
        params["disconnectedNodeAcknowledged"] = str(disconnected_node_acknowledged).lower()

        nifi_client_logger.debug(f"Attempting DELETE {path} for processor {processor_id} with params {params}")
        result = await self._make_request(
            method="DELETE",
            path=path,
            params=params,
            response_model=ProcessorEntity
        )
        if not isinstance(result, ProcessorEntity):
            raise NiFiApiException(0, "Failed to delete processor or parse response correctly.")
        nifi_client_logger.info(f"Successfully deleted Processor ID {processor_id}")
        return result

    async def update_processor_run_status(self, processor_id: str, run_status_entity: ProcessorRunStatusEntity) -> ProcessorEntity:
        """Updates the run status of a processor (e.g., start, stop, disable)."""
        path = f"processors/{processor_id}/run-status"
        nifi_client_logger.debug(f"Attempting PUT {path} for processor {processor_id} to set status with payload: {run_status_entity.model_dump_json(by_alias=True, exclude_none=True)}")
        result = await self._make_request(
            method="PUT",
            path=path,
            json_body=run_status_entity,
            response_model=ProcessorEntity
        )
        if not isinstance(result, ProcessorEntity):
            raise NiFiApiException(0, "Failed to update processor run status or parse response correctly.")
        nifi_client_logger.info(f"Successfully updated run status for Processor ID {processor_id}")
        return result


    # --- Connection methods ---
    async def create_connection(self, parent_group_id: str, connection_entity_payload: ConnectionEntity) -> ConnectionEntity: # Endpoint 1.2
        """Creates a new connection within the specified parent process group."""
        path = f"process-groups/{parent_group_id}/connections"
        nifi_client_logger.debug(f"Attempting POST {path} to create connection in group {parent_group_id}")
        result = await self._make_request(method="POST", path=path, json_body=connection_entity_payload, response_model=ConnectionEntity) # NiFi typically 201 Created
        if not isinstance(result, ConnectionEntity): raise NiFiApiException(0, "Failed to create connection or parse response correctly.")
        nifi_client_logger.info(f"Successfully created Connection with ID {result.id if result.id else 'N/A'} in parent group {parent_group_id}")
        return result

    async def get_connection(self, connection_id: str) -> Optional[ConnectionEntity]: # Endpoint 2.2
        """Gets a connection by its ID."""
        nifi_client_logger.debug(f"Attempting GET /connections/{connection_id}")
        result = await self._make_request(method="GET", path=f"connections/{connection_id}", response_model=ConnectionEntity, allow_404=True)
        if result is None: return None
        if not isinstance(result, ConnectionEntity): raise NiFiApiException(0, f"Invalid response for get_connection, expected ConnectionEntity, got {type(result)}")
        nifi_client_logger.info(f"Successfully retrieved Connection details for ID {connection_id}")
        return result

    async def update_connection(self, connection_id: str, connection_entity_payload: ConnectionEntity) -> ConnectionEntity: # Endpoint 2.3
        """Updates an existing connection."""
        path = f"connections/{connection_id}"
        nifi_client_logger.debug(f"Attempting PUT {path} for connection {connection_id}")
        result = await self._make_request(method="PUT", path=path, json_body=connection_entity_payload, response_model=ConnectionEntity)
        if not isinstance(result, ConnectionEntity): raise NiFiApiException(0, "Failed to update connection or parse response correctly.")
        nifi_client_logger.info(f"Successfully updated Connection ID {connection_id}")
        return result

    async def delete_connection(self, connection_id: str, version: str, client_id: Optional[str] = None, disconnected_node_acknowledged: bool = False) -> ConnectionEntity: # Endpoint 2.1 - Signature updated
        """Deletes a connection."""
        path = f"connections/{connection_id}"
        params: Dict[str, Any] = {"version": version}
        if client_id:
            params["clientId"] = client_id
        params["disconnectedNodeAcknowledged"] = str(disconnected_node_acknowledged).lower()
        nifi_client_logger.debug(f"Attempting DELETE {path} for connection {connection_id} with params {params}")
        result = await self._make_request(method="DELETE", path=path, params=params, response_model=ConnectionEntity)
        if not isinstance(result, ConnectionEntity): raise NiFiApiException(0, "Failed to delete connection or parse response correctly.")
        nifi_client_logger.info(f"Successfully deleted Connection ID {connection_id}")
        return result
    
    # --- Connection Flow Endpoints ---
    async def get_connection_status(self, connection_id: str, nodewise: bool = False, cluster_node_id: Optional[str] = None) -> Optional[ConnectionStatusEntity]: # NEW - Endpoint 3.1
        """Gets the status for a connection."""
        path = f"flow/connections/{connection_id}/status"
        params: Dict[str, Any] = {"nodewise": str(nodewise).lower()}
        if cluster_node_id:
            params["clusterNodeId"] = cluster_node_id
        nifi_client_logger.debug(f"Attempting GET {path} with params {params}")
        result = await self._make_request(method="GET", path=path, params=params, response_model=ConnectionStatusEntity, allow_404=True)
        if result is None: return None
        if not isinstance(result, ConnectionStatusEntity): raise NiFiApiException(0, f"Invalid response for get_connection_status, expected ConnectionStatusEntity, got {type(result)}")
        return result

    async def get_connection_status_history(self, connection_id: str) -> Optional[StatusHistoryEntity]: # NEW - Endpoint 3.2
        """Gets the status history for a connection."""
        path = f"flow/connections/{connection_id}/status/history"
        nifi_client_logger.debug(f"Attempting GET {path}")
        result = await self._make_request(method="GET", path=path, response_model=StatusHistoryEntity, allow_404=True)
        # Basic placeholder for StatusHistoryEntity, so this might need refinement later if complex
        if result is None: return None
        if not isinstance(result, StatusHistoryEntity): raise NiFiApiException(0, f"Invalid response for get_connection_status_history, expected StatusHistoryEntity, got {type(result)}")
        return result

    async def get_connection_statistics(self, connection_id: str, nodewise: bool = False, cluster_node_id: Optional[str] = None) -> Optional[ConnectionStatisticsEntity]: # NEW - Endpoint 3.3
        """Gets statistics for a connection."""
        path = f"flow/connections/{connection_id}/statistics"
        params: Dict[str, Any] = {"nodewise": str(nodewise).lower()}
        if cluster_node_id:
            params["clusterNodeId"] = cluster_node_id
        nifi_client_logger.debug(f"Attempting GET {path} with params {params}")
        result = await self._make_request(method="GET", path=path, params=params, response_model=ConnectionStatisticsEntity, allow_404=True)
        if result is None: return None
        if not isinstance(result, ConnectionStatisticsEntity): raise NiFiApiException(0, f"Invalid response for get_connection_statistics, expected ConnectionStatisticsEntity, got {type(result)}")
        return result

    # --- Input Port methods (Section 3.5) ---
    async def get_input_port(self, port_id: str) -> Optional[PortEntity]:
        nifi_client_logger.warning("get_input_port is a stub and not yet implemented.")
        return None
    async def create_input_port(self, group_id: str, port_entity: PortEntity) -> Optional[PortEntity]:
        nifi_client_logger.warning("create_input_port is a stub and not yet implemented.")
        return None
    async def update_input_port(self, port_id: str, port_entity: PortEntity) -> Optional[PortEntity]:
        nifi_client_logger.warning("update_input_port is a stub and not yet implemented.")
        return None
    async def delete_input_port(self, port_id: str, version: str, client_id: Optional[str] = None, disconnected_node_acknowledged: bool = False) -> Optional[PortEntity]:
        nifi_client_logger.warning("delete_input_port is a stub and not yet implemented.")
        return None

    # --- Output Port methods (Section 3.6) ---
    async def get_output_port(self, port_id: str) -> Optional[PortEntity]:
        nifi_client_logger.warning("get_output_port is a stub and not yet implemented.")
        return None
    async def create_output_port(self, group_id: str, port_entity: PortEntity) -> Optional[PortEntity]:
        nifi_client_logger.warning("create_output_port is a stub and not yet implemented.")
        return None
    async def update_output_port(self, port_id: str, port_entity: PortEntity) -> Optional[PortEntity]:
        nifi_client_logger.warning("update_output_port is a stub and not yet implemented.")
        return None
    async def delete_output_port(self, port_id: str, version: str, client_id: Optional[str] = None, disconnected_node_acknowledged: bool = False) -> Optional[PortEntity]:
        nifi_client_logger.warning("delete_output_port is a stub and not yet implemented.")
        return None

    # Stubs for other /processors endpoints (to be implemented later)
    async def analyze_processor_configuration(self, processor_id: str, config_analysis_entity: ConfigurationAnalysisEntity) -> Optional[ConfigurationAnalysisEntity]:
        nifi_client_logger.warning(f"analyze_processor_configuration for {processor_id} is a stub.")
        return None
    async def clear_processor_state(self, processor_id: str) -> Optional[ComponentStateEntity]:
        nifi_client_logger.warning(f"clear_processor_state for {processor_id} is a stub.")
        return None
    async def delete_processor_verification_request(self, processor_id: str, request_id: str) -> Optional[VerifyConfigRequestEntity]:
        nifi_client_logger.warning(f"delete_processor_verification_request for {processor_id}/{request_id} is a stub.")
        return None
    async def get_processor_diagnostics(self, processor_id: str) -> Optional[ProcessorEntity]: # Note: API returns ProcessorEntity
        nifi_client_logger.warning(f"get_processor_diagnostics for {processor_id} is a stub.")
        return None
    async def get_processor_run_status_details(self, request_entity: RunStatusDetailsRequestEntity) -> Optional[ProcessorsRunStatusDetailsEntity]:
        nifi_client_logger.warning(f"get_processor_run_status_details is a stub.")
        return None
    async def get_processor_property_descriptor(self, processor_id: str, property_name: str, sensitive: Optional[bool]=None) -> Optional[PropertyDescriptorEntity]:
        nifi_client_logger.warning(f"get_processor_property_descriptor for {processor_id} property {property_name} is a stub.")
        return None
    async def get_processor_state(self, processor_id: str) -> Optional[ComponentStateEntity]:
        nifi_client_logger.warning(f"get_processor_state for {processor_id} is a stub.")
        return None
    async def get_processor_verification_request(self, processor_id: str, request_id: str) -> Optional[VerifyConfigRequestEntity]:
        nifi_client_logger.warning(f"get_processor_verification_request for {processor_id}/{request_id} is a stub.")
        return None
    async def submit_processor_verification_request(self, processor_id: str, verification_request_entity: VerifyConfigRequestEntity) -> Optional[VerifyConfigRequestEntity]:
        nifi_client_logger.warning(f"submit_processor_verification_request for {processor_id} is a stub.")
        return None
    async def terminate_processor_threads(self, processor_id: str) -> Optional[ProcessorEntity]:
        nifi_client_logger.warning(f"terminate_processor_threads for {processor_id} is a stub.")
        return None