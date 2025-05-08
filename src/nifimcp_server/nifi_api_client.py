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
    ConnectionEntity,
    PortEntity,
    RevisionDTO,
    # Import other DTOs/Entities as needed when implementing specific methods
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
        ssl_verify: bool = True # <<< ADDED ssl_verify parameter
    ) -> "NiFiApiClient":
        """
        Factory method to create and authenticate a NiFiApiClient instance.

        Args:
            base_url: The base URL of the NiFi API.
            username: NiFi username for authentication.
            password: NiFi password for authentication.
            existing_token: An optional, pre-existing JWT.
            external_httpx_client: An optional, pre-configured httpx.AsyncClient.
            ssl_verify: If False, disables SSL certificate verification. Defaults to True.

        Returns:
            An initialized NiFiApiClient instance.

        Raises:
            NiFiAuthException: If authentication fails.
            ValueError: If insufficient credentials are provided.
        """
        # Configuration for the httpx client instance(s)
        httpx_client_config = {"verify": False}
        if not ssl_verify:
             nifi_client_logger.warning("SSL certificate verification is DISABLED for NiFi API client.")

        token: Optional[str] = None
        temp_auth_client_created = False # Flag to track if we created a temporary client

        if existing_token:
            token = existing_token
            nifi_client_logger.info("Using existing token for NiFi API client.")
        elif username and password:
            # Determine which client to use for the auth call
            auth_client = external_httpx_client
            if not auth_client:
                 # Create a new temporary client *with* the verify setting for the auth call
                 auth_client = httpx.AsyncClient(**httpx_client_config)
                 temp_auth_client_created = True # Mark that we created it

            try:
                # Create a temporary NiFiApiClient instance just for the auth call,
                # passing the correctly configured httpx client
                temp_api_instance_for_auth = cls(base_url, auth_client) # Pass auth_client
                token = await temp_api_instance_for_auth._authenticate(username, password)
                nifi_client_logger.info(f"Successfully authenticated user '{username}' with NiFi.")
            except NiFiAuthException:
                nifi_client_logger.error(f"NiFi authentication failed for user '{username}'.")
                raise # Re-raise the specific auth exception
            finally:
                # Close the temporary client *only if* we created it here
                if temp_auth_client_created and auth_client:
                    await auth_client.aclose()
        else:
            raise ValueError("Either username/password or an existing token must be provided for NiFiApiClient.")

        # Determine the final httpx client for the actual NiFiApiClient instance
        # If an external one was provided, use it. Otherwise, create a new one with config.
        instance_httpx_client = external_httpx_client
        if not instance_httpx_client:
            instance_httpx_client = httpx.AsyncClient(**httpx_client_config)

        # Create the final NiFiApiClient instance
        return cls(base_url, instance_httpx_client, token)


    async def close(self):
        """
        Closes the underlying HTTP client.
        This should be called when the NiFiApiClient is no longer needed.
        """
        if self._httpx_client and not self._httpx_client.is_closed:
            await self._httpx_client.aclose()
            nifi_client_logger.debug("NiFi API HTTP client closed.")

    async def _authenticate(self, username: str, password: str) -> str:
        """
        Authenticates with NiFi using username and password to obtain a JWT.

        Args:
            username: The NiFi username.
            password: The NiFi password.

        Returns:
            The JWT access token as a string.

        Raises:
            NiFiAuthException: If authentication fails.
        """
        auth_url = f"{self._base_url.strip('/')}/access/token"
        data = {"username": username, "password": password}
        # User-Agent is added automatically by _make_request or directly in the httpx call here
        headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": self._user_agent}

        nifi_client_logger.debug(f"Attempting NiFi authentication for user '{username}' at {auth_url}.")
        try:
            # Use the client passed during initialization (which has verify setting)
            response = await self._httpx_client.post(auth_url, data=data, headers=headers)

            if response.status_code == 201: # NiFi spec: "Success = 201"
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
            # Wrap HTTP errors in NiFiAuthException specifically for auth step
            raise NiFiAuthException(error_message) from e

    def _get_auth_header(self) -> Dict[str, str]:
        """
        Constructs the Authorization header if a token is available.

        Returns:
            A dictionary containing the Authorization header.

        Raises:
            NiFiAuthException: If no token is available.
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
        data_body: Optional[Dict[str, str]] = None, # For form-urlencoded data
        response_model: Optional[Type[ResponseType]] = None,
        expect_json_response: bool = True, # Most NiFi responses are JSON
        allow_404: bool = False, # Controls if 404 raises NiFiApiException
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Optional[Union[ResponseType, str, bytes, httpx.Response]]:
        """
        Makes an HTTP request to the NiFi API using the configured httpx client.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            path: API endpoint path (relative to base_url).
            params: URL query parameters.
            json_body: Pydantic model or dict for JSON request body.
            data_body: Dict for x-www-form-urlencoded request body.
            response_model: Pydantic model to parse the JSON response into.
            expect_json_response: Whether to expect a JSON response.
            allow_404: If True and a 404 is received, returns None instead of raising NiFiApiException.
            extra_headers: Additional headers to include in the request.

        Returns:
            Parsed Pydantic model, raw text/bytes, httpx.Response, or None if allow_404=True and 404 is received.

        Raises:
            NiFiApiException: For non-2xx responses (unless allow_404 handles it) or Pydantic validation errors.
            NiFiAuthException: If authentication is required but no token is set (handled by _get_auth_header).
        """
        full_url = f"{self._base_url.strip('/')}/{path.lstrip('/')}"

        # Determine if auth header is needed (all paths except access/token)
        headers = {}
        if path != "access/token":
            try:
                 headers.update(self._get_auth_header())
            except NiFiAuthException as e:
                 # If auth is required but not available, re-raise immediately
                 raise NiFiApiException(status_code=401, message=str(e)) from e

        headers["User-Agent"] = self._user_agent
        if extra_headers:
            headers.update(extra_headers)

        # Prepare request body
        json_payload: Optional[Dict[str, Any]] = None
        if json_body:
            if isinstance(json_body, BaseModel):
                # Use by_alias for correct field names (e.g., clientId)
                # Use exclude_none to only send provided fields
                json_payload = json_body.model_dump(by_alias=True, exclude_none=True)
            else:
                json_payload = json_body
            # Set content type only if we actually have a json body
            headers["Content-Type"] = "application/json"

        nifi_client_logger.debug(f"Making NiFi API request: {method} {full_url}")
        nifi_client_logger.debug(f"Params: {params}, JSON Body: {json_payload}, Data Body: {data_body}")

        try:
            # The self._httpx_client instance already has the verify setting configured
            response = await self._httpx_client.request(
                method,
                full_url,
                params=params,
                json=json_payload,
                data=data_body,
                headers=headers,
                # Timeout can be configured on the client itself, or per-request
                # timeout=httpx.Timeout(10.0, connect=5.0) # Example per-request timeout
            )

            nifi_client_logger.debug(f"NiFi API response: {response.status_code} {response.request.url}")

            # Check for successful status codes (2xx)
            if 200 <= response.status_code < 300:
                if not expect_json_response:
                    # Handle non-JSON responses
                    if response_model is str:
                        return response.text
                    elif response_model is bytes:
                        return response.content
                    # Return raw response if no specific parsing is needed
                    return response

                # Handle successful JSON responses
                if response.status_code == 204: # No Content
                    return None

                try:
                    # Handle cases where response might be empty but status is 200/201 etc.
                    if not response.content:
                        if response_model:
                             # If a model was expected, but no content, raise error or return None?
                             # Returning None seems safer if model fields aren't all Optional.
                             nifi_client_logger.warning(f"Received status {response.status_code} but no content for {method} {full_url}. Expecting {response_model}.")
                             return None
                        else:
                             return {} # Return empty dict if no model expected and no content

                    response_json = response.json()
                    if response_model:
                        # Validate and parse using the provided Pydantic model
                        return response_model.model_validate(response_json)
                    # Return raw dict if no Pydantic model was specified
                    return response_json
                except (ValueError, ValidationError) as e: # Catches JSONDecodeError and Pydantic errors
                    nifi_client_logger.error(f"Failed to parse or validate NiFi API JSON response: {e}. Response text: {response.text[:500]}")
                    raise NiFiApiException(response.status_code, f"Invalid JSON response: {e}", response.text) from e

            # Handle allowed 404
            elif response.status_code == 404 and allow_404:
                nifi_client_logger.info(f"Resource not found (404) but allowed: {method} {full_url}")
                return None
            # Handle other error status codes
            else:
                error_message = f"NiFi API request failed. URL: {full_url}, Status: {response.status_code}"
                try:
                    # NiFi often returns plain text errors
                    details = response.text
                    error_message += f". Details: {details[:500]}" # Limit detail length
                except Exception:
                    pass # Ignore if details can't be read
                nifi_client_logger.error(error_message)
                # Raise custom exception with details
                raise NiFiApiException(response.status_code, error_message, response_text=response.text)

        except httpx.RequestError as e:
            # Handle network-level errors (connection refused, DNS errors, timeouts)
            error_message = f"HTTP request error encountered for {method} {full_url}: {e}"
            nifi_client_logger.error(error_message)
            # Use status_code=0 or similar to indicate non-HTTP error
            raise NiFiApiException(status_code=0, message=error_message) from e

    # --- Authentication Endpoints (Section 3.1) ---

    async def get_nifi_authentication_configuration(self) -> AuthenticationConfigurationEntity:
        """
        Retrieves the server’s login and logout URIs and whether external login is required.
        Corresponds to GET /authentication/configuration.
        """
        # Type ignore because _make_request can return None, but this specific endpoint
        # should always return the entity or raise an exception on error.
        result = await self._make_request(
            method="GET",
            path="authentication/configuration",
            response_model=AuthenticationConfigurationEntity
        )
        if result is None:
            # This case implies a 204 No Content which shouldn't happen for this endpoint
             raise NiFiApiException(204, "Received unexpected No Content response for /authentication/configuration")
        return result # type: ignore

    async def logout_nifi_session(self) -> None:
        """
        Invalidates the current JWT.
        Corresponds to DELETE /access/logout.
        """
        await self._make_request(
            method="DELETE",
            path="access/logout",
            expect_json_response=False # NiFi doc says 200, implies no body or plain text.
        )
        self._token = None # Clear local token after successful logout call
        nifi_client_logger.info("Successfully logged out NiFi session.")

    async def complete_nifi_logout(self) -> httpx.Response:
        """
        Final redirect step for browser logouts; safe no-body call for API clients.
        Corresponds to GET /access/logout/complete.
        Returns the raw httpx.Response object to allow handling of the 302 redirect if needed.
        """
        response_or_none = await self._make_request(
            method="GET",
            path="access/logout/complete",
            expect_json_response=False # Expecting 302 redirect
        )
        if response_or_none and isinstance(response_or_none, httpx.Response):
            # The make_request should have already validated 2xx/3xx status
            # If it's 302, it should return the response object
            if response_or_none.status_code == 302:
                nifi_client_logger.info("Logout complete call successful (302).")
                return response_or_none
            else:
                 # If make_request returned a response but not 302 (unexpected)
                 nifi_client_logger.warning(f"Logout complete call returned unexpected status: {response_or_none.status_code}")
                 raise NiFiApiException(response_or_none.status_code, f"Unexpected status from /access/logout/complete: {response_or_none.status_code}", response_or_none.text)
        else:
             # Should not happen if _make_request is correct and didn't raise an error for non-2xx/3xx
             raise NiFiApiException(0, "Unexpected error during complete_nifi_logout: _make_request returned None or non-Response")
        # --- Authentication Endpoints (Section 3.1) ---

    # ... (existing get_nifi_authentication_configuration, logout_nifi_session, complete_nifi_logout) ...

    # Method we are adding now:
    async def get_nifi_authentication_configuration(self) -> AuthenticationConfigurationEntity:
        """
        Retrieves the server’s login and logout URIs and whether external login is required.
        Corresponds to GET /authentication/configuration. Requires prior authentication.
        """
        nifi_client_logger.debug("Attempting GET /authentication/configuration")
        # This endpoint requires authentication, so _make_request will use the stored token.
        result = await self._make_request(
            method="GET",
            path="authentication/configuration",
            response_model=AuthenticationConfigurationEntity,
            expect_json_response=True # Expecting JSON response
        )
        if not isinstance(result, AuthenticationConfigurationEntity):
            # This can happen if _make_request returns None (e.g., 204 or unexpected non-JSON)
            # or if the response parsing failed in a way not caught earlier.
            # Based on NiFi docs, this endpoint should always return the entity on success.
            raise NiFiApiException(
                status_code=response.status_code if 'response' in locals() and response else 0,
                message="Failed to get valid AuthenticationConfigurationEntity from API"
            )
        return result

    # --- Placeholder Stubs for Other Essential Endpoints ---
    # ... (rest of the stubs remain) ...

    # --- Placeholder Stubs for Other Essential Endpoints ---
    # These will be implemented iteratively later.

    # --- Process Group methods (Section 3.2) ---
    # Inside NiFiApiClient class in nifi_api_client.py

    # --- Process Group methods (Section 3.2) ---
    async def get_process_group(self, pg_id: str) -> Optional[ProcessGroupEntity]:
        """
        Gets a process group by its ID.
        Corresponds to GET /process-groups/{id}.

        Args:
            pg_id: The ID of the process group to retrieve.

        Returns:
            A ProcessGroupEntity if found, None if a 404 is received.

        Raises:
            NiFiApiException: For non-200/404 status codes or other API errors.
        """
        nifi_client_logger.debug(f"Attempting GET /process-groups/{pg_id}")
        result = await self._make_request(
            method="GET",
            path=f"process-groups/{pg_id}",
            response_model=ProcessGroupEntity,
            allow_404=True # A 404 ("Not Found") is a valid response here
        )
        if result is None and not isinstance(result, ProcessGroupEntity): # Check if it was a 404 or other issue
             nifi_client_logger.warning(f"Process Group with ID {pg_id} not found (404) or invalid response.")
             return None # Explicitly return None on 404 or parse failure when allow_404=True
        nifi_client_logger.info(f"Successfully retrieved Process Group details for ID {pg_id}")
        # Type assertion needed because _make_request has a broad return type
        return result # type: ignore

    # ... (rest of the stubs remain for create/update/delete PG) ...
    async def create_process_group(self, parent_id: str, pg_entity: ProcessGroupEntity) -> Optional[ProcessGroupEntity]:
        nifi_client_logger.warning("create_process_group is a stub and not yet implemented.")
        return None
    async def update_process_group(self, pg_id: str, pg_entity: ProcessGroupEntity) -> Optional[ProcessGroupEntity]:
        nifi_client_logger.warning("update_process_group is a stub and not yet implemented.")
        return None
    async def delete_process_group(self, pg_id: str, revision: RevisionDTO, disconnected_node_acknowledged: bool = False) -> Optional[ProcessGroupEntity]:
        nifi_client_logger.warning("delete_process_group is a stub and not yet implemented.")
        return None

    # --- Processor methods (Section 3.3) ---
    async def get_processor(self, processor_id: str) -> Optional[ProcessorEntity]:
        nifi_client_logger.warning("get_processor is a stub and not yet implemented.")
        return None
    async def create_processor(self, group_id: str, processor_entity: ProcessorEntity) -> Optional[ProcessorEntity]:
        nifi_client_logger.warning("create_processor is a stub and not yet implemented.")
        return None
    async def update_processor(self, processor_id: str, processor_entity: ProcessorEntity) -> Optional[ProcessorEntity]:
        nifi_client_logger.warning("update_processor is a stub and not yet implemented.")
        return None
    async def delete_processor(self, processor_id: str, revision: RevisionDTO, disconnected_node_acknowledged: bool = False) -> Optional[ProcessorEntity]:
        nifi_client_logger.warning("delete_processor is a stub and not yet implemented.")
        return None

    # --- Connection methods (Section 3.4) ---
    async def get_connection(self, connection_id: str) -> Optional[ConnectionEntity]:
        nifi_client_logger.warning("get_connection is a stub and not yet implemented.")
        return None
    async def create_connection(self, group_id: str, connection_entity: ConnectionEntity) -> Optional[ConnectionEntity]:
        nifi_client_logger.warning("create_connection is a stub and not yet implemented.")
        return None
    async def update_connection(self, connection_id: str, connection_entity: ConnectionEntity) -> Optional[ConnectionEntity]:
        nifi_client_logger.warning("update_connection is a stub and not yet implemented.")
        return None
    async def delete_connection(self, connection_id: str, revision: RevisionDTO, disconnected_node_acknowledged: bool = False) -> Optional[ConnectionEntity]:
        nifi_client_logger.warning("delete_connection is a stub and not yet implemented.")
        return None

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
    async def delete_input_port(self, port_id: str, revision: RevisionDTO, disconnected_node_acknowledged: bool = False) -> Optional[PortEntity]:
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
    async def delete_output_port(self, port_id: str, revision: RevisionDTO, disconnected_node_acknowledged: bool = False) -> Optional[PortEntity]:
        nifi_client_logger.warning("delete_output_port is a stub and not yet implemented.")
        return None