"""
Pydantic models for NiFi REST API DTOs (Data Transfer Objects) / Entities.

These models are used for:
- Type hinting in NiFi API client methods and MCP tool functions.
- Request and response validation.
- Automatic generation of `inputSchema` for MCP tools by FastMCP.

The fields and their descriptions are derived from the official
NiFi 2.0 REST API documentation.
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator, ValidationInfo

# ===================================================================
# Forward Declarations / Placeholders
# Define names before they are used as type hints in other models.
# ===================================================================

class RevisionDTO(BaseModel): pass
class PositionDTO(BaseModel): pass
class PermissionDTO(BaseModel): pass
class BulletinEntity(BaseModel): pass
class ControllerServiceEntity(BaseModel): pass
class ParameterContextReferenceEntity(BaseModel): pass
class FlowRegistryClientEntity(BaseModel): pass
class VariableRegistryUpdateStepDTO(BaseModel): pass
class VariableRegistryUpdateRequestDTO(BaseModel): pass
class VersionedFlowUpdateRequestDTO(BaseModel): pass
class VersionControlInformationDTO(BaseModel): pass
class VersionedFlowSnapshotBucketDTO(BaseModel): pass
class VersionedFlowSnapshotMetadataDTO(BaseModel): pass
class FlowSnippetDTO(BaseModel): pass
class VersionedFlowSnapshotDTO(BaseModel): pass
class ConnectableDTO(BaseModel): pass
class BundleDTO(BaseModel): pass
class PropertyDescriptorDTO(BaseModel): pass
class ProcessorConfigDTO(BaseModel): pass
class RelationshipDTO(BaseModel): pass
class ProcessGroupDTO(BaseModel): pass
class ProcessorDTO(BaseModel): pass
class PortDTO(BaseModel): pass
class ConnectionDTO(BaseModel): pass
class ProcessGroupEntity(BaseModel): pass
class ProcessorEntity(BaseModel): pass
class ConnectionEntity(BaseModel): pass
class PortEntity(BaseModel): pass
class AuthenticationConfigurationDTO(BaseModel): pass
class AuthenticationConfigurationEntity(BaseModel): pass
class NiFiClientCreds(BaseModel): pass

# ===================================================================
# Common/Core DTO Definitions
# ===================================================================

class RevisionDTO(BaseModel):
    """
    Represents the revision of a NiFi component, used for optimistic locking.
    Source: NiFi 2.0 REST API Docs
    """
    client_id: Optional[str] = Field(default=None, alias="clientId", description="The client id of the last user to modify the flow.")
    last_modifier: Optional[str] = Field(default=None, alias="lastModifier", description="The last user to modify the flow.")
    version: Optional[int] = Field(default=None, description="The revision of the flow.") # NiFi: format: int32

    model_config = {
        "populate_by_name": True,
        "extra": "allow"
    }

class PositionDTO(BaseModel):
    """
    Represents the (x, y) position of a component on the NiFi canvas.
    Source: NiFi 2.0 REST API Docs (Commonly observed structure)
    """
    x: Optional[float] = Field(None, description="The x coordinate.")
    y: Optional[float] = Field(None, description="The y coordinate.")

    model_config = {"extra": "allow"}

class PermissionDTO(BaseModel):
    """
    Permissions for a component.
    Source: NiFi 2.0 REST API Docs (Commonly observed structure)
    """
    can_read: Optional[bool] = Field(default=None, alias="canRead")
    can_write: Optional[bool] = Field(default=None, alias="canWrite")
    # NiFi 2.0 might add canDelete here for some entities like buckets
    can_delete: Optional[bool] = Field(default=None, alias="canDelete")


    model_config = {
        "populate_by_name": True,
        "extra": "allow"
    }

# ===================================================================
# Placeholder DTO Definitions (Referenced by others)
# Full definitions TBD based on specific endpoint documentation.
# ===================================================================

class BulletinEntity(BaseModel):
    """Placeholder for BulletinEntity"""
    id: Optional[int] = Field(None)
    message: Optional[str] = Field(None)
    # ... other fields ...
    model_config = {"extra": "allow"}

class ControllerServiceEntity(BaseModel):
    """Placeholder for ControllerServiceEntity"""
    id: Optional[str] = Field(None)
    # ... other fields ...
    model_config = {"extra": "allow"}

class ParameterContextReferenceEntity(BaseModel):
    """Placeholder for ParameterContextReferenceEntity"""
    id: Optional[str] = Field(None)
    name: Optional[str] = Field(None)
    permissions: Optional[PermissionDTO] = None
    # ... other fields ...
    model_config = {"extra": "allow"}

class FlowRegistryClientEntity(BaseModel):
    """Placeholder for FlowRegistryClientEntity"""
    id: Optional[str] = Field(None)
    # ... other fields ...
    model_config = {"extra": "allow"}

class VariableRegistryUpdateStepDTO(BaseModel):
    """Placeholder for VariableRegistryUpdateStepDTO"""
    description: Optional[str] = Field(None)
    complete: Optional[bool] = Field(None)
    failure_reason: Optional[str] = Field(None, alias="failureReason")
    model_config = {"extra": "allow", "populate_by_name": True}

class VariableRegistryUpdateRequestDTO(BaseModel):
    """Placeholder for VariableRegistryUpdateRequestDTO"""
    request_id: Optional[str] = Field(None, alias="requestId")
    uri: Optional[HttpUrl] = Field(None)
    complete: Optional[bool] = Field(None)
    update_steps: Optional[List[VariableRegistryUpdateStepDTO]] = Field(None, alias="updateSteps")
    # ... other fields ...
    model_config = {"extra": "allow", "populate_by_name": True}

class VersionedFlowUpdateRequestDTO(BaseModel):
    """Placeholder for VersionedFlowUpdateRequestDTO"""
    request_id: Optional[str] = Field(None, alias="requestId")
    uri: Optional[HttpUrl] = Field(None)
    complete: Optional[bool] = Field(None)
    # ... other fields ...
    model_config = {"extra": "allow", "populate_by_name": True}

class VersionControlInformationDTO(BaseModel):
    """Placeholder for VersionControlInformationDTO"""
    group_id: Optional[str] = Field(None, alias="groupId")
    registry_id: Optional[str] = Field(None, alias="registryId")
    registry_name: Optional[str] = Field(None, alias="registryName")
    bucket_id: Optional[str] = Field(None, alias="bucketId")
    bucket_name: Optional[str] = Field(None, alias="bucketName")
    flow_id: Optional[str] = Field(None, alias="flowId")
    flow_name: Optional[str] = Field(None, alias="flowName")
    flow_description: Optional[str] = Field(None, alias="flowDescription")
    version: Optional[int] = Field(None)
    state: Optional[str] = Field(None) # e.g., "LOCALLY_MODIFIED", "UP_TO_DATE"
    state_explanation: Optional[str] = Field(None, alias="stateExplanation")
    model_config = {"extra": "allow", "populate_by_name": True}

class VersionedFlowSnapshotBucketDTO(BaseModel):
    """Placeholder for VersionedFlowSnapshotBucketDTO"""
    identifier: Optional[str] = Field(None)
    name: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    created_timestamp: Optional[int] = Field(None, alias="createdTimestamp", format="int64") # Assuming timestamp is long
    permissions: Optional[PermissionDTO] = Field(None)
    model_config = {"extra": "allow", "populate_by_name": True}

class VersionedFlowSnapshotMetadataDTO(BaseModel):
    """Placeholder for VersionedFlowSnapshotMetadataDTO"""
    flow_identifier: Optional[str] = Field(None, alias="flowIdentifier")
    bucket_identifier: Optional[str] = Field(None, alias="bucketIdentifier")
    version: Optional[int] = Field(None, format="int32") # NiFi spec: version
    timestamp: Optional[int] = Field(None, format="int64") # NiFi spec: timestamp
    author: Optional[str] = Field(None)
    comments: Optional[str] = Field(None)
    branch: Optional[str] = Field(None) # Added from example
    model_config = {"extra": "allow", "populate_by_name": True}

class FlowSnippetDTO(BaseModel):
    """
    Represents a snippet of a dataflow components.
    Note: Fields based on common patterns, confirm with specific API endpoint schema if used.
    Source: Referenced in ProcessGroupDTO, VersionedFlowSnapshotDTO
    """
    processors: Optional[List[ProcessorEntity]] = Field(default=None)
    connections: Optional[List[ConnectionEntity]] = Field(default=None)
    input_ports: Optional[List[PortEntity]] = Field(default=None, alias="inputPorts")
    output_ports: Optional[List[PortEntity]] = Field(default=None, alias="outputPorts")
    funnels: Optional[List[Any]] = Field(default=None) # Placeholder for FunnelEntity
    labels: Optional[List[Any]] = Field(default=None) # Placeholder for LabelEntity
    process_groups: Optional[List[ProcessGroupEntity]] = Field(default=None, alias="processGroups")
    remote_process_groups: Optional[List[Any]] = Field(default=None, alias="remoteProcessGroups") # Placeholder for RemoteProcessGroupEntity
    controller_services: Optional[List[ControllerServiceEntity]] = Field(default=None, alias="controllerServices")

    model_config = {"extra": "allow", "populate_by_name": True}

class VersionedFlowSnapshotDTO(BaseModel):
    """Placeholder for VersionedFlowSnapshotDTO based on example"""
    snapshot_metadata: Optional[VersionedFlowSnapshotMetadataDTO] = Field(None, alias="snapshotMetadata")
    flow_contents: Optional[FlowSnippetDTO] = Field(None, alias="flowContents")
    external_controller_services: Optional[Dict[str, Any]] = Field(None, alias="externalControllerServices") # Placeholder
    parameter_contexts: Optional[Dict[str, Any]] = Field(None, alias="parameterContexts") # Placeholder
    flow_encoding_version: Optional[str] = Field(None, alias="flowEncodingVersion")
    flow: Optional[Any] = Field(None) # Placeholder for VersionedFlowDTO
    bucket: Optional[VersionedFlowSnapshotBucketDTO] = Field(None)
    latest: Optional[bool] = Field(None)
    model_config = {"extra": "allow", "populate_by_name": True}

class ConnectableDTO(BaseModel):
    """
    Represents a connectable component (source or destination of a connection).
    Source: NiFi 2.0 REST API Docs (ConnectionDTO spec)
    """
    id: str = Field(description="The id of the connectable component.")
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId", description="The ID of the corresponding component that is under version control")
    type: str = Field(description="The type of the connectable component.") # E.g. PROCESSOR, REMOTE_INPUT_PORT, REMOTE_OUTPUT_PORT, INPUT_PORT, OUTPUT_PORT, FUNNEL
    group_id: str = Field(alias="groupId", description="The id of the group that the connectable component resides in.")
    name: Optional[str] = Field(default=None, description="The name of the connectable component")
    running: Optional[bool] = Field(default=None, description="Whether the connectable component is running.")
    comments: Optional[str] = Field(default=None, description="The comments for the connectable component.")
    exists: Optional[bool] = Field(default=None, description="Whether the connectable component exists.")

    model_config = {"populate_by_name": True, "extra": "allow"}

class BundleDTO(BaseModel):
    """
    Information about the NiFi Archive (NAR) bundle that a component belongs to.
    Source: NiFi 2.0 REST API Docs (ProcessorDTO spec)
    """
    group: Optional[str] = Field(None, description="The group of the bundle.")
    artifact: Optional[str] = Field(None, description="The artifact of the bundle.")
    version: Optional[str] = Field(None, description="The version of the bundle.")
    model_config = {"extra": "allow"}

class PropertyDescriptorDTO(BaseModel):
    """Placeholder for PropertyDescriptorDTO"""
    name: Optional[str] = Field(None)
    # ... other descriptor fields: displayName, description, defaultValue, allowableValues, required, sensitive, dynamic, supportsEl, identifiesControllerService, identifiesControllerServiceBundle ...
    model_config = {"extra": "allow"}

class RelationshipDTO(BaseModel):
    """Placeholder for RelationshipDTO"""
    name: Optional[str] = Field(None, description="The relationship name.")
    description: Optional[str] = Field(None)
    auto_terminate: Optional[bool] = Field(None, alias="autoTerminate", description="Whether the relationship is auto-terminated.")
    # retired: Optional[bool] = None # Check NiFi 2.0 spec
    model_config = {"extra": "allow", "populate_by_name": True}

class ProcessorConfigDTO(BaseModel):
    """
    Configuration for a Processor, including properties, scheduling, etc.
    Source: NiFi 2.0 REST API Docs (ProcessorDTO.config)
    """
    properties: Optional[Dict[str, Optional[str]]] = Field(default=None, description="The properties for the processor. Properties whose value is not set will only contain the property name.")
    descriptors: Optional[Dict[str, PropertyDescriptorDTO]] = Field(default=None, description="Descriptors for the processor's properties.")
    scheduling_period: Optional[str] = Field(default=None, alias="schedulingPeriod", description="The scheduling period for the processor.") # e.g., "0 sec"
    scheduling_strategy: Optional[str] = Field(default=None, alias="schedulingStrategy", description="The scheduling strategy for the processor.") # E.g., TIMER_DRIVEN, CRON_DRIVEN
    execution_node: Optional[str] = Field(default=None, alias="executionNode", description="Indicates the node where the process will execute.") # E.g., ALL, PRIMARY
    penalty_duration: Optional[str] = Field(default=None, alias="penaltyDuration", description="The duration for which the processor should be penalized when yielded.") # e.g., "30 sec"
    yield_duration: Optional[str] = Field(default=None, alias="yieldDuration", description="The duration for which the processor should be yielded when the yield explicit is invoked.") # e.g., "1 sec"
    bulletin_level: Optional[str] = Field(default=None, alias="bulletinLevel", description="The level at which the processor will report bulletins.") # E.g., INFO, WARN, ERROR
    run_duration_millis: Optional[int] = Field(default=None, alias="runDurationMillis", description="The run duration for the processor in milliseconds.", format="int64")
    concurrently_schedulable_task_count: Optional[int] = Field(default=None, alias="concurrentlySchedulableTaskCount", description="The number of tasks that should be concurrently scheduled for the processor.", format="int32")
    auto_terminated_relationships: Optional[List[str]] = Field(default=None, alias="autoTerminatedRelationships", description="The names of all relationships that cause flowfiles to be auto-terminated.")
    comments: Optional[str] = Field(default=None, description="The comments for the processor.")
    custom_ui_url: Optional[HttpUrl] = Field(default=None, alias="customUiUrl", description="The URL for the processor's custom configuration UI if applicable.") # NiFi: [String] -> Map to HttpUrl
    loss_tolerant: Optional[bool] = Field(default=None, alias="lossTolerant", description="Whether the processor is loss tolerant.")
    # scheduled_state: Optional[str] = Field(default=None, alias="scheduledState") # State is usually on DTO/Entity, not config
    # retry_count: Optional[int] = Field(default=None, alias="retryCount") # Seems specific to snapshot example, not general config
    # retried_relationships: Optional[List[str]] = Field(default=None, alias="retriedRelationships") # Seems specific to snapshot example
    # backoff_mechanism: Optional[str] = Field(default=None, alias="backoffMechanism") # Seems specific to snapshot example
    default_concurrent_tasks: Optional[Dict[str, str]] = Field(default=None, alias="defaultConcurrentTasks", description="Default number of concurrent tasks for scheduling strategies.")
    default_scheduling_period: Optional[Dict[str, str]] = Field(default=None, alias="defaultSchedulingPeriod", description="Default scheduling period for scheduling strategies.")

    model_config = {"populate_by_name": True, "extra": "allow"}

# ===================================================================
# Authentication Related Models
# ===================================================================

class AuthenticationConfigurationDTO(BaseModel):
    """
    Details about the authentication configuration.
    Source: NiFi 2.0 REST API Docs > AuthenticationConfigurationEntity
    """
    external_login_required: Optional[bool] = Field(default=None, alias="externalLoginRequired", description="Whether the system requires login through an external Identity Provider")
    login_supported: Optional[bool] = Field(default=None, alias="loginSupported", description="Whether the system is configured to support login operations")
    login_uri: Optional[HttpUrl] = Field(default=None, alias="loginUri", description="Location for initiating login processing") # NiFi: [String] -> Map to HttpUrl
    logout_uri: Optional[HttpUrl] = Field(default=None, alias="logoutUri", description="Location for initiating logout processing") # NiFi: [String] -> Map to HttpUrl

    model_config = {
        "populate_by_name": True,
        "extra": "allow"
    }

class AuthenticationConfigurationEntity(BaseModel):
    """
    Entity wrapper for Authentication Configuration.
    Source: NiFi 2.0 REST API Docs
    """
    authentication_configuration: Optional[AuthenticationConfigurationDTO] = Field(default=None, alias="authenticationConfiguration")

    model_config = {
        "populate_by_name": True,
        "extra": "allow"
    }


# ===================================================================
# Process Group Related Models
# ===================================================================

class ProcessGroupDTO(BaseModel):
    """
    Detailed information about a Process Group.
    Source: NiFi 2.0 REST API Docs (Aggregated)
    """
    id: Optional[str] = Field(default=None, description="The id of the component.")
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId", description="The ID of the corresponding component that is under version control")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId", description="The id of parent process group.")
    position: Optional[PositionDTO] = Field(default=None, description="The position of this component in the UI if applicable.")
    name: Optional[str] = Field(default=None, description="The name of the process group.")
    comments: Optional[str] = Field(default=None, description="The comments for the process group.")
    running_count: Optional[int] = Field(default=None, alias="runningCount", format="int32")
    stopped_count: Optional[int] = Field(default=None, alias="stoppedCount", format="int32")
    invalid_count: Optional[int] = Field(default=None, alias="invalidCount", format="int32")
    disabled_count: Optional[int] = Field(default=None, alias="disabledCount", format="int32")
    active_remote_port_count: Optional[int] = Field(default=None, alias="activeRemotePortCount", format="int32")
    inactive_remote_port_count: Optional[int] = Field(default=None, alias="inactiveRemotePortCount", format="int32")
    up_to_date_count: Optional[int] = Field(default=None, alias="upToDateCount", format="int32")
    locally_modified_count: Optional[int] = Field(default=None, alias="locallyModifiedCount", format="int32")
    stale_count: Optional[int] = Field(default=None, alias="staleCount", format="int32")
    locally_modified_and_stale_count: Optional[int] = Field(default=None, alias="locallyModifiedAndStaleCount", format="int32")
    sync_failure_count: Optional[int] = Field(default=None, alias="syncFailureCount", format="int32")
    input_port_count: Optional[int] = Field(default=None, alias="inputPortCount", format="int32")
    output_port_count: Optional[int] = Field(default=None, alias="outputPortCount", format="int32")
    contents: Optional[FlowSnippetDTO] = Field(default=None, description="The contents of the process group.")
    variables: Optional[Dict[str, str]] = Field(default=None, description="The variables that are configured for the Process Group...")
    version_control_information: Optional[VersionControlInformationDTO] = Field(default=None, alias="versionControlInformation")
    parameter_context: Optional[ParameterContextReferenceEntity] = Field(default=None, alias="parameterContext")
    flowfile_concurrency: Optional[str] = Field(default=None, alias="flowfileConcurrency")
    flowfile_outbound_policy: Optional[str] = Field(default=None, alias="flowfileOutboundPolicy")
    default_flowfile_expiration: Optional[str] = Field(default=None, alias="defaultFlowFileExpiration")
    default_back_pressure_object_threshold: Optional[int] = Field(default=None, alias="defaultBackPressureObjectThreshold", format="int64")
    default_back_pressure_data_size_threshold: Optional[str] = Field(default=None, alias="defaultBackPressureDataSizeThreshold")
    log_file_suffix: Optional[str] = Field(default=None, alias="logFileSuffix")
    process_group_update_strategy: Optional[str] = Field(None, alias="processGroupUpdateStrategy") # From example

    model_config = {"populate_by_name": True, "extra": "allow"}

class ProcessGroupEntity(BaseModel):
    """
    Entity wrapper for a Process Group. Includes component DTO and metadata.
    Source: NiFi 2.0 REST API Docs (Aggregated + common entity structure)
    """
    revision: Optional[RevisionDTO] = Field(None, description="The revision information for this entity.")
    id: Optional[str] = Field(default=None, description="The id of the component.")
    uri: Optional[HttpUrl] = Field(default=None, description="The URI for futures requests to this component.")
    position: Optional[PositionDTO] = Field(default=None, description="The position of this component in the UI if applicable.")
    permissions: Optional[PermissionDTO] = Field(default=None, description="The permissions for this component.")
    bulletins: Optional[List[BulletinEntity]] = Field(default=None, description="The bulletins for this component.")
    disconnected_node_acknowledged: Optional[bool] = Field(default=None, alias="disconnectedNodeAcknowledged", description="Acknowledges that this node is disconnected to allow for mutable requests to proceed.")
    component: Optional[ProcessGroupDTO] = Field(default=None, description="The process group component.")
    status: Optional[Any] = Field(default=None, description="The status of the process group.") # Placeholder for ProcessGroupStatusDTO
    versioned_flow_snapshot: Optional[VersionedFlowSnapshotDTO] = Field(default=None, alias="versionedFlowSnapshot", description="The snapshot of the versioned flow")
    running_count: Optional[int] = Field(default=None, alias="runningCount", format="int32")
    stopped_count: Optional[int] = Field(default=None, alias="stoppedCount", format="int32")
    invalid_count: Optional[int] = Field(default=None, alias="invalidCount", format="int32")
    disabled_count: Optional[int] = Field(default=None, alias="disabledCount", format="int32")
    active_remote_port_count: Optional[int] = Field(default=None, alias="activeRemotePortCount", format="int32")
    inactive_remote_port_count: Optional[int] = Field(default=None, alias="inactiveRemotePortCount", format="int32")
    up_to_date_count: Optional[int] = Field(default=None, alias="upToDateCount", format="int32")
    locally_modified_count: Optional[int] = Field(default=None, alias="locallyModifiedCount", format="int32")
    stale_count: Optional[int] = Field(default=None, alias="staleCount", format="int32")
    locally_modified_and_stale_count: Optional[int] = Field(default=None, alias="locallyModifiedAndStaleCount", format="int32")
    sync_failure_count: Optional[int] = Field(default=None, alias="syncFailureCount", format="int32")
    local_input_port_count: Optional[int] = Field(default=None, alias="localInputPortCount", format="int32")
    local_output_port_count: Optional[int] = Field(default=None, alias="localOutputPortCount", format="int32")
    public_input_port_count: Optional[int] = Field(default=None, alias="publicInputPortCount", format="int32")
    public_output_port_count: Optional[int] = Field(default=None, alias="publicOutputPortCount", format="int32")
    parameter_context: Optional[ParameterContextReferenceEntity] = Field(default=None, alias="parameterContext")
    parameter_context_name: Optional[str] = Field(default=None, alias="parameterContextName")
    input_port_count: Optional[int] = Field(default=None, alias="inputPortCount", format="int32")
    output_port_count: Optional[int] = Field(default=None, alias="outputPortCount", format="int32")
    process_group_update_strategy: Optional[str] = Field(None, alias="processGroupUpdateStrategy") # From example

    model_config = {"populate_by_name": True, "extra": "allow"}


# ===================================================================
# Processor Related Models
# ===================================================================

class ProcessorDTO(BaseModel):
    """
    Detailed information about a Processor.
    Source: NiFi 2.0 REST API Docs
    """
    id: Optional[str] = Field(default=None, description="The id of the component.")
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId", description="The ID of the corresponding component that is under version control")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId", description="The id of parent process group.")
    position: Optional[PositionDTO] = Field(default=None, description="The position of this component in the UI if applicable.")
    name: Optional[str] = Field(default=None, description="The name of the processor.")
    type: Optional[str] = Field(default=None, description="The type of the processor.")
    bundle: Optional[BundleDTO] = Field(default=None, description="The bundle for the processor.")
    state: Optional[str] = Field(default=None, description="The state of the processor.")
    style: Optional[Dict[str, str]] = Field(default=None, description="Styles for the processor (background-color, etc).")
    relationships: Optional[List[RelationshipDTO]] = Field(default=None, description="The available relationships that the processor currently supports.")
    description: Optional[str] = Field(default=None, description="The description of the processor.")
    supports_parallel_processing: Optional[bool] = Field(default=None, alias="supportsParallelProcessing")
    supports_event_driven: Optional[bool] = Field(default=None, alias="supportsEventDriven")
    supports_batching: Optional[bool] = Field(default=None, alias="supportsBatching")
    persists_state: Optional[bool] = Field(default=None, alias="persistsState")
    restricted: Optional[bool] = Field(default=None)
    deprecated: Optional[bool] = Field(default=None)
    multiple_versions_available: Optional[bool] = Field(default=None, alias="multipleVersionsAvailable")
    input_requirement: Optional[str] = Field(default=None, alias="inputRequirement")
    config: Optional[ProcessorConfigDTO] = Field(default=None, description="The configuration details for the processor.")
    validation_errors: Optional[List[str]] = Field(default=None, alias="validationErrors")
    extension_missing: Optional[bool] = Field(default=None, alias="extensionMissing")
    # Added from ProcessorEntity example (though might be config)
    bulletin_level: Optional[str] = Field(default=None, alias="bulletinLevel", description="The level at which the processor will report bulletins.")
    comments: Optional[str] = Field(default=None, description="The user-supplied comments for the processor.")

    model_config = {"populate_by_name": True, "extra": "allow"}

class ProcessorEntity(BaseModel):
    """
    Entity wrapper for a Processor.
    Source: NiFi 2.0 REST API Docs
    """
    revision: Optional[RevisionDTO] = Field(None, description="The revision information for this entity.")
    id: Optional[str] = Field(default=None)
    uri: Optional[HttpUrl] = Field(default=None)
    position: Optional[PositionDTO] = Field(default=None)
    permissions: Optional[PermissionDTO] = Field(default=None)
    bulletins: Optional[List[BulletinEntity]] = Field(default=None)
    disconnected_node_acknowledged: Optional[bool] = Field(default=None, alias="disconnectedNodeAcknowledged")
    component: Optional[ProcessorDTO] = Field(default=None)
    input_requirement: Optional[str] = Field(default=None, alias="inputRequirement")
    status: Optional[Any] = Field(default=None) # Placeholder for ProcessorStatusDTO
    operate_permissions: Optional[PermissionDTO] = Field(default=None, alias="operatePermissions")

    model_config = {"populate_by_name": True, "extra": "allow"}


# ===================================================================
# Connection Related Models
# ===================================================================

class ConnectionDTO(BaseModel):
    """
    Detailed information about a Connection.
    Source: NiFi 2.0 REST API Docs
    """
    id: Optional[str] = Field(default=None)
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId")
    position: Optional[PositionDTO] = Field(default=None)
    source: Optional[ConnectableDTO] = Field(default=None)
    destination: Optional[ConnectableDTO] = Field(default=None)
    name: Optional[str] = Field(default=None)
    label_index: Optional[int] = Field(default=None, alias="labelIndex", format="int32")
    z_index: Optional[int] = Field(default=None, alias="zIndex", format="int64")
    selected_relationships: Optional[List[str]] = Field(default=None, alias="selectedRelationships")
    available_relationships: Optional[List[str]] = Field(default=None, alias="availableRelationships")
    back_pressure_object_threshold: Optional[int] = Field(default=None, alias="backPressureObjectThreshold", format="int64")
    back_pressure_data_size_threshold: Optional[str] = Field(default=None, alias="backPressureDataSizeThreshold")
    flow_file_expiration: Optional[str] = Field(default=None, alias="flowFileExpiration")
    prioritizers: Optional[List[str]] = Field(default=None)
    bends: Optional[List[PositionDTO]] = Field(default=None)
    load_balance_strategy: Optional[str] = Field(default=None, alias="loadBalanceStrategy")
    load_balance_partition_attribute: Optional[str] = Field(default=None, alias="loadBalancePartitionAttribute")
    load_balance_compression: Optional[str] = Field(default=None, alias="loadBalanceCompression")
    source_id: Optional[str] = Field(default=None, alias="sourceId")
    source_group_id: Optional[str] = Field(default=None, alias="sourceGroupId")
    source_type: Optional[str] = Field(default=None, alias="sourceType")
    destination_id: Optional[str] = Field(default=None, alias="destinationId")
    destination_group_id: Optional[str] = Field(default=None, alias="destinationGroupId")
    destination_type: Optional[str] = Field(default=None, alias="destinationType")

    model_config = {"populate_by_name": True, "extra": "allow"}

class ConnectionEntity(BaseModel):
    """
    Entity wrapper for a Connection.
    Source: NiFi 2.0 REST API Docs
    """
    revision: Optional[RevisionDTO] = Field(None)
    id: Optional[str] = Field(default=None)
    uri: Optional[HttpUrl] = Field(default=None)
    position: Optional[PositionDTO] = Field(default=None)
    permissions: Optional[PermissionDTO] = Field(default=None)
    bulletins: Optional[List[BulletinEntity]] = Field(default=None)
    disconnected_node_acknowledged: Optional[bool] = Field(default=None, alias="disconnectedNodeAcknowledged")
    component: Optional[ConnectionDTO] = Field(default=None)
    status: Optional[Any] = Field(default=None) # Placeholder for ConnectionStatusDTO
    bends: Optional[List[PositionDTO]] = Field(default=None)
    label_index: Optional[int] = Field(default=None, alias="labelIndex", format="int32")
    z_index: Optional[int] = Field(default=None, alias="zIndex", format="int64")
    source_id: Optional[str] = Field(default=None, alias="sourceId")
    source_group_id: Optional[str] = Field(default=None, alias="sourceGroupId")
    source_type: Optional[str] = Field(default=None, alias="sourceType")
    destination_id: Optional[str] = Field(default=None, alias="destinationId")
    destination_group_id: Optional[str] = Field(default=None, alias="destinationGroupId")
    destination_type: Optional[str] = Field(default=None, alias="destinationType")

    model_config = {"populate_by_name": True, "extra": "allow"}

# ===================================================================
# Input/Output Port Related Models
# ===================================================================

class PortDTO(BaseModel):
    """
    Detailed information about an Input or Output Port.
    Source: NiFi 2.0 REST API Docs
    """
    id: Optional[str] = Field(default=None)
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId")
    position: Optional[PositionDTO] = Field(default=None)
    name: Optional[str] = Field(default=None)
    comments: Optional[str] = Field(default=None)
    state: Optional[str] = Field(default=None)
    type: Optional[str] = Field(default=None) # INPUT_PORT or OUTPUT_PORT
    transmitting: Optional[bool] = Field(default=None)
    concurrently_schedulable_task_count: Optional[int] = Field(default=None, alias="concurrentlySchedulableTaskCount", format="int32")
    user_access_control: Optional[List[str]] = Field(default=None, alias="userAccessControl")
    group_access_control: Optional[List[str]] = Field(default=None, alias="groupAccessControl")
    validation_errors: Optional[List[str]] = Field(default=None, alias="validationErrors")
    allow_remote_access: Optional[bool] = Field(default=None, alias="allowRemoteAccess") # Only applicable to Input Ports? Check spec.
    # Added from PortEntity example
    bulletin_level: Optional[str] = Field(default=None, alias="bulletinLevel", description="The level at which the port will report bulletins.")


    model_config = {"populate_by_name": True, "extra": "allow"}

class PortEntity(BaseModel):
    """
    Entity wrapper for an Input or Output Port.
    Source: NiFi 2.0 REST API Docs
    """
    revision: Optional[RevisionDTO] = Field(None)
    id: Optional[str] = Field(default=None)
    uri: Optional[HttpUrl] = Field(default=None)
    position: Optional[PositionDTO] = Field(default=None)
    permissions: Optional[PermissionDTO] = Field(default=None)
    bulletins: Optional[List[BulletinEntity]] = Field(default=None)
    disconnected_node_acknowledged: Optional[bool] = Field(default=None, alias="disconnectedNodeAcknowledged")
    component: Optional[PortDTO] = Field(default=None)
    status: Optional[Any] = Field(default=None) # Placeholder for PortStatusDTO
    port_type: Optional[str] = Field(default=None, alias="portType") # e.g. INPUT_PORT, OUTPUT_PORT
    operate_permissions: Optional[PermissionDTO] = Field(default=None, alias="operatePermissions")
    allow_remote_access: Optional[bool] = Field(default=None, alias="allowRemoteAccess") # Convenience access

    model_config = {"populate_by_name": True, "extra": "allow"}

# ===================================================================
# Generic Models for NiFi Client (not directly from API endpoints)
# ===================================================================

class NiFiClientCreds(BaseModel):
    """
    Parameters for initializing the NiFi API client via MCP _meta.
    Holds credentials for the NiFi instance.
    """
    username: Optional[str] = Field(default=None, description="Username for NiFi authentication.")
    password: Optional[str] = Field(default=None, description="Password for NiFi authentication.")
    token: Optional[str] = Field(default=None, description="Pre-existing JWT for NiFi authentication.")
    url: Optional[HttpUrl] = Field(default=None, description="Optional NiFi Base URL override from client.")
    ssl_verify: Optional[bool] = Field(default=None, description="Optional SSL verification override from client (True/False).")

    @field_validator('*', mode='before')
    @classmethod
    def validate_creds(cls, data: Any, info: ValidationInfo) -> Any:
        # This validator runs for the whole model AFTER individual fields
        if info.field_name is None: # Only run for the whole model
            if isinstance(data, dict):
                username, password, token = data.get('username'), data.get('password'), data.get('token')
                if token is None and (username is None or password is None):
                    raise ValueError("Either 'token' or both 'username' and 'password' must be provided for NiFi authentication.")
                if token is not None and (username is not None or password is not None):
                    raise ValueError("Provide either 'token' or 'username'/'password', not both.")
        return data

class NiFiAuthException(Exception):
    """Custom exception for NiFi authentication failures."""
    pass

class NiFiApiException(Exception):
    """Custom exception for general NiFi API errors."""
    def __init__(self, status_code: int, message: str, response_text: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.response_text = response_text

    def __str__(self):
        return f"NiFi API Error {self.status_code}: {self.message}" + (f" - Response: {self.response_text}" if self.response_text else "")

# ===================================================================
# Update Forward References
# Call model_rebuild() for any model that uses a type hint before its definition.
# ===================================================================
ProcessGroupDTO.model_rebuild()
FlowSnippetDTO.model_rebuild()
VersionedFlowSnapshotDTO.model_rebuild()
ProcessorDTO.model_rebuild()
ConnectionDTO.model_rebuild()
PortDTO.model_rebuild()
ProcessGroupEntity.model_rebuild()
ProcessorEntity.model_rebuild()
ConnectionEntity.model_rebuild()
PortEntity.model_rebuild()
# Add any other models that need rebuilding as the file grows