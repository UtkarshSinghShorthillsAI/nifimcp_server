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

class ProcessGroupsEntity(BaseModel): pass # NEW
class ProcessorsEntity(BaseModel): pass   # NEW
class ProcessGroupContentOverviewDTO(BaseModel): pass # NEW

# NEW/UPDATED FOR PROCESSORS:
class ProcessorStatusDTO(BaseModel): pass
class ProcessorRunStatusEntity(BaseModel): pass
# ProcessorRunStatusDTO might not be needed if ProcessorRunStatusEntity directly holds 'state'

# For other /processors endpoints (to be implemented later)
class ConfigurationAnalysisDTO(BaseModel): pass
class ConfigurationAnalysisEntity(BaseModel): pass
class LocalStateEntryDTO(BaseModel): pass
class ClusterStateDTO(BaseModel): pass
class ComponentStateDTO(BaseModel): pass
class ComponentStateEntity(BaseModel): pass
class PropertyDependencyDTO(BaseModel): pass
# PropertyDescriptorDTO already declared
class PropertyDescriptorEntity(BaseModel): pass
class VerificationResultDTO(BaseModel): pass
class VerifyConfigRequestDTO(BaseModel): pass
class VerifyConfigRequestEntity(BaseModel): pass
class ProcessorRunStatusDetailsDTO(BaseModel): pass
class ProcessorsRunStatusDetailsEntity(BaseModel): pass
class RunStatusDetailsRequestEntity(BaseModel): pass

# NEW FOR /flow/processor-types
class ControllerServiceApiDTO(BaseModel): pass
class RequiredPermissionDTO(BaseModel): pass
class ExplicitRestrictionDTO(BaseModel): pass
class DocumentedTypeDTO(BaseModel): pass
class ProcessorTypesEntity(BaseModel): pass


# NEW/UPDATED FOR CONNECTIONS:
class ConnectionsEntity(BaseModel): pass # NEW
class ConnectionStatusDTO(BaseModel): pass # NEW
class ConnectionStatusPredictionsSnapshotDTO(BaseModel): pass # NEW (nested)
class NodeConnectionStatisticsSnapshotDTO(BaseModel): pass # NEW (nested)
class ConnectionStatisticsSnapshotDTO(BaseModel): pass # NEW (nested)
class ConnectionStatusEntity(BaseModel): pass # NEW
class StatusHistoryEntity(BaseModel): pass # NEW (placeholder for now)
class ConnectionStatisticsDTO(BaseModel): pass # NEW
class ConnectionStatisticsEntity(BaseModel): pass # NEW

# NEW FOR CONTROLLER SERVICES
class ControllerServiceDTO(BaseModel): pass
class ControllerServiceReferencingComponentEntity(BaseModel): pass
class ControllerServiceReferencingComponentsEntity(BaseModel): pass
class ControllerServiceRunStatusEntity(BaseModel): pass
class ControllerServicesEntity(BaseModel): pass
class ControllerServiceTypesEntity(BaseModel): pass
class ControllerServiceStatusDTO(BaseModel): pass

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
    can_delete: Optional[bool] = Field(default=None, alias="canDelete")


    model_config = {
        "populate_by_name": True,
        "extra": "allow"
    }

# ===================================================================
# Placeholder DTO Definitions (Referenced by others)
# ===================================================================

class BulletinEntity(BaseModel):
    """Placeholder for BulletinEntity"""
    id: Optional[int] = Field(None)
    message: Optional[str] = Field(None)
    model_config = {"extra": "allow"}

class ParameterContextReferenceEntity(BaseModel):
    """Placeholder for ParameterContextReferenceEntity"""
    id: Optional[str] = Field(None)
    name: Optional[str] = Field(None)
    permissions: Optional[PermissionDTO] = None
    model_config = {"extra": "allow"}

class FlowRegistryClientEntity(BaseModel):
    """Placeholder for FlowRegistryClientEntity"""
    id: Optional[str] = Field(None)
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
    model_config = {"extra": "allow", "populate_by_name": True}

class VersionedFlowUpdateRequestDTO(BaseModel):
    """Placeholder for VersionedFlowUpdateRequestDTO"""
    request_id: Optional[str] = Field(None, alias="requestId")
    uri: Optional[HttpUrl] = Field(None)
    complete: Optional[bool] = Field(None)
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
    state: Optional[str] = Field(None)
    state_explanation: Optional[str] = Field(None, alias="stateExplanation")
    model_config = {"extra": "allow", "populate_by_name": True}

class VersionedFlowSnapshotBucketDTO(BaseModel):
    """Placeholder for VersionedFlowSnapshotBucketDTO"""
    identifier: Optional[str] = Field(None)
    name: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    created_timestamp: Optional[int] = Field(None, alias="createdTimestamp")
    permissions: Optional[PermissionDTO] = Field(None)
    model_config = {"extra": "allow", "populate_by_name": True}

class VersionedFlowSnapshotMetadataDTO(BaseModel):
    """Placeholder for VersionedFlowSnapshotMetadataDTO"""
    flow_identifier: Optional[str] = Field(None, alias="flowIdentifier")
    bucket_identifier: Optional[str] = Field(None, alias="bucketIdentifier")
    version: Optional[int] = Field(None)
    timestamp: Optional[int] = Field(None)
    author: Optional[str] = Field(None)
    comments: Optional[str] = Field(None)
    branch: Optional[str] = Field(None)
    model_config = {"extra": "allow", "populate_by_name": True}

class ConnectionDTO(BaseModel): # Review and update
    """
    The configuration details for a Connection.
    Source: NiFi 2.0 REST API Docs (ConnectionDTO section, also inferred from ConnectionEntity)
    """
    id: Optional[str] = Field(default=None, description="The id of the connection.")
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId", description="The ID of the corresponding component that is under version control.")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId", description="The ID of the parent process group of this connection.") # Also known as groupIdentifier sometimes

    name: Optional[str] = Field(default=None, description="The name of the connection.")
    comments: Optional[str] = Field(default=None, description="The comments for the connection.")

    source: Optional[ConnectableDTO] = Field(default=None, description="The source of the connection.")
    destination: Optional[ConnectableDTO] = Field(default=None, description="The destination of the connection.")
    
    selected_relationships: Optional[List[str]] = Field(default=None, alias="selectedRelationships", description="The selected relationships that comprise the connection.")
    # available_relationships: Optional[List[str]] = Field(default=None, alias="availableRelationships", description="The relationships that are available from the source component.") # Usually read-only, not part of create/update payload directly

    label_index: Optional[int] = Field(default=None, alias="labelIndex", description="The index of the bend point where to place the connection label.")
    z_index: Optional[int] = Field(default=None, alias="zIndex", description="The z-index for the connection.")
    bends: Optional[List[PositionDTO]] = Field(default=None, description="The bend points on the connection.")

    flow_file_expiration: Optional[str] = Field(default=None, alias="flowFileExpiration", description="The FlowFile expiration period for the connection.")
    back_pressure_data_size_threshold: Optional[str] = Field(default=None, alias="backPressureDataSizeThreshold", description="The FlowFile Data Size threshold for backpressure.")
    back_pressure_object_threshold: Optional[int] = Field(default=None, alias="backPressureObjectThreshold", description="The FlowFile Count threshold for backpressure.") # NiFi: format int64
    
    load_balance_strategy: Optional[str] = Field(default=None, alias="loadBalanceStrategy", description="The load balancing strategy for the connection (e.g., DO_NOT_LOAD_BALANCE, ROUND_ROBIN, PARTITION_BY_ATTRIBUTE).")
    load_balance_partition_attribute: Optional[str] = Field(default=None, alias="loadBalancePartitionAttribute", description="The attribute to use for partitioning data if loadBalanceStrategy is PARTITION_BY_ATTRIBUTE.")
    load_balance_compression: Optional[str] = Field(default=None, alias="loadBalanceCompression", description="The compression to use for load balancing (e.g., DO_NOT_COMPRESS, COMPRESS_ATTRIBUTES_ONLY, COMPRESS_ATTRIBUTES_AND_CONTENT).")
    
    prioritizers: Optional[List[str]] = Field(default=None, description="The FlowFile prioritizers to use for this connection.")

    # group_identifier: Optional[str] = Field(None, alias="groupIdentifier") # This is parent_group_id
    # instance_identifier: Optional[str] = Field(None, alias="instanceIdentifier") # This seems to be internal

    model_config = {"populate_by_name": True, "extra": "allow"}


# --- Models for Connection Status & Statistics ---
class ConnectionStatusPredictionsSnapshotDTO(BaseModel): # Placeholder
    predicted_millis_until_count_backpressure: Optional[int] = Field(None, alias="predictedMillisUntilCountBackpressure")
    predicted_millis_until_bytes_backpressure: Optional[int] = Field(None, alias="predictedMillisUntilBytesBackpressure")
    prediction_interval_seconds: Optional[int] = Field(None, alias="predictionIntervalSeconds")
    # ... other prediction fields
    model_config = {"populate_by_name": True, "extra": "allow"}

class ConnectionStatisticsSnapshotDTO(BaseModel): # Placeholder
    id: Optional[str] = Field(None)
    source_id: Optional[str] = Field(None, alias="sourceId")
    source_name: Optional[str] = Field(None, alias="sourceName")
    destination_id: Optional[str] = Field(None, alias="destinationId")
    destination_name: Optional[str] = Field(None, alias="destinationName")
    flow_files_in: Optional[int] = Field(None, alias="flowFilesIn")
    bytes_in: Optional[int] = Field(None, alias="bytesIn") # NiFi: long
    input: Optional[str] = Field(None) # Pretty printed
    flow_files_out: Optional[int] = Field(None, alias="flowFilesOut")
    bytes_out: Optional[int] = Field(None, alias="bytesOut") # NiFi: long
    output: Optional[str] = Field(None) # Pretty printed
    flow_files_queued: Optional[int] = Field(None, alias="flowFilesQueued")
    bytes_queued: Optional[int] = Field(None, alias="bytesQueued") # NiFi: long
    queued: Optional[str] = Field(None) # Pretty printed
    queued_count: Optional[str] = Field(None, alias="queuedCount") # Example: "100 / 10000"
    queued_size: Optional[str] = Field(None, alias="queuedSize")   # Example: "1 MB / 1 GB"
    percent_use_count: Optional[int] = Field(None, alias="percentUseCount")
    percent_use_bytes: Optional[int] = Field(None, alias="percentUseBytes")
    # ... other snapshot fields
    model_config = {"populate_by_name": True, "extra": "allow"}

class NodeConnectionStatisticsSnapshotDTO(BaseModel): # Placeholder
    node_id: Optional[str] = Field(None, alias="nodeId")
    address: Optional[str] = Field(None)
    api_port: Optional[int] = Field(None, alias="apiPort")
    statistics: Optional[ConnectionStatisticsSnapshotDTO] = Field(None)
    model_config = {"populate_by_name": True, "extra": "allow"}

class ConnectionStatusDTO(BaseModel): # Defined from API doc
    id: Optional[str] = Field(None, description="The ID of the connection.")
    group_id: Optional[str] = Field(None, alias="groupId", description="The ID of the Process Group that the connection belongs to.")
    name: Optional[str] = Field(None, description="The name of the connection.")
    source_id: Optional[str] = Field(None, alias="sourceId", description="The ID of the source component.")
    source_name: Optional[str] = Field(None, alias="sourceName", description="The name of the source component.")
    destination_id: Optional[str] = Field(None, alias="destinationId", description="The ID of the destination component.")
    destination_name: Optional[str] = Field(None, alias="destinationName", description="The name of the destination component.")
    
    flow_files_in: Optional[int] = Field(None, alias="flowFilesIn", description="The number of FlowFiles that have come into the connection in the last 5 minutes.")
    bytes_in: Optional[int] = Field(None, alias="bytesIn", description="The size of the FlowFiles that have come into the connection in the last 5 minutes.") # NiFi uses long
    input: Optional[str] = Field(None, description="The count and size of flowfiles that have come into the connection in the last 5 minutes.") # Pretty printed
    
    flow_files_out: Optional[int] = Field(None, alias="flowFilesOut", description="The number of FlowFiles that have left the connection in the last 5 minutes.")
    bytes_out: Optional[int] = Field(None, alias="bytesOut", description="The size of the FlowFiles that have left the connection in the last 5 minutes.") # NiFi uses long
    output: Optional[str] = Field(None, description="The count and size of flowfiles that have left the connection in the last 5 minutes.") # Pretty printed
    
    flow_files_queued: Optional[int] = Field(None, alias="flowFilesQueued", description="The number of FlowFiles that are currently queued in the connection.")
    bytes_queued: Optional[int] = Field(None, alias="bytesQueued", description="The size of the FlowFiles that are currently queued in the connection.") # NiFi uses long
    queued: Optional[str] = Field(None, description="The count and size of flowfiles that are currently queued in the connection.") # Pretty printed

    percent_use_count: Optional[int] = Field(None, alias="percentUseCount", description="The percent of queue capacity used in terms of FlowFile count.")
    percent_use_bytes: Optional[int] = Field(None, alias="percentUseBytes", description="The percent of queue capacity used in terms of data size.")
    
    predictions: Optional[ConnectionStatusPredictionsSnapshotDTO] = Field(None, description="Predictions, if available, for this connection.")
    
    # For clustered environments
    node_snapshots: Optional[List[NodeConnectionStatisticsSnapshotDTO]] = Field(None, alias="nodeSnapshots", description="The status snapshot for each node in the cluster. If the NiFi instance is a standalone instance, rather than a clustered instance, this will be null.")
    aggregate_snapshot: Optional[ConnectionStatisticsSnapshotDTO] = Field(None, alias="aggregateSnapshot", description="The aggregate status snapshot for all nodes in the cluster.") # This seems to be ConnectionStatusDTO itself in standalone, or an aggregation. Let's use ConnectionStatisticsSnapshotDTO as per docs.
    stats_last_refreshed: Optional[str] = Field(None, alias="statsLastRefreshed", description="The timestamp when the status was last refreshed.")
    
    model_config = {"populate_by_name": True, "extra": "allow"}

class ConnectionStatusEntity(BaseModel): # NEW
    can_read: Optional[bool] = Field(None, description="Indicates whether the user can read a connection status.")
    connection_status: Optional[ConnectionStatusDTO] = Field(None, alias="connectionStatus")
    model_config = {"populate_by_name": True, "extra": "allow"}

class StatusHistoryEntity(BaseModel): # NEW - Placeholder for now
    # Define based on actual `statusHistory` structure, e.g.
    # status_history: Optional[StatusHistoryDTO] = Field(None, alias="statusHistory")
    can_read: Optional[bool] = Field(None)
    model_config = {"populate_by_name": True, "extra": "allow"}

class ConnectionStatisticsDTO(BaseModel): # NEW
    id: Optional[str] = Field(None, description="The ID of the connection.")
    stats_last_refreshed: Optional[str] = Field(None, alias="statsLastRefreshed", description="The timestamp when the stats were last refreshed.")
    aggregate_snapshot: Optional[ConnectionStatisticsSnapshotDTO] = Field(None, alias="aggregateSnapshot", description="The aggregate statistics for all nodes in the cluster.")
    node_snapshots: Optional[List[NodeConnectionStatisticsSnapshotDTO]] = Field(None, alias="nodeSnapshots", description="A list of status snapshots for each node")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ConnectionStatisticsEntity(BaseModel): # NEW
    connection_statistics: Optional[ConnectionStatisticsDTO] = Field(None, alias="connectionStatistics")
    can_read: Optional[bool] = Field(None, description="Indicates whether the user can read the connection statistics.")
    model_config = {"populate_by_name": True, "extra": "allow"}


class BundleDTO(BaseModel):
    group: Optional[str] = Field(None, description="The group of the bundle.")
    artifact: Optional[str] = Field(None, description="The artifact of the bundle.")
    version: Optional[str] = Field(None, description="The version of the bundle.")
    model_config = {"extra": "allow"}

class PropertyDependencyDTO(BaseModel):
    property_name: Optional[str] = Field(None, alias="propertyName")
    dependent_values: Optional[List[str]] = Field(None, alias="dependentValues")
    model_config = {"extra": "allow", "populate_by_name": True}

class PropertyDescriptorDTO(BaseModel):
    name: Optional[str] = Field(None, description="The name of the property.")
    display_name: Optional[str] = Field(None, alias="displayName", description="The human-readable name for the property.")
    description: Optional[str] = Field(None, description="A description of the property.")
    default_value: Optional[str] = Field(None, alias="defaultValue", description="The default value for the property.")
    required: Optional[bool] = Field(None, description="Whether the property is required.")
    sensitive: Optional[bool] = Field(None, description="Whether the property is sensitive.")
    supports_el: Optional[bool] = Field(None, alias="supportsEl", description="Whether the property supports Expression Language.")
    expression_language_scope: Optional[str] = Field(None, alias="expressionLanguageScope", description="Scope of the Expression Language evaluation.")
    dependencies: Optional[List[PropertyDependencyDTO]] = Field(None, description="Any dependencies of the property.")
    # allowable_values, dynamic, identifies_controller_service, identifies_controller_service_bundle can be added if needed
    model_config = {"extra": "allow", "populate_by_name": True}


class RelationshipDTO(BaseModel):
    name: Optional[str] = Field(None, description="The relationship name.")
    description: Optional[str] = Field(None)
    auto_terminate: Optional[bool] = Field(None, alias="autoTerminate", description="Whether the relationship is auto-terminated.")
    retry: Optional[bool] = Field(None, description="Whether the relationship is retryable.") # From createProcessor example
    model_config = {"extra": "allow", "populate_by_name": True}

class ProcessorConfigDTO(BaseModel):
    properties: Optional[Dict[str, Optional[str]]] = Field(default=None, description="The properties for the processor.")
    descriptors: Optional[Dict[str, PropertyDescriptorDTO]] = Field(default=None, description="Descriptors for the processor's properties.")
    scheduling_period: Optional[str] = Field(default=None, alias="schedulingPeriod")
    scheduling_strategy: Optional[str] = Field(default=None, alias="schedulingStrategy")
    execution_node: Optional[str] = Field(default=None, alias="executionNode")
    penalty_duration: Optional[str] = Field(default=None, alias="penaltyDuration")
    yield_duration: Optional[str] = Field(default=None, alias="yieldDuration")
    bulletin_level: Optional[str] = Field(default=None, alias="bulletinLevel")
    run_duration_millis: Optional[int] = Field(default=None, alias="runDurationMillis")
    concurrently_schedulable_task_count: Optional[int] = Field(default=None, alias="concurrentlySchedulableTaskCount")
    auto_terminated_relationships: Optional[List[str]] = Field(default=None, alias="autoTerminatedRelationships")
    comments: Optional[str] = Field(default=None)
    custom_ui_url: Optional[HttpUrl] = Field(default=None, alias="customUiUrl")
    loss_tolerant: Optional[bool] = Field(default=None, alias="lossTolerant")
    default_concurrent_tasks: Optional[Dict[str, str]] = Field(default=None, alias="defaultConcurrentTasks")
    default_scheduling_period: Optional[Dict[str, str]] = Field(default=None, alias="defaultSchedulingPeriod")
    annotation_data: Optional[str] = Field(None, alias="annotationData", description="The annotation data for the processor.") # From createProcessor example
    retry_count: Optional[int] = Field(None, alias="retryCount", description="The number of times to retry a failed task.") # From createProcessor example, verify if general
    model_config = {"populate_by_name": True, "extra": "allow"}

# ===================================================================
# Authentication Related Models
# ... (AuthenticationConfigurationDTO, AuthenticationConfigurationEntity remain the same) ...
# ===================================================================
class AuthenticationConfigurationDTO(BaseModel):
    external_login_required: Optional[bool] = Field(default=None, alias="externalLoginRequired", description="Whether the system requires login through an external Identity Provider")
    login_supported: Optional[bool] = Field(default=None, alias="loginSupported", description="Whether the system is configured to support login operations")
    login_uri: Optional[HttpUrl] = Field(default=None, alias="loginUri", description="Location for initiating login processing")
    logout_uri: Optional[HttpUrl] = Field(default=None, alias="logoutUri", description="Location for initiating logout processing")
    model_config = {"populate_by_name": True, "extra": "allow"}

class AuthenticationConfigurationEntity(BaseModel):
    authentication_configuration: Optional[AuthenticationConfigurationDTO] = Field(default=None, alias="authenticationConfiguration")
    model_config = {"populate_by_name": True, "extra": "allow"}

# ===================================================================
# Process Group Related Models
# ... (ProcessGroupDTO, ProcessGroupEntity remain the same) ...
# ===================================================================
class ProcessGroupDTO(BaseModel):
    id: Optional[str] = Field(default=None, description="The id of the component.")
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId")
    position: Optional[PositionDTO] = Field(default=None)
    name: Optional[str] = Field(default=None)
    comments: Optional[str] = Field(default=None)
    running_count: Optional[int] = Field(default=None, alias="runningCount")
    stopped_count: Optional[int] = Field(default=None, alias="stoppedCount")
    invalid_count: Optional[int] = Field(default=None, alias="invalidCount")
    disabled_count: Optional[int] = Field(default=None, alias="disabledCount")
    active_remote_port_count: Optional[int] = Field(default=None, alias="activeRemotePortCount")
    inactive_remote_port_count: Optional[int] = Field(default=None, alias="inactiveRemotePortCount")
    up_to_date_count: Optional[int] = Field(default=None, alias="upToDateCount")
    locally_modified_count: Optional[int] = Field(default=None, alias="locallyModifiedCount")
    stale_count: Optional[int] = Field(default=None, alias="staleCount")
    locally_modified_and_stale_count: Optional[int] = Field(default=None, alias="locallyModifiedAndStaleCount")
    sync_failure_count: Optional[int] = Field(default=None, alias="syncFailureCount")
    input_port_count: Optional[int] = Field(default=None, alias="inputPortCount")
    output_port_count: Optional[int] = Field(default=None, alias="outputPortCount")
    contents: Optional[FlowSnippetDTO] = Field(default=None)
    variables: Optional[Dict[str, str]] = Field(default=None)
    version_control_information: Optional[VersionControlInformationDTO] = Field(default=None, alias="versionControlInformation")
    parameter_context: Optional[ParameterContextReferenceEntity] = Field(default=None, alias="parameterContext")
    flowfile_concurrency: Optional[str] = Field(default=None, alias="flowfileConcurrency")
    flowfile_outbound_policy: Optional[str] = Field(default=None, alias="flowfileOutboundPolicy")
    default_flowfile_expiration: Optional[str] = Field(default=None, alias="defaultFlowFileExpiration")
    default_back_pressure_object_threshold: Optional[int] = Field(default=None, alias="defaultBackPressureObjectThreshold")
    default_back_pressure_data_size_threshold: Optional[str] = Field(default=None, alias="defaultBackPressureDataSizeThreshold")
    log_file_suffix: Optional[str] = Field(default=None, alias="logFileSuffix")
    process_group_update_strategy: Optional[str] = Field(None, alias="processGroupUpdateStrategy")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ProcessGroupEntity(BaseModel):
    revision: Optional[RevisionDTO] = Field(None)
    id: Optional[str] = Field(default=None)
    uri: Optional[HttpUrl] = Field(default=None)
    position: Optional[PositionDTO] = Field(default=None)
    permissions: Optional[PermissionDTO] = Field(default=None)
    bulletins: Optional[List[BulletinEntity]] = Field(default=None)
    disconnected_node_acknowledged: Optional[bool] = Field(default=None, alias="disconnectedNodeAcknowledged")
    component: Optional[ProcessGroupDTO] = Field(default=None)
    status: Optional[Any] = Field(default=None) # Placeholder for ProcessGroupStatusDTO
    versioned_flow_snapshot: Optional[VersionedFlowSnapshotDTO] = Field(default=None, alias="versionedFlowSnapshot")
    running_count: Optional[int] = Field(default=None, alias="runningCount")
    stopped_count: Optional[int] = Field(default=None, alias="stoppedCount")
    invalid_count: Optional[int] = Field(default=None, alias="invalidCount")
    disabled_count: Optional[int] = Field(default=None, alias="disabledCount")
    active_remote_port_count: Optional[int] = Field(default=None, alias="activeRemotePortCount")
    inactive_remote_port_count: Optional[int] = Field(default=None, alias="inactiveRemotePortCount")
    up_to_date_count: Optional[int] = Field(default=None, alias="upToDateCount")
    locally_modified_count: Optional[int] = Field(default=None, alias="locallyModifiedCount")
    stale_count: Optional[int] = Field(default=None, alias="staleCount")
    locally_modified_and_stale_count: Optional[int] = Field(default=None, alias="locallyModifiedAndStaleCount")
    sync_failure_count: Optional[int] = Field(default=None, alias="syncFailureCount")
    local_input_port_count: Optional[int] = Field(default=None, alias="localInputPortCount")
    local_output_port_count: Optional[int] = Field(default=None, alias="localOutputPortCount")
    public_input_port_count: Optional[int] = Field(default=None, alias="publicInputPortCount")
    public_output_port_count: Optional[int] = Field(default=None, alias="publicOutputPortCount")
    parameter_context: Optional[ParameterContextReferenceEntity] = Field(default=None, alias="parameterContext")
    parameter_context_name: Optional[str] = Field(default=None, alias="parameterContextName")
    stats_last_refreshed: Optional[str] = Field(None, alias="statsLastRefreshed", description="When the status statistics were last refreshed") 
    input_port_count: Optional[int] = Field(default=None, alias="inputPortCount")
    output_port_count: Optional[int] = Field(default=None, alias="outputPortCount")
    process_group_update_strategy: Optional[str] = Field(None, alias="processGroupUpdateStrategy")
    model_config = {"populate_by_name": True, "extra": "allow"}

# NEW Plural Entities for list operations
class ProcessGroupsEntity(BaseModel):
    process_groups: Optional[List[ProcessGroupEntity]] = Field(None, alias="processGroups")
    # NiFi API might also include 'generatedTimestamp' or similar metadata here
    model_config = {"populate_by_name": True, "extra": "allow"}

# NEW DTO for the master tool response
class ProcessGroupContentOverviewDTO(BaseModel):
    process_group_id: str = Field(description="The ID of the process group being described.")
    child_process_groups: Optional[List[ProcessGroupEntity]] = Field(None, alias="childProcessGroups", description="List of direct child process groups.")
    processors: Optional[List[ProcessorEntity]] = Field(None, description="List of processors directly within this group.")
    connections: Optional[List[ConnectionEntity]] = Field(None, description="List of connections directly within this group.")
    errors: Optional[List[str]] = Field(None, description="Any errors encountered while fetching parts of the content.")
    model_config = {"populate_by_name": True, "extra": "allow"}
# ===================================================================
# Processor Related Models (UPDATED SECTION)
# ===================================================================

class ProcessorStatusDTO(BaseModel): # NEW
    run_status: Optional[str] = Field(None, alias="runStatus", description="The run status of the processor (e.g., Running, Stopped, Disabled).")
    active_thread_count: Optional[int] = Field(None, alias="activeThreadCount", description="The number of active threads for the processor.")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ProcessorDTO(BaseModel): # UPDATED based on createProcessor example
    id: Optional[str] = Field(default=None, description="The id of the component.")
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId", description="The ID of the corresponding component that is under version control")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId", description="The id of parent process group.")
    position: Optional[PositionDTO] = Field(default=None, description="The position of this component in the UI if applicable.")
    name: Optional[str] = Field(default=None, description="The name of the processor.")
    type: Optional[str] = Field(default=None, description="The type of the processor (fully qualified class name).") # Emphasize this
    bundle: Optional[BundleDTO] = Field(default=None, description="The bundle for the processor.")
    state: Optional[str] = Field(default=None, description="The state of the processor (e.g., RUNNING, STOPPED, DISABLED).")
    style: Optional[Dict[str, str]] = Field(default=None, description="Styles for the processor (background-color, etc).")
    relationships: Optional[List[RelationshipDTO]] = Field(default=None, description="The available relationships that the processor currently supports.")
    description: Optional[str] = Field(default=None, description="The description of the processor.")
    supports_parallel_processing: Optional[bool] = Field(default=None, alias="supportsParallelProcessing")
    supports_event_driven: Optional[bool] = Field(default=None, alias="supportsEventDriven")
    supports_batching: Optional[bool] = Field(default=None, alias="supportsBatching")
    supports_sensitive_dynamic_properties: Optional[bool] = Field(None, alias="supportsSensitiveDynamicProperties", description="Whether the processor supports sensitive dynamic properties.") # From createProcessor example
    persists_state: Optional[bool] = Field(default=None, alias="persistsState")
    restricted: Optional[bool] = Field(default=None)
    deprecated: Optional[bool] = Field(default=None)
    execution_node_restricted: Optional[bool] = Field(None, alias="executionNodeRestricted", description="Whether the processor is restricted to run only on the primary node.") # From createProcessor example
    multiple_versions_available: Optional[bool] = Field(default=None, alias="multipleVersionsAvailable")
    input_requirement: Optional[str] = Field(default=None, alias="inputRequirement", description="The input requirement for this processor.")
    config: Optional[ProcessorConfigDTO] = Field(default=None, description="The configuration details for the processor.")
    validation_errors: Optional[List[str]] = Field(default=None, alias="validationErrors")
    extension_missing: Optional[bool] = Field(default=None, alias="extensionMissing")
    bulletin_level: Optional[str] = Field(default=None, alias="bulletinLevel", description="The level at which the processor will report bulletins.")
    comments: Optional[str] = Field(default=None, description="The user-supplied comments for the processor.")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ProcessorEntity(BaseModel): # UPDATED
    revision: Optional[RevisionDTO] = Field(None, description="The revision information for this entity.")
    id: Optional[str] = Field(default=None, description="The id of the component.")
    uri: Optional[HttpUrl] = Field(default=None, description="The URI for futures requests to this component.")
    position: Optional[PositionDTO] = Field(default=None, description="The position of this component in the UI if applicable.")
    permissions: Optional[PermissionDTO] = Field(default=None, description="The permissions for this component.")
    bulletins: Optional[List[BulletinEntity]] = Field(default=None, description="The bulletins for this component.")
    disconnected_node_acknowledged: Optional[bool] = Field(default=None, alias="disconnectedNodeAcknowledged", description="Acknowledges that this node is disconnected to allow for mutable requests to proceed.")
    component: Optional[ProcessorDTO] = Field(default=None, description="The processor component.")
    input_requirement: Optional[str] = Field(default=None, alias="inputRequirement", description="The input requirement for this processor.")
    status: Optional[ProcessorStatusDTO] = Field(default=None, description="The status of the processor.") # UPDATED
    operate_permissions: Optional[PermissionDTO] = Field(default=None, alias="operatePermissions", description="Permissions to operate the component.")
    model_config = {"populate_by_name": True, "extra": "allow"}
class ProcessorsEntity(BaseModel):
    processors: Optional[List[ProcessorEntity]] = Field(None)
    model_config = {"populate_by_name": True, "extra": "allow"}
class ProcessorRunStatusEntity(BaseModel): # NEW for PUT /processors/{id}/run-status
    revision: RevisionDTO = Field(description="The revision for this request.")
    state: str = Field(description="The desired state of the processor (e.g., RUNNING, STOPPED, DISABLED).")
    disconnected_node_acknowledged: Optional[bool] = Field(default=False, alias="disconnectedNodeAcknowledged", description="Acknowledges that this node is disconnected to allow for mutable requests to proceed.")
    model_config = {"populate_by_name": True, "extra": "allow"}


# Models for other /processors endpoints (to be implemented later)
class ConfigurationAnalysisDTO(BaseModel):
    component_id: Optional[str] = Field(None, alias="componentId")
    properties: Optional[Dict[str,str]] = Field(None)
    referenced_attributes: Optional[Dict[str,str]] = Field(None, alias="referencedAttributes")
    supports_verification: Optional[bool] = Field(None, alias="supportsVerification")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ConfigurationAnalysisEntity(BaseModel):
    configuration_analysis: Optional[ConfigurationAnalysisDTO] = Field(None, alias="configurationAnalysis")
    # Assuming request body for POST /processors/{id}/config/analysis also uses this structure
    # with componentId and properties being part of the nested DTO
    model_config = {"populate_by_name": True, "extra": "allow"}

class LocalStateEntryDTO(BaseModel):
    key: Optional[str] = Field(None)
    value: Optional[str] = Field(None)
    cluster_node_id: Optional[str] = Field(None, alias="clusterNodeId")
    cluster_node_address: Optional[str] = Field(None, alias="clusterNodeAddress")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ClusterStateDTO(BaseModel):
    scope: Optional[str] = Field(None)
    total_entry_count: Optional[int] = Field(None, alias="totalEntryCount")
    state: Optional[List[LocalStateEntryDTO]] = Field(None)
    model_config = {"populate_by_name": True, "extra": "allow"}

class ComponentStateDTO(BaseModel):
    component_id: Optional[str] = Field(None, alias="componentId")
    state_description: Optional[str] = Field(None, alias="stateDescription")
    cluster_state: Optional[ClusterStateDTO] = Field(None, alias="clusterState")
    local_state: Optional[Dict[str,str]] = Field(None, alias="localState")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ComponentStateEntity(BaseModel):
    component_state: Optional[ComponentStateDTO] = Field(None, alias="componentState")
    model_config = {"populate_by_name": True, "extra": "allow"}

class PropertyDescriptorEntity(BaseModel):
    property_descriptor: Optional[PropertyDescriptorDTO] = Field(None, alias="propertyDescriptor")
    model_config = {"populate_by_name": True, "extra": "allow"}

class VerificationResultDTO(BaseModel):
    verification_step_name: Optional[str] = Field(None, alias="verificationStepName")
    outcome: Optional[str] = Field(None) # e.g., "SUCCESSFUL", "FAILED"
    explanation: Optional[str] = Field(None)
    model_config = {"populate_by_name": True, "extra": "allow"}

class VerifyConfigRequestDTO(BaseModel): # This is the 'request' object within VerifyConfigRequestEntity
    request_id: Optional[str] = Field(None, alias="requestId")
    uri: Optional[HttpUrl] = Field(None)
    submission_time: Optional[str] = Field(None, alias="submissionTime") # Consider datetime
    last_updated: Optional[str] = Field(None, alias="lastUpdated") # Consider datetime
    complete: Optional[bool] = Field(None)
    failure_reason: Optional[str] = Field(None, alias="failureReason")
    percent_completed: Optional[int] = Field(None, alias="percentCompleted") # format int32
    state: Optional[str] = Field(None)
    component_id: Optional[str] = Field(None, alias="componentId")
    properties: Optional[Dict[str, str]] = Field(None)
    attributes: Optional[Dict[str,str]] = Field(None)
    results: Optional[List[VerificationResultDTO]] = Field(None)
    model_config = {"populate_by_name": True, "extra": "allow"}

class VerifyConfigRequestEntity(BaseModel):
    request: Optional[VerifyConfigRequestDTO] = Field(None)
    model_config = {"populate_by_name": True, "extra": "allow"}

class ProcessorRunStatusDetailsDTO(BaseModel):
    id: Optional[str] = Field(None)
    name: Optional[str] = Field(None)
    run_status: Optional[str] = Field(None, alias="runStatus")
    validation_errors: Optional[List[str]] = Field(None, alias="validationErrors")
    active_thread_count: Optional[int] = Field(None, alias="activeThreadCount")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ProcessorsRunStatusDetailsEntity(BaseModel):
    run_status_details: Optional[List[ProcessorRunStatusDetailsDTO]] = Field(None, alias="runStatusDetails")
    model_config = {"populate_by_name": True, "extra": "allow"}

class RunStatusDetailsRequestEntity(BaseModel):
    processor_ids: Optional[List[str]] = Field(None, alias="processorIds")
    model_config = {"populate_by_name": True, "extra": "allow"}

# ===================================================================
# Connection Related Models
# ... (ConnectionDTO, ConnectionEntity remain the same) ...
# ===================================================================
class ConnectableDTO(BaseModel):
    id: str = Field(description="The id of the connectable component.")
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId", description="The ID of the corresponding component that is under version control")
    type: str = Field(description="The type of the connectable component.") # E.g. PROCESSOR, REMOTE_INPUT_PORT, REMOTE_OUTPUT_PORT, INPUT_PORT, OUTPUT_PORT, FUNNEL
    group_id: str = Field(alias="groupId", description="The id of the group that the connectable component resides in.")
    name: Optional[str] = Field(default=None, description="The name of the connectable component")
    running: Optional[bool] = Field(default=None, description="Whether the connectable component is running.")
    comments: Optional[str] = Field(default=None, description="The comments for the connectable component.")
    exists: Optional[bool] = Field(default=None, description="Whether the connectable component exists.")
    model_config = {"populate_by_name": True, "extra": "allow"}
    
class ConnectionDTO(BaseModel):
    id: Optional[str] = Field(default=None)
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId")
    position: Optional[PositionDTO] = Field(default=None)
    source: Optional[ConnectableDTO] = Field(default=None)
    destination: Optional[ConnectableDTO] = Field(default=None)
    name: Optional[str] = Field(default=None)
    label_index: Optional[int] = Field(default=None, alias="labelIndex")
    z_index: Optional[int] = Field(default=None, alias="zIndex")
    selected_relationships: Optional[List[str]] = Field(default=None, alias="selectedRelationships")
    available_relationships: Optional[List[str]] = Field(default=None, alias="availableRelationships")
    back_pressure_object_threshold: Optional[int] = Field(default=None, alias="backPressureObjectThreshold")
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

# --- ConnectionEntity and ConnectionsEntity ---
class ConnectionEntity(BaseModel): # Review and update
    revision: Optional[RevisionDTO] = Field(None, description="The revision information for this entity.")
    id: Optional[str] = Field(default=None, description="The id of the component.")
    uri: Optional[HttpUrl] = Field(default=None, description="The URI for futures requests to this component.")
    position: Optional[PositionDTO] = Field(default=None, description="The position of this component's label in the UI if applicable.")
    permissions: Optional[PermissionDTO] = Field(default=None, description="The permissions for this component.")
    bulletins: Optional[List[BulletinEntity]] = Field(default=None, description="The bulletins for this component.")
    disconnected_node_acknowledged: Optional[bool] = Field(default=None, alias="disconnectedNodeAcknowledged", description="Acknowledges that this node is disconnected to allow for mutable requests to proceed.")
    
    component: Optional[ConnectionDTO] = Field(default=None, description="The connection component details.")
    status: Optional[ConnectionStatusDTO] = Field(default=None, description="The status of the connection.") # UPDATED from Any

    # These fields are often part of the component (ConnectionDTO), but the API doc example for ConnectionEntity shows them at top level too.
    # Keeping them here allows flexibility if NiFi returns them at this level, Pydantic will populate if present.
    # The primary source for these when creating/updating should be via the component.
    source_id: Optional[str] = Field(default=None, alias="sourceId", description="The ID of the source of this connection.")
    source_group_id: Optional[str] = Field(default=None, alias="sourceGroupId", description="The ID of the Process Group that the source of this connection belongs to.")
    source_type: Optional[str] = Field(default=None, alias="sourceType", description="The type of component that is the source of this connection.")
    destination_id: Optional[str] = Field(default=None, alias="destinationId", description="The ID of the destination of this connection.")
    destination_group_id: Optional[str] = Field(default=None, alias="destinationGroupId", description="The ID of the Process Group that the destination of this connection belongs to.")
    destination_type: Optional[str] = Field(default=None, alias="destinationType", description="The type of component that is the destination of this connection.")

    model_config = {"populate_by_name": True, "extra": "allow"}

class ConnectionsEntity(BaseModel): # NEW for GET /process-groups/{id}/connections
    connections: Optional[List[ConnectionEntity]] = Field(default=None)
    model_config = {"populate_by_name": True, "extra": "allow"}

class FlowSnippetDTO(BaseModel):
    processors: Optional[List[ProcessorEntity]] = Field(default=None)
    connections: Optional[List[ConnectionEntity]] = Field(default=None) # Ensure this uses ConnectionEntity
    input_ports: Optional[List[PortEntity]] = Field(default=None, alias="inputPorts")
    output_ports: Optional[List[PortEntity]] = Field(default=None, alias="outputPorts")
    funnels: Optional[List[Any]] = Field(default=None) # Placeholder for FunnelEntity
    labels: Optional[List[Any]] = Field(default=None) # Placeholder for LabelEntity
    process_groups: Optional[List[ProcessGroupEntity]] = Field(default=None, alias="processGroups")
    remote_process_groups: Optional[List[Any]] = Field(default=None, alias="remoteProcessGroups") # Placeholder for RemoteProcessGroupEntity
    controller_services: Optional[List[ControllerServiceEntity]] = Field(default=None, alias="controllerServices")
    model_config = {"extra": "allow", "populate_by_name": True}

# --- DTOs for /flow/processor-types ---

class ControllerServiceApiDTO(BaseModel):
    """Information about a Controller Service API that a component implements."""
    type: Optional[str] = Field(None, description="The fully qualified class name of the Controller Service API.")
    # NiFi's BundleDTO might be here too if API specifies bundle info per API
    # bundle: Optional[BundleDTO] = Field(None) 
    model_config = {"populate_by_name": True, "extra": "allow"}

class RequiredPermissionDTO(BaseModel):
    """A required permission for a restricted component."""
    id: Optional[str] = Field(None, description="The unique identifier for the permission.")
    label: Optional[str] = Field(None, description="The human-readable label for the permission.")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ExplicitRestrictionDTO(BaseModel):
    """An explicit restriction for a component."""
    required_permission: Optional[RequiredPermissionDTO] = Field(None, alias="requiredPermission", description="The required permission.")
    explanation: Optional[str] = Field(None, description="The explanation of why this restriction exists.")
    model_config = {"populate_by_name": True, "extra": "allow"}

class DocumentedTypeDTO(BaseModel):
    """Describes a type of NiFi component (e.g., a processor type)."""
    type: Optional[str] = Field(None, description="The fully qualified name of the type.")
    bundle: Optional[BundleDTO] = Field(None, description="The bundle that provides this type.")
    controller_service_apis: Optional[List[ControllerServiceApiDTO]] = Field(None, alias="controllerServiceApis", description="If this type represents a ControllerService, this lists the APIs it implements.")
    description: Optional[str] = Field(None, description="The description of the type.")
    usage_restriction: Optional[str] = Field(None, alias="usageRestriction", description="An optional description of why the usage of this component is restricted.")
    deprecation_reason: Optional[str] = Field(None, alias="deprecationReason", description="If this component has been deprecated, the reason for the deprecation.")
    tags: Optional[List[str]] = Field(None, description="The tags associated with this type.")
    restricted: Optional[bool] = Field(None, description="Whether this type is restricted.")
    explicit_restrictions: Optional[List[ExplicitRestrictionDTO]] = Field(None, alias="explicitRestrictions", description="An optional collection of explicit restrictions.")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ProcessorTypesEntity(BaseModel):
    """Entity containing a list of available processor types."""
    processor_types: Optional[List[DocumentedTypeDTO]] = Field(None, alias="processorTypes")
    model_config = {"populate_by_name": True, "extra": "allow"}
# ===================================================================
# Input/Output Port Related Models
# ... (PortDTO, PortEntity remain the same) ...
# ===================================================================
class PortDTO(BaseModel):
    id: Optional[str] = Field(default=None)
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId")
    parent_group_id: Optional[str] = Field(default=None, alias="parentGroupId")
    position: Optional[PositionDTO] = Field(default=None)
    name: Optional[str] = Field(default=None)
    comments: Optional[str] = Field(default=None)
    state: Optional[str] = Field(default=None)
    type: Optional[str] = Field(default=None) # INPUT_PORT or OUTPUT_PORT
    transmitting: Optional[bool] = Field(default=None)
    concurrently_schedulable_task_count: Optional[int] = Field(default=None, alias="concurrentlySchedulableTaskCount")
    user_access_control: Optional[List[str]] = Field(default=None, alias="userAccessControl")
    group_access_control: Optional[List[str]] = Field(default=None, alias="groupAccessControl")
    validation_errors: Optional[List[str]] = Field(default=None, alias="validationErrors")
    allow_remote_access: Optional[bool] = Field(default=None, alias="allowRemoteAccess")
    bulletin_level: Optional[str] = Field(default=None, alias="bulletinLevel", description="The level at which the port will report bulletins.")
    model_config = {"populate_by_name": True, "extra": "allow"}

class PortEntity(BaseModel):
    revision: Optional[RevisionDTO] = Field(None)
    id: Optional[str] = Field(default=None)
    uri: Optional[HttpUrl] = Field(default=None)
    position: Optional[PositionDTO] = Field(default=None)
    permissions: Optional[PermissionDTO] = Field(default=None)
    bulletins: Optional[List[BulletinEntity]] = Field(default=None)
    disconnected_node_acknowledged: Optional[bool] = Field(default=None, alias="disconnectedNodeAcknowledged")
    component: Optional[PortDTO] = Field(default=None)
    status: Optional[Any] = Field(default=None) # Placeholder for PortStatusDTO
    port_type: Optional[str] = Field(default=None, alias="portType")
    operate_permissions: Optional[PermissionDTO] = Field(default=None, alias="operatePermissions")
    allow_remote_access: Optional[bool] = Field(default=None, alias="allowRemoteAccess")
    model_config = {"populate_by_name": True, "extra": "allow"}

# ===================================================================
# Controller Service Related Models (NEW SECTION)
# ===================================================================
class ControllerServiceStatusDTO(BaseModel):
    """The status of a controller service."""
    run_status: Optional[str] = Field(None, alias="runStatus", description="The run status of the controller service (e.g., 'ENABLED', 'DISABLED').")
    active_thread_count: Optional[int] = Field(None, alias="activeThreadCount", description="The number of active threads for the controller service.")
    validation_status: Optional[str] = Field(None, alias="validationStatus", description="The validation status of the controller service (e.g., 'VALID', 'INVALID').")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ControllerServiceDTO(BaseModel):
    """The configuration details for a Controller Service."""
    id: Optional[str] = Field(None, description="The id of the component.")
    versioned_component_id: Optional[str] = Field(None, alias="versionedComponentId")
    parent_group_id: Optional[str] = Field(None, alias="parentGroupId")
    name: Optional[str] = Field(None, description="The name of the controller service.")
    type: Optional[str] = Field(None, description="The type of the controller service (fully qualified class name).")
    bundle: Optional[BundleDTO] = Field(None, description="The bundle for the controller service.")
    comments: Optional[str] = Field(None, description="The comments for the controller service.")
    state: Optional[str] = Field(None, description="The state of the controller service (e.g., 'ENABLED', 'DISABLED', 'ENABLING', 'DISABLING').")
    persists_state: Optional[bool] = Field(None, alias="persistsState")
    restricted: Optional[bool] = Field(None)
    deprecated: Optional[bool] = Field(None)
    extension_missing: Optional[bool] = Field(None, alias="extensionMissing")
    multiple_versions_available: Optional[bool] = Field(None, alias="multipleVersionsAvailable")
    properties: Optional[Dict[str, Optional[str]]] = Field(None, description="The properties of the controller service.")
    descriptors: Optional[Dict[str, PropertyDescriptorDTO]] = Field(None, description="The descriptors for the controller service properties.")
    validation_errors: Optional[List[str]] = Field(None, alias="validationErrors")
    validation_status: Optional[str] = Field(None, alias="validationStatus")
    bulletin_level: Optional[str] = Field(None, alias="bulletinLevel")
    annotation_data: Optional[str] = Field(None, alias="annotationData")
    referencing_components: Optional[List[ControllerServiceReferencingComponentEntity]] = Field(None, alias="referencingComponents")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ControllerServiceEntity(BaseModel):
    """An entity representing a Controller Service."""
    revision: Optional[RevisionDTO] = Field(None)
    id: Optional[str] = Field(None)
    uri: Optional[HttpUrl] = Field(None)
    position: Optional[PositionDTO] = Field(None)
    permissions: Optional[PermissionDTO] = Field(None)
    bulletins: Optional[List[BulletinEntity]] = Field(None)
    disconnected_node_acknowledged: Optional[bool] = Field(None, alias="disconnectedNodeAcknowledged")
    parent_group_id: Optional[str] = Field(None, alias="parentGroupId")
    component: Optional[ControllerServiceDTO] = Field(None)
    status: Optional[ControllerServiceStatusDTO] = Field(None)
    operate_permissions: Optional[PermissionDTO] = Field(None, alias="operatePermissions")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ControllerServiceReferencingComponentEntity(BaseModel):
    """An entity representing a component that references a controller service."""
    revision: Optional[RevisionDTO] = Field(None)
    id: Optional[str] = Field(None)
    permissions: Optional[PermissionDTO] = Field(None)
    component: Optional[Dict[str, Any]] = Field(None, description="A generic component DTO (Processor, Controller Service, etc.).")
    operate_permissions: Optional[PermissionDTO] = Field(None, alias="operatePermissions")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ControllerServiceReferencingComponentsEntity(BaseModel):
    """A list of components that reference a controller service."""
    controller_service_referencing_components: Optional[List[ControllerServiceReferencingComponentEntity]] = Field(None, alias="controllerServiceReferencingComponents")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ControllerServiceRunStatusEntity(BaseModel):
    """Payload for updating the run status of a controller service."""
    revision: RevisionDTO = Field(description="The revision for this request.")
    state: str = Field(description="The desired state of the controller service ('ENABLED' or 'DISABLED').")
    disconnected_node_acknowledged: Optional[bool] = Field(False, alias="disconnectedNodeAcknowledged")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ControllerServicesEntity(BaseModel):
    """Entity for a list of controller services."""
    controller_services: Optional[List[ControllerServiceEntity]] = Field(None, alias="controllerServices")
    current_time: Optional[str] = Field(None, alias="currentTime")
    model_config = {"populate_by_name": True, "extra": "allow"}

class ControllerServiceTypesEntity(BaseModel):
    """Entity containing a list of available controller service types."""
    controller_service_types: Optional[List[DocumentedTypeDTO]] = Field(None, alias="controllerServiceTypes")
    model_config = {"populate_by_name": True, "extra": "allow"}

# ===================================================================
# Generic Models for NiFi Client
# ... (NiFiClientCreds, NiFiAuthException, NiFiApiException remain the same) ...
# ===================================================================
class NiFiClientCreds(BaseModel):
    username: Optional[str] = Field(default=None, description="Username for NiFi authentication.")
    password: Optional[str] = Field(default=None, description="Password for NiFi authentication.")
    token: Optional[str] = Field(default=None, description="Pre-existing JWT for NiFi authentication.")
    url: Optional[HttpUrl] = Field(default=None, description="Optional NiFi Base URL override from client.")
    ssl_verify: Optional[bool] = Field(default=None, description="Optional SSL verification override from client (True/False).")

    @field_validator('*', mode='before')
    @classmethod
    def validate_creds(cls, data: Any, info: ValidationInfo) -> Any:
        if info.field_name is None:
            if isinstance(data, dict):
                username, password, token = data.get('username'), data.get('password'), data.get('token')
                if token is None and (username is None or password is None):
                    raise ValueError("Either 'token' or both 'username' and 'password' must be provided for NiFi authentication.")
                if token is not None and (username is not None or password is not None):
                    raise ValueError("Provide either 'token' or 'username'/'password', not both.")
        return data

class NiFiAuthException(Exception):
    pass

class NiFiApiException(Exception):
    def __init__(self, status_code: int, message: str, response_text: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.response_text = response_text

    def __str__(self):
        return f"NiFi API Error {self.status_code}: {self.message}" + (f" - Response: {self.response_text}" if self.response_text else "")

# ===================================================================
# Update Forward References
# ===================================================================
ProcessGroupDTO.model_rebuild()
FlowSnippetDTO.model_rebuild()
VersionedFlowSnapshotDTO.model_rebuild()
ProcessorConfigDTO.model_rebuild()
ProcessorDTO.model_rebuild()
# ConnectionDTO.model_rebuild()
# PortDTO.model_rebuild()
ProcessGroupEntity.model_rebuild()
ProcessorEntity.model_rebuild()
# ConnectionEntity.model_rebuild()
# PortEntity.model_rebuild()

# NEW/UPDATED model_rebuild calls for processors:
ProcessorStatusDTO.model_rebuild()
ProcessorRunStatusEntity.model_rebuild()
ConfigurationAnalysisDTO.model_rebuild()
ConfigurationAnalysisEntity.model_rebuild()
LocalStateEntryDTO.model_rebuild()
ClusterStateDTO.model_rebuild()
ComponentStateDTO.model_rebuild()
ComponentStateEntity.model_rebuild()
PropertyDependencyDTO.model_rebuild()
PropertyDescriptorDTO.model_rebuild()
PropertyDescriptorEntity.model_rebuild()
VerificationResultDTO.model_rebuild()
VerifyConfigRequestDTO.model_rebuild()
VerifyConfigRequestEntity.model_rebuild()
ProcessorRunStatusDetailsDTO.model_rebuild()
ProcessorsRunStatusDetailsEntity.model_rebuild()
RunStatusDetailsRequestEntity.model_rebuild()

# NEW model_rebuild calls for /flow/processor-types
ControllerServiceApiDTO.model_rebuild()
RequiredPermissionDTO.model_rebuild()
ExplicitRestrictionDTO.model_rebuild()
DocumentedTypeDTO.model_rebuild()
ProcessorTypesEntity.model_rebuild()

# NEW model_rebuild calls for Connections:
ConnectableDTO.model_rebuild() # If ConnectableDTO references other models defined later, or if it was changed
ConnectionDTO.model_rebuild()
ConnectionStatusPredictionsSnapshotDTO.model_rebuild()
ConnectionStatisticsSnapshotDTO.model_rebuild()
NodeConnectionStatisticsSnapshotDTO.model_rebuild()
ConnectionStatusDTO.model_rebuild()
ConnectionStatusEntity.model_rebuild()
StatusHistoryEntity.model_rebuild()
ConnectionStatisticsDTO.model_rebuild()
ConnectionStatisticsEntity.model_rebuild()
ConnectionEntity.model_rebuild()
ConnectionsEntity.model_rebuild()

ProcessGroupsEntity.model_rebuild()   # NEW
ProcessorsEntity.model_rebuild()      # NEW
ProcessGroupContentOverviewDTO.model_rebuild() # NEW

# NEW model_rebuild calls for Controller Services
ControllerServiceStatusDTO.model_rebuild()
ControllerServiceDTO.model_rebuild()
ControllerServiceReferencingComponentEntity.model_rebuild()
ControllerServiceReferencingComponentsEntity.model_rebuild()
ControllerServiceRunStatusEntity.model_rebuild()
ControllerServiceEntity.model_rebuild()
ControllerServicesEntity.model_rebuild()
ControllerServiceTypesEntity.model_rebuild()