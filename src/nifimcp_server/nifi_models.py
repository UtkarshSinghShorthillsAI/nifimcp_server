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

class ControllerServiceEntity(BaseModel):
    """Placeholder for ControllerServiceEntity"""
    id: Optional[str] = Field(None)
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

class ConnectableDTO(BaseModel):
    id: str = Field(description="The id of the connectable component.")
    versioned_component_id: Optional[str] = Field(default=None, alias="versionedComponentId", description="The ID of the corresponding component that is under version control")
    type: str = Field(description="The type of the connectable component.")
    group_id: str = Field(alias="groupId", description="The id of the group that the connectable component resides in.")
    name: Optional[str] = Field(default=None, description="The name of the connectable component")
    running: Optional[bool] = Field(default=None, description="Whether the connectable component is running.")
    comments: Optional[str] = Field(default=None, description="The comments for the connectable component.")
    exists: Optional[bool] = Field(default=None, description="Whether the connectable component exists.")
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
    input_port_count: Optional[int] = Field(default=None, alias="inputPortCount")
    output_port_count: Optional[int] = Field(default=None, alias="outputPortCount")
    process_group_update_strategy: Optional[str] = Field(None, alias="processGroupUpdateStrategy")
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

class ConnectionEntity(BaseModel):
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
    label_index: Optional[int] = Field(default=None, alias="labelIndex")
    z_index: Optional[int] = Field(default=None, alias="zIndex")
    source_id: Optional[str] = Field(default=None, alias="sourceId")
    source_group_id: Optional[str] = Field(default=None, alias="sourceGroupId")
    source_type: Optional[str] = Field(default=None, alias="sourceType")
    destination_id: Optional[str] = Field(default=None, alias="destinationId")
    destination_group_id: Optional[str] = Field(default=None, alias="destinationGroupId")
    destination_type: Optional[str] = Field(default=None, alias="destinationType")
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
ConnectionDTO.model_rebuild()
PortDTO.model_rebuild()
ProcessGroupEntity.model_rebuild()
ProcessorEntity.model_rebuild()
ConnectionEntity.model_rebuild()
PortEntity.model_rebuild()

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