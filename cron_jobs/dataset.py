import json

from app import data
from app import exceptions
from app import session
from app.public import common
from app.public.common import ID
from app.public.common import doc
from app.public.common import exclude_streaming_datasets
from app.public.common import input_validations
from app.public.common import method
from app.public.common import required
from app.public.common import returns
from app.public.common import verify_location
from app.public.return_filters import ColumnSchema
from app.public.return_filters import Dataset
from app.public.return_filters import DatasetUpload
from app.public.return_filters import DatasetVersion
from app.session import loggedin
from reainternal import db
from reainternal.enums import DatasetLifecycle
from reainternal.enums import FileFormat
from reainternal.enums import LocationType
from reainternal.enums import ProjectDatasetType
from reainternal.enums import RefreshPolicyType
from reainternal.enums import SourceType


def _get_target_info(project_id: ID, dataset_type: str):
    project_target_info = {}
    if project_id:
        use_case = data.get_project(project_id.value).use_case
        valid_dataset_types = {external_type: internal_type
                               for internal_type, external_type in data.get_dataset_type_translations(use_case).items()}
        # Allow for custom tables to be attached to any problem type for joins. Not supported publicly, but used for some advanced
        # use cases.
        if 'CUSTOM_TABLE' not in valid_dataset_types:
            valid_dataset_types['CUSTOM_TABLE'] = 'table'
        if dataset_type not in valid_dataset_types:
            if len(valid_dataset_types) > 1:
                valid_dataset_types.pop('CUSTOM_TABLE', None)
            raise exceptions.InvalidEnumParameterError('dataset_type', [key for key in valid_dataset_types], dataset_type)
        dataset_type = valid_dataset_types[dataset_type]
        project_target_info = {'project_id': project_id.value, 'project_dataset_type': ProjectDatasetType(dataset_type)}
    return project_target_info


@loggedin
@method('POST')
@required('name', file_format={None, *[file_format.value for file_format in FileFormat]})
@returns(DatasetUpload)
@input_validations(name=common.validate_name)
def add_uploaded_dataset(name: str, file_format: str = None, project_id: ID = None, dataset_type: str = None):
    '''
    Creates a dataset from a local file. The model will take in the name of your file and return the dataset's information (its attributes).

    Args:
        name (String): The name for the dataset.
        file_format (Enum of type 'String' ): The file format of the dataset.
        project_id (Unique Identifier of type 'String'): The project to attach the dataset to after creating the dataset.
        dataset_type (Enum of type 'String' ): The dataset type to use when projectId is specified. Please see the (Use Case Documentation)[{USE_CASES_URL}] for the datasetTypes that are supported for each use case.

    Returns:
        DatasetUpload: A token to be used when uploading file parts. For more information, please refer to the details on the object as follows:
    '''
    values = {
        'name': name,
        'data_source': {
            'location_type': LocationType.RE.value
        },
        'lifecycle': DatasetLifecycle.UPLOADING,
        'source_type': SourceType.UPLOADED.value
    }
    if file_format:
        values['file_format'] = file_format
    result = data.add_dataset(organization_id=session.user_info.organization.organization_id, values=values, project_target_info=_get_target_info(project_id, dataset_type))
    return data.get_upload_by_dataset_instance(result['dataset_instance'].get_id())


@loggedin
@method('POST')
@required('name', 'location', file_format={None, *[file_format.value for file_format in FileFormat]})
@returns(Dataset)
@input_validations(name=common.validate_name, location=verify_location)
def add_imported_dataset(name: str, location: str, file_format: str = None, project_id: ID = None, dataset_type: str = None, refresh_schedule: str = None):
    '''
    Creates a dataset from a file located in a cloud storage, such as Amazon AWS S3, using the specified dataset name and location. The model will return the dataset's information, such as its ID, name, data source, etc.

    Args:
        name (String): The name for the dataset
        location (String): The cloud location of the dataset
        file_format (Enum of type 'String' ): The file format of the dataset
        project_id (Unique Identifier of type 'String'): The project to attach the dataset to after creating the dataset
        dataset_type (Enum of type 'String' ): The Dataset Type to use when projectId is specified. Please see the (Use Case Documentation)[{USE_CASES_URL}] for the datasetTypes that are supported for each use case
        refresh_schedule (String): The Cron time string format that describes a schedule to retrieve the latest version of the imported dataset. The time is specified in UTC.

    Returns:
        Dataset: The dataset created. For more information, please refer to the details on the object as follows:

    Raises:
        InvalidParameterError: The location is not a valid cloud location URI.
        PermissionDeniedError: The location has not been verified with {PRODUCT_NAME}.
        DataNotFoundError: No file was found at the specified location.
    '''
    values = {
        'name': name,
        'data_source': {
            'location': location,
            'location_type': LocationType.CLOUD.value
        },
        'lifecycle': DatasetLifecycle.IMPORTING,
        'source_type': SourceType.IMPORTED.value
    }
    if file_format:
        values['file_format'] = file_format
    if refresh_schedule:
        data.validate_cron(refresh_schedule, 'refresh_schedule')
    organization_id = session.user_info.organization.organization_id
    result = data.add_dataset(organization_id=organization_id, values=values, project_target_info=_get_target_info(project_id, dataset_type))
    dataset = result['dataset'].get_dict()
    dataset['dataset_instance'] = result['dataset_instance'].get_dict()
    if refresh_schedule:
        refresh_policy = data.add_refresh_policy(organization_id, f'Dataset {name} Refresh', refresh_schedule, RefreshPolicyType.DATASET, dataset_ids=[result['dataset'].get_id()])
        dataset['refresh_schedules'] = [{'refresh_policy_id': refresh_policy.refresh_policy_id, 'cron': refresh_policy.cron, 'next_run_time': refresh_policy.next_run_time}]
    return dataset


@loggedin
@method('POST')
@doc('dataset', hide=True)
@required('name', 'external_connection_id')
@returns(Dataset)
@input_validations(name=common.validate_name, refresh_schedule=lambda x: data.validate_cron(x, 'refresh_schedule'))
def add_external_service_dataset(name: str, external_connection_id: ID, object_name: str = None, columns: str = None, project_id: ID = None, dataset_type: str = None, refresh_schedule: str = None):
    '''
    Creates a dataset from a file located in an external service.

    Args:
        name (String): The name for the dataset to be attached.
        service_id (Unique Identifier of type 'String'): The unique service ID to use.
        object_name (String): If applicable, the name/id of the object in the service to query.
        columns (String): The columns to query from the external service object.
        project_id (Unique Identifier of type 'String'): The project to attach the dataset to, after the dataset has been created.
        dataset_type (Enum of type 'String'): The dataset type to use when projectId is specified. Please see the (Use Case Documentation)[{USE_CASES_URL}] for the datasetTypes that are supported for each use case.
        refresh_schedule (String): The Cron time string format that describes a schedule to retrieve the latest version of the imported dataset. The time is specified in UTC.

    Returns:
        Dataset: The created dataset.

    Raises:
        DataNotFoundError: No file was found at the specified location.
    '''
    values = {
        'name': name,
        'data_source': {
            'external_connection_id': external_connection_id.value,
            'args': columns,
            'location': object_name,
            'location_type': LocationType.EXTERNAL_SERVICE.value
        },
        'lifecycle': DatasetLifecycle.IMPORTING,
        'source_type': SourceType.IMPORTED.value
    }
    result = data.add_dataset(organization_id=session.user_info.organization.organization_id, values=values, project_target_info=_get_target_info(project_id, dataset_type))
    dataset = result['dataset'].get_dict()
    dataset['dataset_instance'] = result['dataset_instance'].get_dict()
    if refresh_schedule:
        data.add_refresh_policy(session.user_info.organization.organization_id, f'Dataset {name} Refresh', refresh_schedule, RefreshPolicyType.DATASET, dataset_ids=[result['dataset'].get_id()])
    return dataset


@loggedin
@doc('streaming', use_cases=['user_recommendations'])
@method('POST')
@required('name', 'project_id', 'dataset_type')
@input_validations(name=common.validate_name)
@returns(Dataset)
def add_streaming_dataset(name: str, project_id: ID, dataset_type: str):
    '''
    Creates a streaming dataset. Use a streaming dataset if your dataset is receiving information from multiple sources over an extended period of time.

    Args:
        project_id (Unique Identifier of type 'String'): The project to create the streaming dataset for.
        name (String): The name for the dataset.
        dataset_type (Enum of type 'String'): The dataset has to be a type that is associated with the use case of your project. Please see (Use Case Documentation)[{USE_CASES_URL}] for the datasetTypes that are supported per use case.

    Returns:
        Dataset: The streaming dataset created. For more information, please refer to the details on the object as follows:
    '''
    if not data.project_supports_streaming(project_id.value):
        raise exceptions.InvalidRequest('This project does not support streaming datasets')
    project_dataset_type = _get_target_info(project_id, dataset_type)['project_dataset_type']
    if project_dataset_type in {dataset.project_dataset_type for dataset in data.get_all_project_datasets(project_id.value)}:
        raise exceptions.ConflictError('This Project already contains a dataset of type %s' % dataset_type)
    values = {
        'name': name,
        'lifecycle': DatasetLifecycle.COMPLETE,
        'source_type': SourceType.STREAMING.value
    }
    result = data.add_dataset(organization_id=session.user_info.organization.organization_id, values=values)
    use_case = db.get_single_value('SELECT use_case FROM projects WHERE project_id=%s', (project_id.value,))
    schema = json.loads(data.get_use_case_yml(use_case)['info']['uiCustom']['schemas'][project_dataset_type]['streaming_schema'])
    data.add_project_dataset(project_id=project_id.value, dataset_id=result['dataset'].get_id(), project_dataset_type=project_dataset_type, pending_column_mapping=schema, skip_inspect=True)
    data.set_project_dataset_ui_state(project_id.value, result['dataset'].get_id(), {'confirm': ['']})
    dataset = result['dataset'].get_dict()
    dataset['dataset_instance'] = result['dataset_instance'].get_dict()
    return dataset


@loggedin
@method('POST')
@required('dataset_id', 'project_id', 'dataset_type')
@returns(ColumnSchema)
def add_dataset_to_project(dataset_id: ID, project_id: ID, dataset_type: str):
    """
    Attaches the dataset to the project.

    Use this method to attach a dataset that is already in the organization to another project. The dataset type is required to let the AI engine know what type of schema should be used.

    Args:
        dataset_id (Unique Identifier of type 'String'): The dataset to attach.
        project_id (Unique Identifier of type 'String'): The project to attach the dataset to
        dataset_type (Enum of type 'String' ): The dataset has to be a type that is associated with the use case of your project. Please see (Use Case Documentation)[{USE_CASES_URL}] for the datasetTypes that are supported per use case.

    Returns:
        List<ColumnSchema>: An array of columns descriptions. For more information, please refer to the details on the object as follows:
    """
    data.add_project_dataset(project_id=project_id.value, dataset_id=dataset_id.value, project_dataset_type=_get_target_info(project_id, dataset_type)['project_dataset_type'])
    return common.resolve_translated_schema(project_id.value, dataset_id.value)


@loggedin
@method('POST')
@required('dataset_id', 'project_id')
@returns(None)
def remove_dataset_from_project(dataset_id: ID, project_id: ID):
    '''
    Removes a dataset from a project.

    Args:
        dataset_id (Unique Identifier of type 'String'): The unique ID associated with the dataset.
        project_id (Unique Identifier of type 'String'): The unique ID associated with the project.
    '''
    data.detach_project_dataset(project_id=project_id.value, dataset_id=dataset_id.value)


@loggedin
@method('DELETE')
@required('dataset_id')
@returns(None)
def delete_dataset(dataset_id: ID):
    '''
    Deletes the specified dataset from the organization.
    The dataset cannot be deleted if it is currently attached to a project.

    Args:
        dataset_id (Unique Identifier of type 'String'): The dataset to delete.

    Raises:
        ConflictError: The dataset is currently attached to one or more projects or refresh policies.
    '''
    # Check for refresh policies
    organization_id = session.user_info.organization.organization_id
    refresh_policies = data.list_refresh_policies(organization_id, dataset_ids=[dataset_id.value])
    if refresh_policies:
        raise exceptions.ConflictError(message='Cannot delete a dataset used in a refresh policy')
    data.delete_dataset(dataset_id=dataset_id.value)


@loggedin
@required('dataset_id')
@returns(Dataset)
def get_dataset(dataset_id: ID):
    '''
    Retrieves a full description of the specified dataset, with attributes such as its ID, name, source type, etc.

    Args:
        dataset_id (Unique Identifier of type 'String'): The unique ID associated with the dataset.

    Returns:
        Dataset: The dataset. For more information, please refer to the details on the object as follows:
    '''
    dataset = data.get_dataset(dataset_id=dataset_id.value).get_dict()
    dataset['dataset_instance'] = data.get_latest_dataset_instance(dataset_id.value, dict_results=True)
    organization_id = session.user_info.organization.organization_id
    refresh_policies = data.list_refresh_policies(organization_id, dataset_ids=[dataset_id.value], policy_types=[RefreshPolicyType.DATASET])
    if refresh_policies:
        dataset['refresh_schedules'] = [{'refresh_policy_id': policy.refresh_policy_id, 'cron': policy.cron, 'next_run_time': policy.next_run_time} for policy in refresh_policies]
    return dataset


@loggedin
@method('POST')
@required('dataset_id', file_format={None, *[file_format.value for file_format in FileFormat]})
@returns(DatasetVersion)
@exclude_streaming_datasets
def import_new_dataset_instance(dataset_id: ID, location: str = None, file_format: str = None):
    '''
    Creates a new version of the specified dataset. The model returns the new version of the dataset with its attributes.

    Args:
        dataset_id (Unique Identifier of type 'String'): The unique ID associated with the dataset.
        location (String): A new location to import the dataset from. If not specified, the last location will be used.
        file_format (String): The file_format to be used. If not specified, the service will try to detect the file format.

    Returns:
        DatasetVersion: The new Dataset Version created. For more information, please refer to the details on the object as follows:

    Raises:
        InvalidParameterError: The location is not a valid cloud location URI.
        PermissionDeniedError: The location has not been verified with {PRODUCT_NAME}.
        DataNotFoundError: No file was found at the specified location.
    '''
    location = location.strip() if location else None
    dataset = data.get_dataset(dataset_id.value)
    if dataset.source_type != SourceType.IMPORTED.value:
        raise exceptions.ConflictError('Cannot read new Dataset Version on this Dataset. Please use the createDatasetVersionFromLocalFile API')
    if location:
        verify_location(location)
    return data.start_dataset_instance_read(dataset_id.value, session.user_info.organization.organization_id, location=location, file_format=file_format or dataset.file_format)


@loggedin
@method('POST')
@required('dataset_id', file_format={None, *[file_format.value for file_format in FileFormat]})
@returns(DatasetUpload)
@exclude_streaming_datasets
def upload_new_dataset_instance(dataset_id: ID, file_format: str = None):
    '''
    Creates a new version of the specified dataset using a local file upload. The method will return the attributes of the dataset.

    Args:
        dataset_id (Unique Identifier of type 'String'): The unique ID associated with the dataset.
        file_format (String): The file_format to be used. If not specified, the service will try to detect the file format.

    Returns:
        DatasetUpload: A token to be used when uploading file parts. For more information, please refer to the details on the object as follows:
    '''
    dataset = data.get_dataset(dataset_id.value)
    if dataset.source_type != SourceType.UPLOADED.value:
        raise exceptions.ConflictError(f'Cannot upload new Dataset Version to this Dataset. Please use the createDatasetVersion API')
    return common.create_dataset_instance_upload(dataset, file_format)


@loggedin
@returns(Dataset)
def list_datasets():
    '''
    Retrieves a list of all of the datasets in the organization, each with their attributes and IDs.

    Returns:
        List<Dataset>: An array of datasets. For more information, please refer to the details on the object as follows:
    '''
    # TODO: Annotate refresh_schedule after pagination is figured out for large orgs
    return [dataset for dataset in data.list_datasets_by_organization(session.user_info.organization.organization_id) if dataset.source_type != SourceType.STREAMING.value]


@loggedin
@required('dataset_id')
@returns(DatasetVersion)
def list_dataset_instances(dataset_id: ID):
    '''
    Retrieves a list of all dataset versions for the specified dataset.

    Args:
        dataset_id (Unique Identifier of type 'String'): The unique ID associated with the dataset.

    Returns:
        List<DatasetVersion>: An array of dataset version. For more information, please refer to the details on the object as follows:
    '''
    return list(data.get_dataset_instances(dataset_id=dataset_id.value, dict_results=True))


@loggedin
@method('POST')
@required('dataset_id', 'name')
@input_validations(name=common.validate_name)
@returns(None)
def rename_dataset(dataset_id: ID, name: str):
    """
    Rename a dataset that has already been defined. Specify the new name and dataset ID, and the model will return the attributes of the renamed dataset.

    Args:
        dataset_id (Unique Identifier of type 'String'): The unique ID associated with the dataset.
        name (String): The new name for the dataset.
    """
    data.update_dataset(dataset_id.value, {'name': name})


@loggedin
@method('POST')
@required('dataset_id', 'url')
@exclude_streaming_datasets
@input_validations(url=lambda x: x.strip())
@returns(None)
def set_dataset_public_source(dataset_id: ID, url: str):
    """
    Set a dataset's public source URL.

    Args:
        dataset_id (Unique Identifier of type 'String'): The Dataset ID
        url (String): The public URL for a dataset source
    """
    if not url.startswith('http'):
        raise exceptions.InvalidParameterError('url', url, 'URL must begin with http')
    data_source = data.read_single_value('data_source', data.Dataset, dataset_id.value) or {}
    data_source['public_url'] = url
    data.update_dataset(dataset_id.value, {'data_source': json.dumps(data_source)})
