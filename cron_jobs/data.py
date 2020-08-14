import MySQLdb._exceptions
import base64
import bcrypt
import collections
import copy
import datetime
import decimal
import feedparser
import graphene
import hashlib
import inflection
import inspect
import io
import ipaddress
import json
import logging
import os
import pytz
import re
import requests
import sys
import time
import uuid
import yaml

from calendar import monthrange
from enum import Enum
from future.moves.urllib.parse import quote
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple
from typing import Union

from croniter import croniter
from promise import Promise
from promise.dataloader import DataLoader

from app import billing
from app import exceptions
from app import send_email
from app.problem_types import discover_data_use
from app.problem_types import get_problem_type
from app.project_errors import ProjectValidationError
from inference_service import utils as inference_svc
from pipeline.servingdata_generate import ServingdataGenerate


TABLE_INFOS = {}
ID_INFOS = {}
ID_KEYS = [''] * utils.MAX_ID_TYPES
CHILD_RELATIONSHIPS = collections.defaultdict(set)


class Loader(DataLoader):
    def __init__(self, **kwargs):
        kwargs['cache'] = kwargs.get('cache', False)
        super().__init__(**kwargs)

    def load(self, *args):
        if len(args) == 1:
            return super().load(args[0])
        else:
            return super().load(tuple(args))


class DatasetLoader(Loader):
    def batch_load_fn(self, keys):
        """ Batch load all the datasets

        Should only be used in graphql functions

        Params:
        :param keys: List of tuples of (<dataset_id>)
        """
        datasets = list_datasets(keys)
        datasets_dict = {ds.dataset_id: ds for ds in datasets}
        datasets_list = [datasets_dict.get(hash_id('dataset_id', ds_id)) for ds_id in keys]
        return Promise.resolve(datasets_list)


class DeploymentsByProjectLoader(Loader):
    def filter_func_gen(self, project_id, status):
        if status is None:
            return lambda x: x.project_id == project_id
        else:
            return lambda x: x.project_id == project_id and x.lifecycle == status

    def batch_load_fn(self, keys):
        """ Batch load deployments

        Supports loading of deployments by project with filtering based on status.
        Since it may be possible for the same project to appear twice, but with different
        status filters, we will need to rearrange the data before returning.

        Params:
        :param keys: List of tuples of form (<project_id>, <status>)
        """
        unique_projects_map = collections.defaultdict(list)
        for project_id, status in keys:
            unique_projects_map[(project_id)].append(status)
        # Generate the where clause
        where_clause = []
        params = []
        for (project_id), statuses in unique_projects_map.items():
            if any([1 for status in statuses if status is None]):
                where_clause.append('project_id=%s')
                params.append(project_id)
            else:
                for status in statuses:
                    where_clause.append('(project_id=%s AND deployments.lifecycle=%s)')
                    params.append(project_id)
                    params.append(status)
        query = ('SELECT deployments.deployment_id, project_id, deployments.name, description, lifecycle, '
                 'deployment_instance_id, model_instance_id '
                 'FROM deployments JOIN projects USING (project_id) JOIN deployment_instances ON (deployment_instance_id) WHERE (')
        query += ' OR '.join(where_clause)
        query += ')'
        deployments = read_instances(query, Deployment, params)
        # Naively reassemble the list of lists
        to_return = []
        for project_id, status in keys:
            encoded_project_id = hash_id('project_id', project_id)
            to_return.append(filter(self.filter_func_gen(encoded_project_id, status), deployments))
        return Promise.resolve(to_return)


class ModelInstanceMetricsLoader(Loader):
    def batch_load_fn(self, keys):
        """ Batch load model instance metrics

        Each model_instance has a metrics object inside its info json. This batch extracts
        this information.

        Params:
        :param keys: List of model_instance_id
        """
        query = 'SELECT model_instance_id, info FROM model_instances WHERE model_instance_id iN (' + ','.join(['%s'] * len(keys)) + ')'
        model_instance_metrics = db.read(query, keys)
        metrics_map = {}
        for metrics in model_instance_metrics:
            metrics_list = []
            for name, score in (metrics.get('info') or {}).get('metrics', {}).items():
                metrics_list.append({'name': name, 'score': score})
            metrics_map[metrics['model_instance_id']] = metrics_list
        return Promise.resolve([metrics_map[key] for key in keys])


class ProjectDatasetsByDataset(Loader):
    def batch_load_fn(self, keys):
        """ Batch load all the project_datasets

        Should only be used in graphql functions

        Params:
        :param keys: List of dataset_ids
        """
        query = 'SELECT project_datasets.*, use_case FROM project_datasets JOIN projects USING (project_id) WHERE dataset_id IN (%s)' % ', '.join(['%s'] * len(keys)) + ' AND lifecycle = %s'
        results = read_instances(query, ProjectDataset, keys + [ProjectDatasetLifecycle.ACTIVE.value])
        order_list = [hash_id('dataset_id', dataset_id) for dataset_id in keys]
        grouped_by_id = collections.defaultdict(list)
        for elem in results:
            grouped_by_id[elem.dataset.dataset_id].append(elem)
        return Promise.resolve([grouped_by_id[dataset_id] for dataset_id in order_list])


class ProjectModelsByProject(Loader):
    def batch_load_fn(self, keys):
        """ Batch load all the project_models

        Should only be used in graphql functions

        Params:
        :param keys: List of project_ids
        """
        query = 'SELECT * FROM models WHERE '
        query += ' OR '.join(['(project_id=%s)'] * len(keys))
        args = []
        order_list = []
        for project_id in keys:
            args.append(project_id)
            order_list.append(hash_id('project_id', project_id))
        results = read_instances(query, Model, args)
        group_by_id = collections.defaultdict(list)
        for elem in results:
            key = elem.project.project_id
            group_by_id[key].append(elem)
        return Promise.resolve([group_by_id[key] for key in order_list])


class ProjectDatasetsByProject(Loader):
    def batch_load_fn(self, keys):
        """ Batch load all the project_datasets

        Should only be used in graphql functions

        Params:
        :param keys: List of <project_id>
        """
        query = 'SELECT project_datasets.*, use_case FROM project_datasets JOIN projects USING (project_id) JOIN datasets USING (dataset_id) WHERE project_id IN (%s)' % ', '.join(['%s'] * len(keys))
        results = read_instances(query, ProjectDataset, keys)
        order_list = [hash_id('project_id', project_id) for project_id in keys]
        grouped_by_id = collections.defaultdict(list)
        for elem in results:
            grouped_by_id[elem.project.project_id].append(elem)
        return Promise.resolve([grouped_by_id[project_id] for project_id in order_list])


class DatasetsInstances(Loader):
    def batch_load_fn(self, keys):
        """ Batch load all the projects

        Should only be used in graphql functions

        Params:
        :param keys: List of tuples (<dataset_id>)
        """
        query = 'SELECT * FROM dataset_instances WHERE '

        order_list = []
        where_list = []
        vals = []
        for dataset_id in keys:
            order_list.append(hash_id('dataset_id', dataset_id))

            where_this = '(dataset_id=%s)'
            vals.append(dataset_id)
            where_list.append(where_this)

        query += ' OR '.join(where_list)
        results = read_instances(query, DatasetInstance, vals)

        grouped_by_id = collections.defaultdict(list)
        for elem in results:
            grouped_by_id[elem.dataset.dataset_id].append(elem)
        return Promise.resolve([grouped_by_id[dataset_id] for dataset_id in order_list])


class DatasetsInstancesCount(Loader):
    def batch_load_fn(self, keys):
        """ Batch load the number of dataset instances for a given dataset

        Should only be used in graphql functions

        Params:
        :param keys: List of tuples (<dataset_id>)
        """
        query = 'SELECT dataset_id FROM dataset_instances WHERE '

        order_list = []
        where_list = []
        vals = []
        for dataset_id in keys:
            order_list.append(hash_id('dataset_id', dataset_id))

            where_this = '(dataset_id=%s)'
            vals.append(dataset_id)
            where_list.append(where_this)

        query += ' OR '.join(where_list)
        results = read_instances(query, DatasetInstance, vals)
        grouped_by_id = collections.defaultdict(list)
        for elem in results:
            grouped_by_id[elem.dataset.dataset_id].append(elem)
        return Promise.resolve([len(grouped_by_id[dataset_id]) if grouped_by_id[dataset_id] else 0 for dataset_id in order_list])


class DatasetsInstancesLast(Loader):
    def batch_load_fn(self, keys):
        """ Batch load all the projects

        Should only be used in graphql functions

        Params:
        :param keys: List of <dataset_id>
        """
        dataset_list = db.read('SELECT dataset_id, MAX(dataset_instance_id) AS ds_instance_id FROM dataset_instances WHERE dataset_id IN (' + ', '.join(['%s'] * len(keys)) + ') GROUP BY dataset_id', [dataset_id for dataset_id in keys])
        results = []
        if dataset_list:
            dataset_instance_ids = [row['ds_instance_id'] for row in dataset_list]
            results = read_instances('SELECT dataset_instances.*, datasets.name, datasets.source_type FROM dataset_instances JOIN datasets USING (dataset_id) WHERE dataset_instance_id IN (' + ', '.join(['%s'] * len(dataset_instance_ids)) + ')', DatasetInstance, dataset_instance_ids)

        order_list = [hash_id('dataset_id', dataset_id) for dataset_id in keys]
        grouped_by_id = collections.defaultdict(list)
        for elem in results:
            grouped_by_id[elem.dataset.dataset_id].append(elem)
        return Promise.resolve([(grouped_by_id[dataset_id][0] if grouped_by_id[dataset_id] else None) for dataset_id in order_list])


class ProjectLoader(Loader):
    def batch_load_fn(self, keys):
        """ Batch load all the projects

        Should only be used in graphql functions

        Params:
        :param keys: List of tuples of (<project_id>)
        """
        projects = get_projects(project_ids=keys)
        projects_dict = {proj.project_id: proj for proj in projects}
        projects_list = [projects_dict.get(hash_id('project_id', project_id)) for project_id in keys]
        return Promise.resolve(projects_list)


class UserLoader(Loader):
    def batch_load_fn(self, keys):
        return Promise.resolve([get_user(user_id) for user_id in keys])


class OrganizationLoader(Loader):
    def batch_load_fn(self, keys):
        return Promise.resolve([get_organization(organization_id) for organization_id in keys])


""" Initialize the dataloaders since these are global-ish objects
"""
dataset_instances_last_loader = DatasetsInstancesLast()
dataset_instances_loader = DatasetsInstances()
dataset_instances_count_loader = DatasetsInstancesCount()
dataset_loader = DatasetLoader()
deployments_by_project_loader = DeploymentsByProjectLoader()
model_instance_metrics_loader = ModelInstanceMetricsLoader()
project_datsets_by_dataset_loader = ProjectDatasetsByDataset()
project_datasets_by_project_loader = ProjectDatasetsByProject()
project_loader = ProjectLoader()
project_models_by_project_loader = ProjectModelsByProject()
user_loader = UserLoader()
organization_loader = OrganizationLoader()


""" Graphene Enums
"""
DeploymentLifecycleField = graphene.Enum.from_enum(DeploymentLifecycle)
DatasetLifecycleField = graphene.Enum.from_enum(DatasetLifecycle)
DatasetUploadLifecycleField = graphene.Enum.from_enum(DatasetUploadLifecycle)
ProjectDatasetLifecycleField = graphene.Enum.from_enum(ProjectDatasetLifecycle)
ModelLifecycleField = graphene.Enum.from_enum(ModelLifecycle)
DatasetGroupLifecycleField = graphene.Enum.from_enum(DatasetGroupLifecycle)
BatchPredictionLifecycleField = graphene.Enum.from_enum(BatchPredictionLifecycle)
InvoiceLifecycleField = graphene.Enum.from_enum(InvoiceLifecycle)
PricingPlanField = graphene.Enum.from_enum(PricingPlan)
BillingPlanField = graphene.Enum.from_enum(BillingPlan)
LoginServiceField = graphene.Enum.from_enum(LoginService)
RefreshPipelineField = graphene.Enum.from_enum(RefreshPipelineLifecycle)
RefreshPolicyTypeField = graphene.Enum.from_enum(RefreshPolicyType)
ConnectionStatusField = graphene.Enum.from_enum(ConnectionStatus)


def is_table_type(_type):
    """
    Helper to check if we are a sub type of BaseTable
    """
    return inspect.isclass(_type) and _type.__module__ == is_table_type.__module__ and hasattr(_type, 'table_type') and _type != BaseTable


class BaseTable(graphene.ObjectType):
    table_type = None
    table_name = None
    common_columns = ['created_at', 'updated_at', 'picture', 'info', 'description']
    internal_columns = None
    api_id_range_ordering = None
    parents = None
    id_column = None
    parent_rel_id_columns = None
    all_columns = None
    has_id = True
    enums = None
    bools = None

    @classmethod
    def init(cls):
        cls.table_type = inflection.underscore(cls.__name__)
        cls.table_name = cls.table_type + 's' if not cls.table_name else cls.table_name
        cls.id_column = cls.table_type + '_id' if cls.has_id else cls.table_type
        if cls.internal_columns is None:
            cls.internal_columns = []
        if cls.parents is None:
            cls.parents = []
        if cls.enums is None:
            cls.enums = {}
        if cls.bools is None:
            cls.bools = []

        global ID_KEYS, ID_INFOS, TABLE_INFOS
        if cls.api_id_range_ordering is not None:
            ID_KEYS[cls.api_id_range_ordering] = cls.id_column
        cls.all_columns = set(cls.common_columns + cls.internal_columns)
        ID_INFOS[cls.id_column] = cls
        cls.all_columns.add(cls.id_column)
        TABLE_INFOS[cls.table_type] = cls

        for field_name, field_val in inspect.getmembers(cls, lambda a: not inspect.isfunction(a)):
            if not field_val or not field_val.__class__.__module__.startswith('graphene.') or field_name.startswith('_'):
                continue

            if isinstance(field_val, graphene.Field) and is_table_type(field_val.type):
                cls.parents.append(field_val.type)
            else:
                if isinstance(field_val, graphene.Enum):
                    cls.enums[field_name] = field_val
                elif isinstance(field_val, graphene.Boolean):
                    cls.bools.append(field_name)
                cls.all_columns.add(field_name)

        cls.parent_rel_id_columns = set()

    @classmethod
    def init_relationships(cls):
        global CHILD_RELATIONSHIPS
        for parent in cls.parents:
            CHILD_RELATIONSHIPS[parent.table_name].add(cls)
            cls.parent_rel_id_columns.add(parent.id_column)
        cls.all_columns.update(cls.parent_rel_id_columns)

    def __init__(self, db_row={}, processed_cols=None, processed_tables=None, suffix_translations=None):
        if processed_cols is None:
            processed_cols = set()
        if processed_tables is None:
            processed_tables = set()
        if suffix_translations is None:
            suffix_translations = []
        self._from_db_row(db_row, processed_cols, processed_tables, suffix_translations)

    def _from_db_row(self, db_row, processed_cols, processed_tables, suffix_translations):
        if not db_row:
            return

        if self.table_type in processed_tables:
            return

        remaining_cols = [col for col in db_row if col not in processed_cols]
        if not remaining_cols:
            return

        seen_cols = set()
        parent_rel_id_cols_found = set()

        def get_stripped_col(col):
            if col.startswith(self.table_name + '.'):
                return col[len(self.table_name) + 1:]
            return None

        def assign_value(obj, col, val):
            if col in self.enums:
                val = self.enums[col]._meta.enum(val)
            for suffix, translate in suffix_translations:
                if val is not None and col.endswith(suffix):
                    val = translate(col, val)
            setattr(obj, col, val)

        # First look for columns prefixed with our table name. Those
        # take precedence. Along the way, calculate the parent relationship structs
        # that we will populate.
        for col in remaining_cols:
            val = db_row[col]
            stripped_col = get_stripped_col(col)
            if stripped_col and stripped_col in self.all_columns:
                if stripped_col not in self.parent_rel_id_columns:
                    assign_value(self, stripped_col, val)
                    seen_cols.add(stripped_col)
                else:
                    parent_rel_id_cols_found.add(col)
                processed_cols.add(col)

        for col in remaining_cols:
            if col in processed_cols or col in seen_cols or col not in self.all_columns:
                continue
            val = db_row[col]
            if col not in self.parent_rel_id_columns:
                if col in self.bools:
                    val = bool(val)
                assign_value(self, col, val)
            else:
                parent_rel_id_cols_found.add(col)
            processed_cols.add(col)

        processed_tables.add(self.table_type)

        for parent_rel_id_col in parent_rel_id_cols_found:
            stripped_col = get_stripped_col(parent_rel_id_col)
            col = parent_rel_id_col if not stripped_col else stripped_col
            parent = ID_INFOS[col]
            parent_obj = parent(db_row, processed_cols, processed_tables)
            assign_value(parent_obj, col, db_row[parent_rel_id_col])
            assign_value(self, parent_obj.table_type, parent_obj)

    @classmethod
    def validate_and_translate(cls, vals: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = {}
        if not vals:
            return sanitized
        for col, val in vals.items():
            if col not in cls.all_columns:
                continue

            if cls.has_id and col == cls.id_column or col in cls.parent_rel_id_columns and col[-3:] == '_id':
                id_val = unhash_id_with_type(val, col, allow_ints=True)
                if id_val is None:
                    continue
                val = id_val
            elif isinstance(val, Enum):
                val = val.value

            sanitized[col] = val
        return sanitized

    def get_value(self, key):
        if hasattr(self, key) and not getattr(self, key).__class__.__module__.startswith('graphene.'):
            return getattr(self, key)
        return None

    def get_dict(self, skip_sub_structs=False):
        vals = {k: getattr(self, k) for k in self.all_columns if hasattr(self, k) and
                not getattr(self, k).__class__.__module__.startswith('graphene.')}

        for parent in self.parents:
            if hasattr(self, parent.table_type) and not getattr(self, parent.table_type).__class__.__module__.startswith('graphene.'):
                parent_obj = getattr(self, parent.table_type)
                if parent_obj:
                    if not skip_sub_structs:
                        parent_obj = parent_obj.get_dict()
                    vals[parent.table_type] = parent_obj
        return vals

    def get_id(self):
        if self.id_column and hasattr(self, self.id_column):
            return unhash_id_with_type(getattr(self, self.id_column), self.id_column, allow_ints=True)
        return None

    def __repr__(self):
        return self.__class__.__name__ + '(' + repr(self.get_dict(True)) + ')'

    def __str__(self):
        return self.__class__.__name__ + '(' + str(self.get_dict(True)) + ')'

    def __eq__(self, other):
        if isinstance(other, BaseTable):
            return self.get_dict(True) == other.get_dict(True)
        return False


class Organization(BaseTable):
    internal_columns = ['info']
    api_id_range_ordering = 0

    organization_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    name = graphene.String()
    picture = graphene.String()
    domain = graphene.String()
    discoverable = graphene.Boolean()
    workspace = graphene.String()
    info = graphene.JSONString()
    billing_account_id = graphene.String()
    billing_plan = graphene.String()  # BillingPlanField() @TODO update when all orgs have been updated
    pricing_plan = graphene.String()  # PricingPlanField()
    last_billed_at = graphene.types.datetime.DateTime()
    cluster_name = graphene.String()
    cloud_info = graphene.JSONString()

    def resolve_cloud_info(self, info):
        return get_cloud_from_cluster(self.cluster_name)


class User(BaseTable):
    internal_columns = ['password', 'info', 'verification_token', 'signup_token', 'suspended', 'signup_user_agent']
    api_id_range_ordering = 1

    user_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    name = graphene.String()
    picture = graphene.String()
    organization = graphene.Field(Organization)
    email = graphene.String()
    user_handle = graphene.String()
    info = graphene.JSONString()
    password = graphene.String()
    email_validated = graphene.Boolean()
    verification_token = graphene.String()
    signup_token = graphene.String()
    last_login_time = graphene.types.datetime.DateTime()
    organization_admin = graphene.Boolean()
    billing = graphene.String()
    suspended = graphene.Boolean()
    email_channels = graphene.JSONString()
    signup_user_agent = graphene.String()
    can_join_org = graphene.Boolean()
    force_verification = graphene.Boolean()
    bio = graphene.String()

    def resolve_force_verification(self, info):
        return not self.email_validated and bool(get_unjoined_orgs(self.get_id()))

    def resolve_can_join_org(self, info):
        return self.email_validated and bool(get_unjoined_orgs(self.get_id()))

    def resolve_billing(self, info):
        flag = 'default'
        if self.info and 'flag' in self.info and not (self.info['flag'] or '').startswith('default'):
            flag = self.info['flag']
        return BillingPlan.CC.value if get_config_flags(flag, environment.get_default_flag()).get(Flags.CC_REQUIRED.value) else BillingPlan.FREE.value

    def resolve_organization_admin(self, info):
        if self.organization.get_id() != 0:
            org_user = get_organization_user(self.organization.get_id(), self.get_id())
            return org_user and org_user.admin
        return False

    def resolve_email_channels(self, info):
        email_preferences = {'MARKETING': not bool(get_unsubscribe_request(self.email))}
        if self.organization.get_id() != 0:
            email_preferences.update(get_user_org_preferences(self.get_id(), self.organization.get_id()))
        return email_preferences


class UserInvite(BaseTable):
    api_id_range_ordering = 16
    user_invite_id = graphene.ID()
    email = graphene.String()
    user = graphene.Field(User)
    organization = graphene.Field(Organization)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    accepted_at = graphene.types.datetime.DateTime()


class PasswordResetRequest(BaseTable):
    api_id_range_ordering = 17
    password_reset_request_id = graphene.ID()
    request_token = graphene.String()
    user = graphene.Field(User)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    expires_at = graphene.types.datetime.DateTime()


class UseCase(BaseTable):
    has_id = False

    use_case = graphene.String()
    prediction_api = graphene.String()
    description = graphene.String()
    pretty_name = graphene.String()
    img_src = graphene.String()
    pretty_name_web = graphene.String()
    info = graphene.String()

    def resolve_info(self, info):
        use_case_data = get_use_case_yml(self.use_case)
        if use_case_data:
            full_batch_supported = not get_problem_type(use_case_data['problem_type']).disable_full_batch_prediction()
            use_case_data = use_case_data.get('info')
            use_case_data['full_batch_supported'] = full_batch_supported

        return json.dumps(use_case_data) if use_case_data else None


class Project(BaseTable):
    api_id_range_ordering = 4
    internal_columns = ['info', 'ingress_type', 'ingress_name']

    project_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    name = graphene.String()
    problem_type = graphene.String()
    use_case = graphene.String()
    info = graphene.JSONString()

    all_project_datasets = graphene.List(lambda: ProjectDataset)
    all_project_models = graphene.List(lambda: Model)
    deployments = graphene.List(lambda: Deployment, status=DeploymentLifecycleField())

    is_pnp = graphene.Boolean()

    def resolve_all_project_models(self, info):
        return project_models_by_project_loader.load(self.get_id())

    def resolve_all_project_datasets(self, info):
        return project_datasets_by_project_loader.load(self.get_id())

    def resolve_deployments(self, info, status=None):
        return deployments_by_project_loader.load(self.get_id(), status)

    def resolve_is_pnp(self, info):
        return self.problem_type == ProblemType.CUSTOM.value


class ProjectOwner(BaseTable):
    internal_columns = ['info']
    has_id = False

    project = graphene.Field(Project)
    organization = graphene.Field(Organization)
    created_at = graphene.types.datetime.DateTime()


class Dataset(BaseTable):
    api_id_range_ordering = 5
    internal_columns = ['data_source']

    dataset_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    name = graphene.String()

    data_source = graphene.JSONString()
    source_type = graphene.String()
    schema_values = graphene.JSONString()
    file_format = graphene.String()
    refresh_schedules = graphene.JSONString()

    last_version = graphene.Field(lambda: DatasetInstance)
    all_versions = graphene.List(lambda: DatasetInstance)
    version_count = graphene.Int()

    all_project_datasets = graphene.List(lambda: ProjectDataset)

    def resolve_last_version(self, info):
        dataset_id = unhash_id_with_type(self.dataset_id, 'dataset_id')
        return dataset_instances_last_loader.load(dataset_id)

    def resolve_all_versions(self, info):
        dataset_id = unhash_id_with_type(self.dataset_id, 'dataset_id')
        return dataset_instances_loader.load(dataset_id)

    def resolve_all_project_datasets(self, info):
        dataset_id = unhash_id_with_type(self.dataset_id, 'dataset_id')
        return project_datsets_by_dataset_loader.load(dataset_id)

    def resolve_version_count(self, info):
        dataset_id = unhash_id_with_type(self.dataset_id, 'dataset_id')
        return dataset_instances_count_loader.load(dataset_id)


class DatasetOwner(BaseTable):
    internal_columns = ['info']
    has_id = False

    dataset = graphene.Field(Dataset)
    organization = graphene.Field(Organization)
    created_at = graphene.types.datetime.DateTime()

    def resolve_organization(self, info):
        organization_id = unhash_id_with_type(self.organization.organization_id, 'organization_id')
        return organization_loader.load(organization_id)

    def resolve_dataset(self, info):
        dataset_id = unhash_id_with_type(self.dataset.dataset_id, 'dataset_id')
        return dataset_loader.load(dataset_id)


class DatasetInstance(BaseTable):
    api_id_range_ordering = 10
    internal_columns = ['location', 'metrics_lifecycle']

    dataset_instance_id = graphene.ID()
    dataset_version = graphene.String()
    dataset = graphene.Field(Dataset)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    tag = graphene.String()
    errors = graphene.String()

    inspecting_started_at = graphene.types.datetime.DateTime()
    inspecting_completed_at = graphene.types.datetime.DateTime()

    lifecycle = DatasetLifecycleField()
    lifecycle_msg = graphene.String()

    location = graphene.String()
    size = graphene.String()
    schema_values = graphene.JSONString()
    file_format = graphene.String()

    all_project_datasets = graphene.List(lambda: ProjectDataset)
    status = graphene.String()
    has_metrics = graphene.Boolean()

    def resolve_dataset_version(self, info):
        return self.dataset_instance_id

    def resolve_status(self, info):
        return self.lifecycle.value if self.lifecycle else None

    def resolve_has_metrics(self, info):
        return self.get_value('metrics_lifecycle') == DatasetMetricsLifecycle.COMPLETE

    def resolve_all_project_datasets(self, info):
        dataset_id = unhash_id_with_type(self.dataset.dataset_id, 'dataset_id')
        return project_datsets_by_dataset_loader.load(dataset_id)


class DatasetUpload(BaseTable):
    api_id_range_ordering = 15
    internal_columns = ['upload_id', 'cloud_url']

    dataset_upload_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    lifecycle = DatasetUploadLifecycleField()
    lifecycle_msg = graphene.String()
    dataset = graphene.Field(Dataset)
    dataset_instance = graphene.Field(DatasetInstance)
    dataset_version = graphene.Field(DatasetInstance)
    upload_id = graphene.String()
    cloud_url = graphene.String()
    upload_type = graphene.String()
    project_target_info = graphene.JSONString()

    status = graphene.String()

    def resolve_dataset_version(self, info):
        return self.dataset_instance

    def resolve_status(self, info):
        return self.lifecycle.value if self.lifecycle else None


class ProjectDataset(BaseTable):
    has_id = False
    project = graphene.Field(Project)
    dataset = graphene.Field(Dataset)
    created_at = graphene.types.datetime.DateTime()
    detached_at = graphene.types.datetime.DateTime()
    lifecycle = ProjectDatasetLifecycleField()
    lifecycle_msg = graphene.String()
    data_usage_config = graphene.JSONString()
    project_dataset_type = graphene.String()
    ui_wizard_state = graphene.JSONString()

    status = graphene.String()
    dataset_type = graphene.String()

    def resolve_status(self, info):
        return self.lifecycle.value if self.lifecycle else None

    def resolve_dataset_type(self, info):
        use_case = self.project.get_value('use_case')
        dataset_type = self.get_value('project_dataset_type')
        if use_case:
            dataset_type = get_use_case_schema(use_case).get(dataset_type, {}).get('dataset_type', dataset_type)
        return dataset_type

    def resolve_project(self, info):
        # Skip resolving projects if we only select the project id
        selected_project_fields = info.field_asts[0].selection_set.selections
        if len(selected_project_fields) == 1 and selected_project_fields[0].name.value == 'projectId':
            return self.project
        else:
            project_id = unhash_id_with_type(self.project.project_id, 'project_id')
            return project_loader.load(project_id)

    def resolve_dataset(self, info):
        selected_dataset_fields = info.field_asts[0].selection_set.selections
        if len(selected_dataset_fields) == 1 and selected_dataset_fields[0].name.value == 'datasetId':
            return self.dataset
        else:
            dataset_id = unhash_id_with_type(self.dataset.dataset_id, 'dataset_id')
            return dataset_loader.load(dataset_id)


class SocialLogin(BaseTable):
    has_id = False

    user = graphene.Field(User)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    service = LoginServiceField()
    service_id = graphene.String()


class OrganizationUser(BaseTable):
    has_id = False
    organization = graphene.Field(Organization)
    user = graphene.Field(User)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    admin = graphene.Boolean()
    preferences = graphene.JSONString()


class Model(BaseTable):
    api_id_range_ordering = 6
    internal_columns = ['model_config', 'description', 'votes', 'comments', 'publish_status']
    parents = [Project]

    model_id = graphene.ID()
    name = graphene.String()
    created_at = graphene.types.datetime.DateTime()
    algorithm = graphene.String()
    model_config = graphene.JSONString()
    primary_model_id = graphene.Int()
    shared = graphene.Boolean()
    shared_at = graphene.types.datetime.DateTime()


class ModelInstance(BaseTable):
    api_id_range_ordering = 11
    internal_columns = ['algorithm', 'dataset_instance_group_id', 'training_output_params']
    parents = [Project]

    model_instance_id = graphene.ID()
    model_version = graphene.String()
    model = graphene.Field(lambda: Model)
    tag = graphene.String()
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    algorithm = graphene.String()
    model_config = graphene.JSONString()
    dataset_instance_group = graphene.Field(lambda: DatasetInstanceGroup)

    lifecycle = ModelLifecycleField()
    lifecycle_msg = graphene.String()
    training_started_at = graphene.types.datetime.DateTime()
    training_completed_at = graphene.types.datetime.DateTime()
    status = graphene.String()
    training_output_params = graphene.JSONString()

    def resolve_model_version(self, info):
        return self.model_instance_id

    def resolve_status(self, info):
        return self.lifecycle.value if self.lifecycle else None

    def resolve_metrics(self, info):
        model_instance_id = unhash_id_with_type(self.model_instance_id, 'model_instance_id')
        return model_instance_metrics_loader.load(model_instance_id)


class DatasetInstanceGroup(BaseTable):
    api_id_range_ordering = 14
    internal_columns = ['dataset_instance_ids', 'training_config']

    dataset_instance_group_id = graphene.ID()
    project = graphene.Field(Project)
    created_at = graphene.types.datetime.DateTime()
    dataset_instance_ids = graphene.JSONString()
    data_usage_config = graphene.JSONString()
    preparation_config = graphene.JSONString()
    lifecycle = DatasetGroupLifecycleField()
    lifecycle_msg = graphene.String()
    preparation_started_at = graphene.types.datetime.DateTime()
    preparation_completed_at = graphene.types.datetime.DateTime()

    status = graphene.String()

    def resolve_status(self, info):
        return self.lifecycle.value if self.lifecycle else None


class RangeDates(graphene.ObjectType):
    start = graphene.String()
    end = graphene.String()


class Deployment(BaseTable):
    api_id_range_ordering = 12
    internal_columns = ['deployment_config', 'cluster_name', 'num_replicas', 'calls_per_second', 'ingress_type', 'ingress_name']

    deployment_id = graphene.ID()
    deployment_instance = graphene.Field(lambda: DeploymentInstance)
    deployment_version = graphene.Field(lambda: DeploymentInstance)

    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    name = graphene.String()
    description = graphene.String()
    model = graphene.Field(Model)
    project = graphene.Field(Project)

    def resolve_deployment_version(self, info):
        return self.deployment_instance


class DeploymentInstance(BaseTable):
    api_id_range_ordering = 13
    internal_columns = ['git_hash', 'docker_sha',
                        'disable_tf_serving', 'use_datatransform_server', 'cluster_name', 'service_url',
                        'num_replicas', 'calls_per_second', 'streaming_data_source_id', 'deployment_completed_at']

    deployent_instance_id = graphene.ID()
    deployment_version = graphene.String()
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    deployed_at = graphene.types.datetime.DateTime()
    deployment = graphene.Field(Deployment)
    model_instance = graphene.Field(ModelInstance)
    model_version = graphene.Field(ModelInstance)
    deployment_config = graphene.JSONString()
    lifecycle = DeploymentLifecycleField()
    lifecycle_msg = graphene.String()
    tag = graphene.String()

    status = graphene.String()

    def resolve_deployment_version(self, info):
        return self.deployment_instance_id

    def resolve_model_version(self, info):
        return self.model_instance

    def resolve_status(self, info):
        return self.lifecycle.value if self.lifecycle else None

    def resolve_deployed_at(self, info):
        return self.get_value('deployment_completed_at')


class ApiKey(BaseTable):
    api_id_range_ordering = 18
    internal_columns = ['api_key']

    api_key_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    api_key = graphene.String()
    user = graphene.Field(User)
    organization = graphene.Field(Organization)
    tag = graphene.String()


class DeploymentAuthToken(BaseTable):
    api_id_range_ordering = 19

    deployment_auth_token_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    auth_token = graphene.String()
    project = graphene.Field(Project)


class BatchPrediction(BaseTable):
    api_id_range_ordering = 20
    internal_columns = ['serving_dataset_instance_group_id']

    batch_prediction_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    predictions_started_at = graphene.types.datetime.DateTime()
    predictions_completed_at = graphene.types.datetime.DateTime()
    lifecycle = BatchPredictionLifecycleField()
    lifecycle_msg = graphene.String()
    model_instance = graphene.Field(ModelInstance)
    deployment = graphene.Field(Deployment)
    data_source = graphene.JSONString()
    output_location = graphene.String()
    uploaded_input = graphene.Boolean()
    internal_input = graphene.Boolean()
    internal_output = graphene.Boolean()
    name = graphene.String()

    status = graphene.String()

    def resolve_status(self, info):
        return self.lifecycle.value if self.lifecycle else None


class Alert(BaseTable):
    api_id_range_ordering = 21

    alert_id = graphene.ID()
    user = graphene.Field(User)
    organization = graphene.Field(Organization)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    title = graphene.String()
    description = graphene.String()
    seen = graphene.Boolean()


class BetaSignup(BaseTable):
    api_id_range_ordering = 22

    beta_signup_id = graphene.ID()
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    invited_at = graphene.types.datetime.DateTime()
    use_case = graphene.String()
    organization_size = graphene.String()
    name = graphene.String()
    email = graphene.String()
    organization = graphene.String()
    comment = graphene.String()
    user_agent = graphene.String()
    ip_addr = graphene.String()
    blacklist = graphene.Boolean()
    tag = graphene.String()
    consultation = graphene.Boolean()


class Invoice(BaseTable):
    api_id_range_ordering = 23

    invoice_id = graphene.ID()
    stripe_invoice_id = graphene.String()
    organization = graphene.Field(Organization)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    due_at = graphene.types.datetime.DateTime()
    paid_at = graphene.types.datetime.DateTime()
    paid_using = graphene.String()
    lifecycle = InvoiceLifecycleField()
    invoice_items = graphene.JSONString()
    total = graphene.Int()
    billing_period_start = graphene.types.datetime.DateTime()
    billing_period_end = graphene.types.datetime.DateTime()


class ExternalConnection(BaseTable):
    api_id_range_ordering = 24

    external_connection_id = graphene.ID()
    service = graphene.String()
    organization = graphene.Field(Organization)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    service_id = graphene.String()
    name = graphene.String()
    auth = graphene.JSONString()
    status = ConnectionStatusField()


class StreamingAuthToken(BaseTable):
    has_id = False

    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    auth_token = graphene.String()
    organization = graphene.Field(Organization)


class CommunityInteraction(BaseTable):
    # Placeholder for id encding only
    api_id_range_ordering = 7

    community_interaction_id = graphene.ID()


class RefreshPolicy(BaseTable):
    api_id_range_ordering = 2
    table_name = 'refresh_policies'
    internal_columns = ['project_id', 'dataset_ids', 'model_ids', 'deployment_ids']

    refresh_policy_id = graphene.ID()
    organization = graphene.Field(Organization)
    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    name = graphene.String()
    cron = graphene.String()
    next_run_time = graphene.types.datetime.DateTime()
    refresh_type = RefreshPolicyTypeField()


class RefreshPipelineRun(BaseTable):
    api_id_range_ordering = 3
    internal_columns = ['dataset_instance_ids', 'model_instance_ids', 'deployment_instance_ids', 'batch_prediction_ids', 'serving_dataset_instance_group_ids']

    refresh_pipeline_run_id = graphene.ID()
    organization = graphene.Field(Organization)
    refresh_policy_id = graphene.Field(RefreshPolicy)
    refresh_type = RefreshPolicyTypeField()

    created_at = graphene.types.datetime.DateTime()
    updated_at = graphene.types.datetime.DateTime()
    started_at = graphene.types.datetime.DateTime()
    completed_at = graphene.types.datetime.DateTime()

    lifecycle = RefreshPipelineField()
    lifecycle_msg = graphene.String()
    status = graphene.String()

    def resolve_status(self, info):
        return self.lifecycle.value if self.lifecycle else None


_ddl_initialized = False


def _initialize_ddl():
    global _ddl_initialized
    if _ddl_initialized:
        return
    table_types = []
    for name, member in inspect.getmembers(sys.modules[__name__]):
        if is_table_type(member):
            member.init()
            table_types.append(member)

    for table_type in table_types:
        table_type.init_relationships()

    # TODO(arvind): Sanity check for api_id_range_ordering collisions and relationship constraints
    _ddl_initialized = True


_initialize_ddl()


def date_field(val):
    return val.isoformat()


def unhash_id(val, allow_ints: bool = False):
    if val is None:
        return None, None

    if environment.in_devpod() or allow_ints:
        try:
            int_id = int(val)
            if int_id < 1000000:
                return int_id, None
        except ValueError:
            pass
    elif type(val) != str:
        return None, None

    global ID_KEYS
    return utils.unhash_id(ID_KEYS, val)


def unhash_id_with_type(val, id_type, allow_ints: bool = False):
    resolved_val, resolved_id_type = unhash_id(val, allow_ints=allow_ints)
    if resolved_id_type and id_type != resolved_id_type:
        return None
    return resolved_val


def hash_id(key=None, val=None, **kwargs):
    global ID_INFOS
    if not key and kwargs:
        key = next(iter(kwargs))
        val = kwargs[key]
    if key not in ID_INFOS:
        return val
    return utils.hash_id(ID_KEYS, key, val)


def parse_and_unhash_list(id_list, id_type):
    # Note: for request api?id=a&id=b&id=c,d we get ['a', 'b', 'c,d']
    exploded_list = []
    for item in id_list or []:
        exploded_list.extend(item.split(','))
    return [unhash_id_with_type(val, id_type) for val in exploded_list]


def get_base_table_attr(base_table_obj: Union[dict, BaseTable], *attrs: str):
    is_base_table_obj = isinstance(base_table_obj, dict)
    attr_val = base_table_obj
    for attr in attrs:
        attr_val = attr_val[attr] if is_base_table_obj else getattr(attr_val, attr)
        if attr.endswith('_id') and isinstance(attr_val, str):
            return unhash_id_with_type(attr_val, attr)
    return attr_val


API_TRANSLATIONS = [
    ('_id', hash_id),
]

NAME_TRANSLATIONS = [
    ('password', None),
]

TYPE_TRANSLATIONS = {
    datetime.datetime: date_field,
    datetime.date: date_field,
    Enum: lambda x: x.value.upper()
}


def create_instance(data_type: BaseTable, values: Dict[str, Any]):
    table = data_type.table_name
    id_name = data_type.id_column
    sanitized = data_type.validate_and_translate(values)
    if not sanitized:
        raise exceptions.InstanceNotModifiedError('create', data_type.table_type)

    new_id = db.add_row(table, None, None, sanitized)
    if data_type.has_id and new_id:
        instance = read_one_instance(f'SELECT * FROM {table} WHERE {id_name}=%s', data_type, (new_id,))
        if instance:
            return instance
    elif data_type.has_id:
        raise exceptions.InstanceNotModifiedError('create', data_type.table_type)
    return True


def read_instances(query: str, result_type: BaseTable, params: Tuple[Any] = None, skip_translate: bool = False, dict_results: bool = False):
    rows = db.read(query, params) or []
    if not rows:
        return []

    suffix_translations = API_TRANSLATIONS if not skip_translate else []
    results = [result_type(row, suffix_translations=suffix_translations) for row in rows]
    if dict_results:
        results = [r.get_dict() for r in results]
    return results


def read_one_instance(query: str, result_type: BaseTable, params: Tuple[Any] = None, skip_translate: bool = False, dict_results: bool = False):
    row = db.read_one(query, params)
    if not row:
        return None

    suffix_translations = API_TRANSLATIONS if not skip_translate else []
    result = result_type(row, suffix_translations=suffix_translations)
    if dict_results:
        result = result.get_dict()
    return result


def read_single_value(value: str, data_type: BaseTable, id_value: int):
    table = data_type.table_name
    id_name = data_type.id_column
    return db.get_single_value(f'SELECT {value} FROM {table} WHERE {id_name}=%s', (id_value,))


def read_single_value_where(value: str, data_type: BaseTable, **kwargs):
    table = data_type.table_name
    return db.get_single_value(f'SELECT {value} FROM {table} WHERE ' + ' AND '.join([id_name + '=%s' for id_name in kwargs]), tuple(kwargs.values()))


def update_instance(data_type: BaseTable, id_value: int, updates: Dict[str, Any]):
    table = data_type.table_name
    id_name = data_type.id_column

    curr_row = db.read_one(f'SELECT * FROM {table} WHERE {id_name}=%s', (id_value,))
    if not curr_row:
        raise exceptions.DataNotFoundError(data_type.table_type, hash_id(id_name, id_value))

    sanitized = data_type.validate_and_translate(updates)
    if not sanitized:
        raise exceptions.InstanceNotModifiedError('update', data_type.table_type)
    db.update_table_entry(table, id_name, id_value, sanitized)


def update_instance_where(data_type: BaseTable, updates: Dict[str, Any], **kwargs):
    table = data_type.table_name
    curr_row = db.read_one(f'SELECT * FROM {table} WHERE ' + ' AND '.join([id_name + '=%s' for id_name in kwargs]), tuple(kwargs.values()))
    if not curr_row:
        raise exceptions.DataNotFoundError(data_type.table_type, ' and ' .join([hash_id(id_name, id_value) for id_name, id_value in kwargs.items()]))

    sanitized = data_type.validate_and_translate(updates)
    if not sanitized:
        raise exceptions.InstanceNotModifiedError('update', data_type.table_type)

    db.update_table_entry_where(table, kwargs, sanitized)


def delete_instance(data_type: BaseTable, instance_id: int):
    table = data_type.table_name
    id_name = data_type.id_column
    return db.delete_row(table, f'{id_name}=%s', (instance_id,))


def delete_instance_where(data_type: BaseTable, **kwargs):
    table = data_type.table_name
    return db.delete_row(table, ' AND '.join([id_name + '=%s' for id_name in kwargs]), tuple(kwargs.values()))


def get_user(user_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM users LEFT JOIN organizations USING (organization_id) WHERE user_id=%s',
                             User, (user_id,), skip_translate=skip_translate, dict_results=dict_results)


def is_re_admin(user_id: int):
    return db.get_single_value('SELECT is_re_admin FROM users WHERE user_id=%s', (user_id,))


def get_organization(organization_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM organizations WHERE organization_id=%s',
                             Organization, (organization_id,), skip_translate=skip_translate, dict_results=dict_results)


def add_organization_user(organization_id: int, user_id: int, admin: bool = False):
    return create_instance(OrganizationUser, {'organization_id': organization_id, 'user_id': user_id, 'admin': admin})


def get_all_users_for_organization(organization_id: int, skip_translate=False, dict_results=False):
    return read_instances('SELECT * FROM organization_users JOIN users USING (user_id) WHERE organization_users.organization_id=%s', OrganizationUser, (organization_id,), skip_translate=skip_translate, dict_results=dict_results)


def get_organization_user(organization_id: int, user_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * from organization_users JOIN users USING (user_id) WHERE organization_users.organization_id=%s AND user_id=%s', OrganizationUser, (organization_id, user_id), skip_translate, dict_results)


def get_users_organizations(user_id: int, skip_translate=False, dict_results=False):
    return read_instances('SELECT organizations.* from organization_users JOIN organizations USING (organization_id) WHERE user_id=%s', Organization, (user_id,), skip_translate, dict_results)


def update_organization_user(organization_id: int, user_id: int, changes: dict):
    return update_instance_where(OrganizationUser, changes, organization_id=organization_id, user_id=user_id)


def remove_user_from_organization(organization_id: int, user_id: int):
    delete_instance_where(ApiKey, organization_id=organization_id, user_id=user_id)
    delete_instance_where(UserInvite, organization_id=organization_id, email=read_single_value('email', User, user_id))
    delete_instance_where(OrganizationUser, organization_id=organization_id, user_id=user_id)
    if get_user(user_id).organization.get_id() == organization_id:
        new_primary_org = read_single_value_where('organization_id', OrganizationUser, user_id=user_id) or 0
        update_user(user_id, {'organization_id': new_primary_org})


def get_organization_invoices(organization_id: int):
    return read_instances('SELECT * FROM invoices WHERE organization_id=%s',
                          Invoice, (organization_id,))


def get_last_billing_date(organization_id: int):
    org_info = db.read_one('SELECT last_billed_at, created_at FROM organizations WHERE organization_id = %s', (organization_id,))
    return org_info['last_billed_at'] or org_info['created_at']


def get_next_billing_date(organization_id: int):
    plan = read_single_value('billing_plan', Organization, organization_id)
    if plan in (BillingPlan.INVOICE.value, BillingPlan.CC.value):
        last_bill_date = get_last_billing_date(organization_id)
        if plan == BillingPlan.CC:
            return last_bill_date + datetime.timedelta(days=environment.get_billing_config('billing_period_days'))
        else:
            next_month_first_day = last_bill_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0, tzinfo=datetime.timezone.utc) + datetime.timedelta(monthrange(last_bill_date.year, last_bill_date.month)[1])
            return next_month_first_day
    return None


class DecimalToJsonNumber(json.JSONEncoder):

    def default(self, o):
        if isinstance(o, decimal.Decimal):
            float_val = round(float(o), 3)
            if float_val.is_integer():
                return int(float_val)
            return float_val
        return super(DecimalToJsonNumber, self).default(o)


def create_invoice(organization_id: int, due_at=datetime.datetime.utcnow()):
    billing_period_start = get_last_billing_date(organization_id)
    billing_period_end = get_next_billing_date(organization_id)
    if not billing_period_end or billing_period_end > datetime.datetime.now(pytz.utc):
        billing_period_end = datetime.datetime.now(pytz.utc)

    billing_account_id = read_single_value('billing_account_id', Organization, organization_id)
    total = 0
    summed_invoice_items = summarize_charges(organization_id, billing_period_start, billing_period_end)
    # initialize credits
    due_at_timestamp = int(due_at.timestamp())
    dev_billing = use_dev_billing(organization_id)
    billing_credits = get_organization_credits(organization_id)
    if billing_credits and billing_credits['expires_at'] and int(billing_credits['expires_at'].timestamp()) < due_at_timestamp:
        billing_credits = None
    try:
        for line_item, item in list(summed_invoice_items.items()):
            price = int(item['price'])
            if price > 0:
                item['line_item_id'] = billing.create_invoice_item(customer_id=billing_account_id,
                                                                   amount=price,
                                                                   description=line_item,
                                                                   period_start=item['start'],
                                                                   period_end=item['end'],
                                                                   dev_env=dev_billing)
                total += price
                if billing_credits and billing_credits.get(line_item):
                    unit_credits = min(billing_credits[line_item], item['units'])
                    refund = -int(price * unit_credits / item['units'])
                    billing_credits[line_item] = billing_credits[line_item] - unit_credits
                    line_item_id = billing.create_invoice_item(customer_id=billing_account_id,
                                                               amount=refund,
                                                               description=line_item + ' Credit',
                                                               period_start=due_at_timestamp,
                                                               period_end=due_at_timestamp,
                                                               dev_env=dev_billing)
                    summed_invoice_items[line_item + ' Credit'] = {'start': due_at_timestamp,
                                                                   'end': due_at_timestamp,
                                                                   'price': refund,
                                                                   'units': -unit_credits,
                                                                   'line_item_id': line_item_id}
                    total += refund
        if len(summed_invoice_items) > 0:
            auto_advance = read_single_value('billing_plan', Organization, organization_id) != BillingPlan.INVOICE.value
            finalize_invoice = total >= 0.01
            invoice = {
                'organization_id': organization_id,
                'due_at': due_at,
                'lifecycle': InvoiceLifecycle.PENDING.value if finalize_invoice else InvoiceLifecycle.PAID.value,
                'invoice_items': json.dumps([{'item': key, **values} for key, values in summed_invoice_items.items()], cls=DecimalToJsonNumber),
                'total': total,
                'billing_period_start': billing_period_start,
                'billing_period_end': billing_period_end}
            if finalize_invoice:
                invoice['stripe_invoice_id'] = billing.finalize_invoice(billing_account_id, auto_advance=auto_advance, dev_env=dev_billing)
            # Don't update until after we've finalized the stripe invoice
            update_organization(organization_id, {'last_billed_at': billing_period_end})
            if billing_credits:
                update_promotion_value(organization_id, billing_credits)
            new_invoice = create_instance(Invoice, invoice)
            from app import alert
            alert.send_billing_alert(organization_id, AlertType.INVOICE_READY, new_invoice)
            return new_invoice
        # nothing to bill for this period
        update_organization(organization_id, {'last_billed_at': billing_period_end})
        return False
    except Exception:
        logging.exception(f'Could not create invoice for organization_id {organization_id}. Unrolling invoice_items')
        for item in summed_invoice_items.values():
            if 'line_item_id' in item:
                billing.delete_invoice_item(item['line_item_id'], dev_env=dev_billing)
        raise


def create_billing_account(organization_id: int, name: str, email: str):
    billing_account_id = billing.create_billing_account(name, email, f'Billing Account for Org "{get_organization(organization_id).name}" ({organization_id})', dev_env=use_dev_billing(organization_id))
    update_organization(organization_id, {'billing_account_id': billing_account_id})
    return billing_account_id


def get_invoice(invoice_id: int):
    return read_one_instance('SELECT * FROM invoices WHERE invoice_id=%s',
                             Invoice, (invoice_id,))


def get_invoice_stripe_id(stripe_invoice_id: str):
    return read_one_instance('SELECT * FROM invoices WHERE stripe_invoice_id=%s',
                             Invoice, (stripe_invoice_id,))


def update_invoice(invoice_id: str, changes: dict):
    update_instance_where(Invoice, changes, invoice_id=invoice_id)


PROJECT_LIMIT = 200  # limit on number of projects to load. Also used to find minimum dataset id to load


def get_all_datasets_for_organization(organization_id: int):
    recent_projects = db.read('SELECT project_id FROM project_owners WHERE organization_id=%s ORDER BY project_id DESC LIMIT %s', (organization_id, PROJECT_LIMIT)) or []
    project_ids = [p['project_id'] for p in recent_projects]
    recent_attached_datasets = []
    if project_ids:
        recent_attached_datasets = db.read(('SELECT dataset_id '
                                            'FROM project_datasets '
                                            f'WHERE project_id in ({", ".join(["%s"] * len(project_ids))})'),
                                           project_ids) or []
    # To discover any un-attached datasets lets also pick a bunch of the recently created ones to toss in
    recent_datasets = db.read('SELECT dataset_id FROM dataset_owners WHERE organization_id=%s ORDER BY dataset_id DESC LIMIT %s', (organization_id, PROJECT_LIMIT * 2)) or []
    dataset_ids = list(set([d['dataset_id'] for d in recent_attached_datasets] + [d['dataset_id'] for d in recent_datasets]))
    query = 'SELECT * FROM dataset_owners JOIN datasets USING (dataset_id) WHERE organization_id=%s'
    vals = [organization_id]
    if dataset_ids:
        query += f' AND dataset_id IN ({", ".join(["%s"]*len(dataset_ids))})'
        vals += dataset_ids
    refresh_map = {}
    if dataset_ids:
        refresh_policies = list_refresh_policies(organization_id, dataset_ids=dataset_ids, policy_types=[RefreshPolicyType.DATASET])
        for refresh_policy in refresh_policies:
            entry = {'refresh_policy_id': refresh_policy.refresh_policy_id, 'cron': refresh_policy.cron, 'next_run_time': date_field(refresh_policy.next_run_time)}
            for dataset_id in refresh_policy.get_value('dataset_ids') or []:
                refresh_map.setdefault(dataset_id, []).append(entry)
    datasets = read_instances(query, Dataset, vals)
    for dataset in datasets:
        dataset_id = dataset.get_id()
        if refresh_map.get(dataset_id):
            dataset.refresh_schedules = refresh_map[dataset_id]
        else:
            dataset.refresh_schedules = {}
    return datasets


def get_projects_for_organization(organization_id: int, skip_translate=False, dict_results=False):
    return read_instances('SELECT * FROM project_owners JOIN projects USING (project_id) ' +
                          'WHERE organization_id=%s ORDER BY project_owners.project_id DESC LIMIT %s',
                          Project, (organization_id, PROJECT_LIMIT), skip_translate=skip_translate, dict_results=dict_results)


def get_projects(project_ids: List[int] = [], skip_translate=False, dict_results=False):
    return read_instances('SELECT * FROM project_owners JOIN projects USING (project_id) ' +
                          'WHERE ' +
                          'project_id IN (%s)' % ','.join(['%s'] * len(project_ids)),
                          Project, project_ids, skip_translate=skip_translate, dict_results=dict_results)


def get_all_project_datasets(project_id: int = None, exclude_detached=True, skip_translate=False, dict_results=False):
    extra_where = ''
    if exclude_detached:
        extra_where = f' AND lifecycle IN ("{ProjectDatasetLifecycle.ACTIVE.value}", "{ProjectDatasetLifecycle.PENDING.value}")'
    return read_instances('SELECT * FROM project_datasets JOIN datasets USING (dataset_id) JOIN projects USING (project_id) WHERE project_id=%s' + extra_where, ProjectDataset, (project_id,),
                          skip_translate=skip_translate, dict_results=dict_results)


def list_solutions_and_use_cases(is_solutions: bool, use_case: str, organization_id: int = None):
    solutions_overrides = {}
    if organization_id:
        solutions_overrides = db.get_single_value('SELECT info->"$.solutions_overrides" FROM organizations WHERE organization_id=%s', (organization_id,)) or {}
    if is_solutions:
        group_use_cases, one_use_case, is_group = get_web_use_case('internal_homepage', show_hidden=False, force_show=solutions_overrides.get('force_show') or [])
        if group_use_cases:
            for use_case in group_use_cases:
                use_case['url'] = use_case['url_name_use_case'][3:]

                group_use_cases2, one_use_case2, is_group2 = get_web_use_case(use_case['url'], False)
                if is_group2 and group_use_cases2:
                    sub_items = [
                        {'name': item['pretty_name_web'] or item['web_name'], 'url': '/' + item['url_name_use_case'].upper(),
                         'problem_type': item.get('problem_type').upper(),
                         'img_src': item.get('img_src'), 'title': item.get('info', {}).get('web_use_case', {}).get('title'),
                         'use_case': item['use_case'].upper()} for item in group_use_cases2]
                    use_case['subitems'] = sub_items
                elif one_use_case2:
                    use_case['title'] = one_use_case2.get('info', {}).get('web_use_case', {}).get('title')

            return [{'url': item['url'].upper(), 'subitems': item.get('subitems'), 'name': item['main_title'], 'description_large': item.get('description_large') or '', 'use_case': item.get('use_case').upper(), 'img_src': item.get('url_name_use_case'), 'problem_type': item.get('problem_type').upper(), 'title': item.get('title')} for item in group_use_cases]
    else:
        if use_case:
            group_use_cases, one_use_case, is_group = get_web_use_case(use_case, False)
            if not is_group and one_use_case:
                return [{'name': one_use_case['pretty_name_web'], 'img_src': one_use_case['img_src']}]
    return None


SOLUTION_MAP = {}


def get_solution(use_case: str):
    global SOLUTION_MAP
    if not SOLUTION_MAP:
        all_solutions = list_solutions_and_use_cases(True, None)
        SOLUTION_MAP = {}
        for solution in all_solutions:
            SOLUTION_MAP[solution['use_case']] = solution
            for sub in solution.get('subitems') or []:
                SOLUTION_MAP[sub['use_case']] = solution
    return SOLUTION_MAP.get(use_case.upper())


METRICS_RANGES = None
WEB_USE_CASES = None
USE_CASES = None
USE_CASES_DOCUMENTATION = None
HOMEPAGE_POINTS = None
EXAMPLE_CODE = None
USE_CASE_VARIABLES = None


def get_example_code_json():
    global EXAMPLE_CODE
    if not EXAMPLE_CODE:
        with open(os.path.join(environment.get_config_dir(), 'apidocs/examples.json')) as fp:
            EXAMPLE_CODE = json.load(fp)
    return EXAMPLE_CODE


def get_all_example_variables():
    global USE_CASE_VARIABLES
    if not USE_CASE_VARIABLES:
        with open(os.path.join(environment.get_config_dir(), 'apidocs/use_case_variables.yml')) as fp:
            USE_CASE_VARIABLES = yaml.safe_load(fp)
    return USE_CASE_VARIABLES


def get_use_case_variables(use_case):
    example_variables = get_all_example_variables()
    variables = example_variables.get('default').copy()
    variables.update(example_variables.get(use_case))
    return {'%' + key.upper(): val for key, val in variables.items()}


def get_all_web_use_cases_yml():
    global WEB_USE_CASES
    if not WEB_USE_CASES:
        with open(os.path.join(environment.get_config_dir(), 'web/web_use_cases.yml'), 'rb') as fp:
            WEB_USE_CASES = yaml.safe_load(fp)
    return WEB_USE_CASES


def get_all_use_cases_yml():
    global USE_CASES
    if not USE_CASES:
        with open(os.path.join(environment.get_config_dir(), 'web/use_cases.yml'), 'rb') as fp:
            USE_CASES = yaml.safe_load(fp)
    return USE_CASES


def get_all_metrics_yml():
    global METRICS_RANGES
    if not METRICS_RANGES:
        with open(os.path.join(environment.get_config_dir(), 'web/metrics.yml'), 'rb') as fp:
            METRICS_RANGES = yaml.safe_load(fp)
    return METRICS_RANGES


def get_use_case_documentation_yml():
    global USE_CASES_DOCUMENTATION
    if not USE_CASES_DOCUMENTATION:
        with open(os.path.join(environment.get_config_dir(), 'web/use_cases_documentation.yml'), 'rb') as fp:
            USE_CASES_DOCUMENTATION = yaml.safe_load(fp)
    return USE_CASES_DOCUMENTATION


def get_homepage_new_yml():
    global HOMEPAGE_POINTS
    if not HOMEPAGE_POINTS:
        with open(os.path.join(environment.get_config_dir(), 'web/homepage_new.yml'), 'rb') as fp:
            HOMEPAGE_POINTS = yaml.safe_load(fp)
    return HOMEPAGE_POINTS


def get_all_use_case_names():
    all_data = get_all_use_cases_yml()
    # Need to filter out default and custom
    return [name.upper() for name, config in all_data.items() if config.get('problem_type')]


def get_all_use_cases() -> List[UseCase]:
    all_data = get_all_use_cases_yml()
    all_use_cases = []
    for use_case, data in all_data.items():
        if not data or not data.get('problem_type'):
            continue
        name = data['info'].get('real_name') if data.get('info') else None
        info = data.get('info')

        use_case_data = get_use_case_yml(use_case) or {}
        web_use_case = use_case_data.get('info', {}).get('web_use_case', {})
        description = '. '.join([web_use_case.get('title', ''), web_use_case.get('title2', '')])
        all_use_cases.append(UseCase(dict(use_case=use_case, pretty_name=name, pretty_name_web=name, img_src=(use_case_data.get('web_ui') or {}).get('img_src'), description=description, prediction_api=use_case_data.get('prediction_api'), info=info)))
    return all_use_cases


def get_use_case_yml(use_case: str, follow_alias=True, no_copy=False):
    if use_case is None:
        return None

    use_case_data = get_all_use_cases_yml()
    data = use_case_data.get(use_case.lower())
    if no_copy:
        res = data
    else:
        res = copy.deepcopy(data)
    if res and follow_alias:
        alias_name = (res.get('info') or {}).get('uiCustom', {}).get('schemas', {}).get('alias')
        if alias_name and res.get('info', {}).get('uiCustom', {}).get('schemas'):
            use_case_alias = get_use_case_yml(alias_name, False)
            alias_data = (use_case_alias or {}).get('info', {}).get('uiCustom', {}).get('schemas')
            res['info']['uiCustom']['schemas'] = alias_data.copy() if alias_data else None

    return res


def get_use_case_prediction_api(use_case: str, host: str):
    pred_fn_names = get_use_case_yml(use_case).get('prediction_api', 'predict')
    from app.api import get_public_api_func, get_func_doc
    return {pred_fn_name: get_func_doc(get_public_api_func(pred_fn_name), host)['inputs'] for pred_fn_name in pred_fn_names}


def get_project_dataset_column_types(use_case: str, project_dataset_type: str = None):
    use_case_schema = get_use_case_schema(use_case)
    data_use_translator = {}
    for dataset_type in use_case_schema['list']:
        if project_dataset_type and project_dataset_type != dataset_type:
            continue
        column_types = {}
        for col in use_case_schema[dataset_type]['schema']:
            if col.get('data_use'):
                col_type_description = {
                    'name': col['name'],
                    'description': col['description'],
                    'multiple': col.get('multiple'),
                    'optional': col.get('optional')
                }
                if col.get('force_data_type'):
                    col_type_description['data_type'] = col['force_data_type']
                if col.get('data_type_options'):
                    col_type_description['data_type_options'] = col['data_type_options']
                column_types[col['data_use']] = col_type_description

        column_types[ValueDataUse.Ignore.value] = {
            'name': ValueDataUse.Ignore.value.upper(),
            'description': 'Ignore this column in training',
            'multiple': True,
            'optional': True
        }
        data_use_translator.update(column_types)
    return data_use_translator


def get_use_case_schema(use_case: str):
    return get_use_case_yml(use_case)['info']['uiCustom']['schemas']


def get_data_use_dataset_types(use_case: str):
    use_case_schema = get_use_case_schema(use_case)
    dataset_descriptions = {}
    for dataset_type in use_case_schema['list']:
        dataset_desc = use_case_schema[dataset_type]
        dataset_descriptions[dataset_type] = {
            'name': dataset_desc.get('title'),
            'description': dataset_desc.get('description'),
            'required': dataset_desc.get('is_required')
        }
    return dataset_descriptions


def get_problem_type_from_use_case(use_case: str):
    use_case_data = get_use_case_yml(use_case) or {}
    return use_case_data.get('problem_type')


def get_example_dataset_infos(project_id: int):
    use_case = db.get_single_value('SELECT use_case FROM projects WHERE project_id = %s', (project_id,))
    if not use_case:
        return []
    use_case_data = get_use_case_yml(use_case) or {}
    return use_case_data.get('example_datasets', [])


def get_training_config_options(project_id: int):
    dataset_instance_infos = get_dataset_instance_infos_for_project(project_id)
    problem_type = db.get_single_value('SELECT problem_type FROM projects WHERE project_id = %s', (project_id,))
    return get_problem_type(problem_type).get_training_config_options(dataset_instance_infos)


def validate_training_config_values(project_id: int, training_config: dict):
    dataset_instance_infos = get_dataset_instance_infos_for_project(project_id)
    problem_type = db.get_single_value('SELECT problem_type FROM projects WHERE project_id = %s', (project_id,))
    return get_problem_type(problem_type).validate_training_config_values(dataset_instance_infos, training_config)


def add_project(values: Dict[str, Any], organization_id: int):
    try:
        if 'use_case' in values:
            values['use_case'] = values['use_case'].lower()
        instance = create_instance(Project, values)
        create_instance(ProjectOwner, {'organization_id': organization_id, 'project_id': instance.get_id()})
        return instance
    except db.DuplicateEntryError:
        raise exceptions.AlreadyExistsError('Project name', values['name'])
    except MySQLdb._exceptions.Error as e:
        logging.exception('Error creating project row', e)
        if environment.in_devpod():
            raise exceptions.BaseError(e.args[1])
        raise exceptions.BaseError('Internal error creating project')


def get_project(project_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM projects WHERE project_id=%s',
                             Project, (project_id,), skip_translate=skip_translate, dict_results=dict_results)


def get_project_resource_ids(project_id: int):
    ''' Lightweight function to get a bunch of ids related to a project
    '''
    # Filter out datasets that are for streaming
    datasets = db.read('SELECT dataset_id FROM project_datasets JOIN datasets USING (dataset_id) WHERE project_id=%s AND project_datasets.lifecycle = %s', (project_id, ProjectDatasetLifecycle.ACTIVE.value)) or []
    # Filter out models that are not the deployable ones
    models = db.read('SELECT model_id FROM models WHERE project_id=%s AND primary_model_id IS NULL', (project_id,)) or []
    deployments = db.read('SELECT deployment_id FROM deployments WHERE project_id=%s', (project_id,)) or []
    return {
        'dataset_ids': [dataset['dataset_id'] for dataset in datasets],
        'model_ids': [model['model_id'] for model in models],
        'deployment_ids': [deployment['deployment_id'] for deployment in deployments]
    }


def edit_project(project_id: int, changes: dict):
    update_instance(Project, project_id, changes)


def get_project_wizard_state(project_id: int):
    return (read_single_value_where('info', Project, project_id=project_id) or {}).get('wizard_state') or {}


def set_project_wizard_state(project_id: int, values: dict):
    info = read_single_value_where('info', Project, project_id=project_id) or {}
    info['wizard_state'] = values
    db.update_table_entry('projects', 'project_id', project_id, {'info': json.dumps(info)})


def delete_organization(organization_id: int, force: bool = False):
    if not force and not use_dev_billing(organization_id) and not environment.get_test_run_id() and read_single_value('billing_account_id', Organization, organization_id):
        create_invoice(organization_id)  # roll up latest charges, if they exceed credits in account, bill first.
        if next(iter(invoice for invoice in get_organization_invoices(organization_id) if invoice.lifecycle not in {InvoiceLifecycle.PAID, InvoiceLifecycle.CANCELLED}), None):
            raise exceptions.ConflictError('Organization has unpaid invoices and cannot be cancelled')

    for project in get_projects_for_organization(organization_id):
        delete_project(organization_id, project.get_id())

    for dataset in (list_datasets_by_organization(organization_id) or []):
        delete_dataset(dataset.get_id())

    delete_instance_where(UserInvite, organization_id=organization_id)
    for organization_user in get_all_users_for_organization(organization_id):
        remove_user_from_organization(organization_id, organization_user.user.get_id())
        if read_single_value_where('organization_id', User, user_id=organization_user.user.get_id()) == 0:
            delete_instance(User, organization_user.user.get_id())
            db.delete_row('social_logins', 'user_id=%s', (organization_user.user.get_id(),))
    delete_instance(Organization, organization_id)


def delete_project(organization_id: int, project_id: int):
    deployments = list_deployments(project_id=project_id)
    models = list_models(project_id=project_id)
    deployment_ids = [deployment.get_id() for deployment in deployments]
    model_ids = [model.get_id() for model in models]

    refresh_policies = list_refresh_policies(organization_id, model_ids=model_ids, deployment_ids=deployment_ids)
    for policy in refresh_policies:
        # TODO: Still need to delete pipeline runs from things like project refresh...
        db.delete_row('refresh_pipeline_runs', 'refresh_policy_id=%s', (policy.get_id(),))
        delete_refresh_policy(policy.get_id())

    for deployment_id in deployment_ids:
        batch_predictions = list_batch_predictions(deployment_id)
        for batch_prediction in batch_predictions:
            delete_batch_prediction(batch_prediction.get_id())
        delete_deployment(deployment_id)

    auth_tokens = list_deployment_auth_tokens(project_id)
    for auth_token in auth_tokens:
        delete_deployment_auth_token(auth_token.auth_token)

    for model_id in model_ids:
        delete_model(model_id)

    dataset_instance_groups = db.read('SELECT dataset_instance_group_id FROM dataset_instance_groups WHERE project_id=%s', (project_id,)) or []
    for dataset_instance_group in dataset_instance_groups:
        delete_instance(DatasetInstanceGroup, dataset_instance_group['dataset_instance_group_id'])

    baseline_models = list_baseline_models(project_id=project_id)
    for model in baseline_models:
        delete_model(model.get_id())

    project_datasets = get_all_project_datasets(project_id, skip_translate=True, dict_results=True)
    for project_dataset in project_datasets:
        delete_project_dataset(project_id, project_dataset['dataset']['dataset_id'])

    delete_instance_where(ProjectOwner, project_id=project_id)
    return delete_instance(Project, project_id)


def get_data_usage_configs(project_id: int):
    configs = db.read('SELECT dataset_id, data_usage_config FROM project_datasets LEFT JOIN datasets USING (dataset_id) WHERE project_id=%s AND lifecycle=%s', (project_id, ProjectDatasetLifecycle.ACTIVE.value,))
    return {config['dataset_id']: apply_schema_overrides((config['data_usage_config'].get('schema') or config['data_usage_config'].get('fields')), config['data_usage_config'].get('user_overrides')) for config in configs}


def add_dataset(organization_id: int, values: Dict[str, Any], project_target_info: dict = None):
    values_dataset_fields = ['name', 'data_source', 'source_type', 'file_format']
    values_dataset = {}
    for field_dataset in values_dataset_fields:
        if values.get(field_dataset) is not None:
            values_dataset[field_dataset] = values.get(field_dataset)

    file_format = values_dataset.get('file_format')
    external_location = values_dataset.get('data_source', {}).get('location')
    if not file_format and external_location:
        file_format = FileFormat.from_file_path(external_location)
        if file_format:
            values_dataset['file_format'] = file_format

    try:
        new_row = create_instance(Dataset, values_dataset)
    except db.DuplicateEntryError:
        raise exceptions.AlreadyExistsError("Dataset Name", values_dataset['name'])
    except MySQLdb._exceptions.Error as e:
        logging.exception('Error creating dataset row: %s', e.args[1])
        if environment.in_devpod():
            raise exceptions.BaseError(e.args[1])
        raise exceptions.BaseError('Internal error creating dataset')

    dataset_id = new_row.get_id()

    create_instance(DatasetOwner, {'organization_id': organization_id, 'dataset_id': dataset_id})
    values_dataset_instance_fields = ['tag', 'schema_values', 'lifecycle']

    location_type = values_dataset.get('data_source', {}).get('location_type', '')
    values_dataset_instance = {
        'dataset_id': dataset_id,
        'location': external_location,
    }
    if file_format:
        values_dataset_instance['file_format'] = file_format

    for field_dataset in values_dataset_instance_fields:
        if values.get(field_dataset) is not None:
            values_dataset_instance[field_dataset] = values.get(field_dataset)

    if location_type == LocationType.RE:
        dataset_instance = add_dataset_instance(values_dataset_instance, organization_id, create_upload=True, project_target_info=project_target_info)
        dataset_instance_id = dataset_instance.get_id()
        update = {'location': get_uploaded_location(organization_id, dataset_id, dataset_instance_id, create=True)}
        update_dataset_instance(dataset_instance_id, update)
    elif values['source_type'] == SourceType.STREAMING:
        dataset_instance = add_dataset_instance(values_dataset_instance, organization_id, project_target_info=project_target_info)
    else:
        dataset_instance = start_dataset_instance_read(dataset_id, organization_id, project_target_info, file_format=file_format)
    return {'dataset': new_row, 'dataset_instance': dataset_instance}


def update_dataset(dataset_id: int, values: dict):
    return update_instance(Dataset, dataset_id, values)


def get_uploaded_location(organization_id: int, dataset_id: int, dataset_instance_id: int, create: bool = False) -> str:
    return os.path.join(cloudartifacts.get_dataset_upload_directory(organization_id, dataset_id, dataset_instance_id, create=create), 'data')


def start_dataset_instance_read(dataset_id: int, organization_id: int, project_target_info: dict = None, location: str = None, file_format: str = None):
    requires_import = dataset_requires_import(dataset_id)
    dataset_instance_info = {'lifecycle': DatasetLifecycle.IMPORTING if requires_import else DatasetLifecycle.INSPECTING,
                             'location': location or '',
                             'dataset_id': dataset_id,
                             'file_format': file_format}
    dataset = get_dataset(dataset_id)
    if location:
        dataset.data_source['location'] = location
        edit_dataset(dataset_id, {'data_source': dataset.data_source})
    elif not requires_import:
        dataset_instance_info['location'] = dataset.data_source['location']
        dataset_instance_info['metrics_lifecycle'] = DatasetMetricsLifecycle.PENDING.value

    dataset_instance = add_dataset_instance(dataset_instance_info,
                                            organization_id=organization_id,
                                            project_target_info=project_target_info)
    dataset_instance_id = dataset_instance.get_id()
    if requires_import:
        internal_location = f"{cloudartifacts.get_dataset_import_directory(organization_id, dataset_id, dataset_instance_id, create=True)}/data"
        update_dataset_instance(dataset_instance_id, {'location': internal_location})
    start_dataset_instance_pipeline(dataset_instance_id)
    return dataset_instance


def update_dataset_instance(dataset_instance_id: int, values: Dict[str, Any]):
    update_instance(DatasetInstance, dataset_instance_id, values)


def add_dataset_instance(values: Dict[str, Any], organization_id: int, create_upload: bool = False, project_target_info: dict = None):
    dataset_id = values.get('dataset_id')
    if dataset_id is None:
        raise exceptions.InvalidParameterError('dataset_id', dataset_id)

    values['schema_values'] = read_single_value('schema_values', Dataset, dataset_id)
    try:
        dataset_instance = create_instance(DatasetInstance, values)
        if create_upload:
            add_dataset_upload(organization_id, dataset_instance.get_id(), dataset_id)
        if project_target_info:
            add_project_dataset(project_target_info['project_id'], dataset_id, project_target_info['project_dataset_type'], pending_column_mapping=project_target_info.get('column_mappings'))
    except MySQLdb._exceptions.Error as e:
        logging.exception('Error creating dataset created_at row: %s', e.args[1])
        if environment.in_devpod():
            raise exceptions.BaseError(e.args[1])
        raise exceptions.BaseError('Internal error creating dataset created_at')

    return dataset_instance


def start_dataset_instance_pipeline(dataset_instance_id):
    # Now kick off the import/inspect pipeline setup
    from pipeline import dataset_pipeline
    dp = dataset_pipeline.DatasetPipeline(dataset_instance_id)
    dp.initialize_workflow_db_state()


def add_serving_dataset_instance_group(project_id: int, dataset_instance_ids: List[int]):
    dataset_instance_group_id = db.get_single_value('SELECT dataset_instance_group_id FROM dataset_instance_groups WHERE project_id=%s AND lifecycle=%s ORDER BY dataset_instance_group_id DESC', (project_id, DatasetGroupLifecycle.COMPLETE.value))
    if not dataset_instance_group_id:
        raise exceptions.DataNotFoundError('DatasetInstanceGroups', f'Project: {project_id}')
    row = {'project_id': project_id,
           'dataset_instance_ids': json.dumps(dataset_instance_ids),
           'dataset_instance_group_id': dataset_instance_group_id}
    serving_dataset_instance_group_id = db.add_row('serving_dataset_instance_groups', None, None, row)
    ServingdataGenerate(cron=False).initialize_task_db_state(serving_dataset_instance_group_id)
    return serving_dataset_instance_group_id


def add_dataset_instance_group(project_id: int, dataset_instances: List[int], training_config: dict):
    return create_instance(DatasetInstanceGroup, {
                           'dataset_instance_ids': json.dumps(dataset_instances),
                           'project_id': project_id,
                           'training_config': json.dumps(training_config)
                           })


def get_dataset(dataset_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM datasets WHERE dataset_id=%s', Dataset, (dataset_id,),
                             skip_translate=skip_translate, dict_results=dict_results)


def get_dataset_instances(dataset_id: int, skip_translate=False, dict_results=False):
    datasets_instances = read_instances('SELECT * FROM dataset_instances JOIN datasets USING (dataset_id) WHERE dataset_id=%s ORDER BY dataset_instance_id DESC', DatasetInstance, (dataset_id,), skip_translate=skip_translate, dict_results=dict_results)
    return datasets_instances


def get_dataset_instance(dataset_instance_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM dataset_instances WHERE dataset_instance_id=%s', DatasetInstance, (dataset_instance_id,),
                             skip_translate=skip_translate, dict_results=dict_results)


def get_latest_dataset_instance(dataset_id: int, skip_translate=False, dict_results=False):
    instances = get_dataset_instances(dataset_id=dataset_id, skip_translate=skip_translate, dict_results=dict_results)
    if instances:
        return instances[0]
    return None


def list_datasets_by_organization(organization_id: int, skip_translate=False, dict_results=False):
    args = [organization_id]
    query = 'SELECT * FROM dataset_owners JOIN datasets USING (dataset_id) WHERE organization_id=%s'
    datasets = read_instances(query, Dataset, args,
                              skip_translate=skip_translate, dict_results=dict_results)
    return datasets if datasets else None


def list_datasets(dataset_ids: List[int] = [], skip_translate=False, dict_results=False):
    args = dataset_ids
    query = 'SELECT * FROM datasets WHERE '
    query += ' dataset_id IN (%s)' % ', '.join(['%s'] * len(dataset_ids))
    datasets = read_instances(query, Dataset, args,
                              skip_translate=skip_translate, dict_results=dict_results)
    return datasets if datasets else None


def edit_dataset(dataset_id: int, changes: dict):
    return update_instance(Dataset, dataset_id, changes)


def delete_dataset(dataset_id: int):
    num_project_datasets = db.get_single_value('SELECT count(1) FROM projects JOIN project_datasets USING (project_id) WHERE dataset_id=%s AND lifecycle NOT IN (%s, %s)', (dataset_id, ProjectDatasetLifecycle.FAILED.value, ProjectDatasetLifecycle.DETACHED.value)) or 0
    if num_project_datasets > 0:
        raise exceptions.ConflictError(f'Dataset is currently associated with {num_project_datasets} projects. Please remove from projects before deleting.')
    delete_instance_where(DatasetInstance, dataset_id=dataset_id)
    delete_instance(Dataset, dataset_id)
    delete_instance_where(DatasetUpload, dataset_id=dataset_id)
    delete_instance_where(DatasetOwner, dataset_id=dataset_id)


def call_dataset_server(path: str, **request_kwargs):
    datasetserver_url = environment.get_datasetserver_url()
    response = requests.post(f'{datasetserver_url}/{path}', data=request_kwargs)

    if response.status_code == 404:
        raise exceptions.Generic404Error(response.json()['error'])
    if response.status_code != requests.codes.ok:
        logging.warn('Call to datasetserver returned a %s: %s', response.status_code, response.text)
        if response.status_code < 500:
            try:
                raise exceptions.BaseError(response.json()['error'], http_status=response.json()['status'])
            except json.decoder.JSONDecodeError:
                raise exceptions.BaseError('Encountered error loading dataset information')
        else:
            raise exceptions.BaseError('Encountered error loading dataset information')
    return response


def get_raw_data_rows_to_load(dataset_instance_info: DatasetInstanceInfo, num_columns: int = 0):
    if dataset_instance_info:
        num_columns = len(dataset_instance_info.columns)
    if num_columns:
        return int(2000000 / num_columns)
    else:
        return 0


def get_dataset_data(project_id: int, dataset_id: int, from_row: int, to_row: int, from_col: int, to_col: int) -> (Dict, str):
    """
    Primarily written to work the the react virtualization component which handles viewports into large
    tables.

    :param dataset_id: numeric id of the dataset to load
    :param from_row: starting row index to return
    :param to_row: ending row index to return
    :return: tuple of a response dictionary and a str for any error messaging
    """

    params = {
        'from_row': from_row,
        'to_row': to_row,
        'from_col': from_col,
        'to_col': to_col
    }

    dataset_instance_id = db.get_single_value('SELECT MAX(dataset_instance_id) FROM dataset_instances WHERE dataset_id=%s', (dataset_id,))
    if not dataset_instance_id:
        raise exceptions.DataNotFoundError('Dataset', hash_id('dataset_id', dataset_id))
    instance_infos = _get_dataset_instance_infos(project_id, [dataset_instance_id])
    dataset_instance_info = instance_infos[0]

    params['dataset_instance_info'] = dataset_instance_info.to_json()
    params['rows_to_load'] = get_raw_data_rows_to_load(dataset_instance_info)

    response = call_dataset_server('v1/rawData', **params)
    return response.json()


def get_project_dataset_data_usage(project_id: int, dataset_id: int):
    data_usage_config = read_single_value_where('data_usage_config', ProjectDataset, project_id=project_id, dataset_id=dataset_id)
    if data_usage_config and 'schema' not in data_usage_config:  # @TODO (austin) remove when projet datasets fully migrated to new schema
        data_usage_config['schema'] = data_usage_config.get('fields')
    return data_usage_config


def set_project_dataset_data_usage(project_id: int, dataset_id: int, data_usage_config: dict):
    return update_instance_where(ProjectDataset, {'data_usage_config': data_usage_config}, project_id=project_id, dataset_id=dataset_id)


def get_project_dataset_ui_state(project_id: int, dataset_id: int):
    return read_single_value_where('ui_wizard_state', ProjectDataset, project_id=project_id, dataset_id=dataset_id) or {}


def set_project_dataset_ui_state(project_id: int, dataset_id: int, state: dict):
    db.update_table_entry_where('project_datasets', {'project_id': project_id, 'dataset_id': dataset_id}, {'ui_wizard_state': state})


def get_required_data_use_columns(project_id: int, dataset_id: int):
    project = get_project(project_id)
    dataset_type = ProjectDatasetType(get_project_dataset(project_id, dataset_id).project_dataset_type)
    return [data_use for data_use, data_use_desc in get_project_dataset_column_types(project.use_case, dataset_type.value).items()
            if not data_use_desc['optional']]


def set_project_dataset_schema_overrides(project_id: int, dataset_id: int, column_overrides):
    project_dataset = db.read_one('SELECT * from project_datasets WHERE project_id = %s and dataset_id = %s', (project_id, dataset_id))
    if not project_dataset:
        raise exceptions.DataNotFoundError('ProjectDataset', f'Project {hash_id(project_id=project_id)} Dataset {hash_id(dataset_id=dataset_id)}')
    elif not project_dataset.get('data_usage_config'):
        instance_lifecycle = get_latest_dataset_instance(dataset_id).lifecycle
        if instance_lifecycle in (DatasetLifecycle.FAILED, DatasetLifecycle.IMPORTING_FAILED, DatasetLifecycle.INSPECTING_FAILED):
            raise exceptions.ConflictError('Dataset failed to import, please upload a valid dataset')
        raise exceptions.NotReadyError('Dataset', 30 if instance_lifecycle == DatasetLifecycle.INSPECTING else 60)
    data_usage_config = project_dataset.get('data_usage_config')

    detected_schema = {}
    single_use_cols = {}
    schema = data_usage_config.get('schema') or data_usage_config['detected_fields']
    required_data_uses = get_required_data_use_columns(project_id, dataset_id)  # These can only be used once

    for col in schema:
        detected_schema[col['name']] = {'data_use': col.get('data_use'), 'data_type': col['data_type']}
        if col.get('data_use') in required_data_uses:
            single_use_cols[col.get('data_use')] = {'detected': col['name']}

    overrides = {}
    for column_name, column_schema in column_overrides.items():
        if column_name not in detected_schema:
            raise exceptions.InvalidParameterError('column', column_name, 'Must be one of (\'' + '\', \''.join(col for col in detected_schema) + '\')')
        if type(column_schema) != dict:
            raise exceptions.InvalidParameterError('columnOverrides column', column_name, 'Each column must be a JSON collection')
        if column_schema.get('data_type') and not ValueDataType.has_value(column_schema['data_type']):
            raise exceptions.InvalidEnumParameterError('Column dataType', [data_use.value.upper() for data_use in ValueDataType], column_schema['data_type'])
        if column_schema.get('data_use') and not ValueDataUse.has_value(column_schema['data_use']):
            raise exceptions.InvalidEnumParameterError('Column mapping', [data_use.value.upper() for data_use in ValueDataUse], column_schema['data_use'])
        column_override = {}

        # Force data_types for specific data uses
        resolved_data_use = column_schema.get('data_use', detected_schema[column_name].get('data_use'))

        if resolved_data_use == ValueDataUse.Timestamp:
            column_schema['data_type'] = ValueDataType.Timestamp.value
        if resolved_data_use in (ValueDataUse.ItemKey.value, ValueDataUse.UserKey.value):
            column_schema['data_type'] = ValueDataType.Categorical.value
        if 'data_use' in column_schema and column_schema['data_use'] != detected_schema[column_name].get('data_use'):
            if type(column_schema['data_use']) == str and len(column_schema['data_use']) == 0:
                column_schema['data_use'] = None
            column_override['data_use'] = column_schema['data_use']
        if column_schema.get('data_use') in required_data_uses:
            if single_use_cols.get(column_schema['data_use'], {}).get('override'):
                raise exceptions.ConflictError(f"Data Use '{column_schema['data_use']}' can only be used once", extra_data={'data_use': column_schema['data_use']})
            single_use_cols.setdefault(column_schema['data_use'], {})['override'] = column_name
        if column_schema.get('data_type') and column_schema['data_type'] != detected_schema[column_name]['data_type']:
            column_override['data_type'] = column_schema['data_type']
        if column_override:
            overrides[column_name] = column_override

    # If the user overrode a data use that can only be used once, make sure the detected column is overridden
    for col in single_use_cols.values():
        if col.get('detected') and col.get('override') and col.get('detected') != col.get('override') and overrides.get(col.get('detected'), {}).get('data_use') is None:
            overrides.setdefault(col['detected'], {})['data_use'] = None

    data_usage_config['user_overrides'] = overrides
    set_project_dataset_data_usage(project_id=project_id, dataset_id=dataset_id, data_usage_config=data_usage_config)
    return overrides


def get_dataset_default_schema(dataset_id: int):
    return read_single_value('schema_values', Dataset, dataset_id)


def merge_columns(discovered_columns: List[Dict[str, Any]], updated_columns: List[Dict[str, Any]] = []) -> List[Dict[str, Any]]:
    """ Merge values received via api with current schema
    Params:
    :param discovered_columns: Current schema (auto-detected)
    :param updated_columns   : Schema provided by the API
    """
    updated_columns_dict = {col['name']: col for col in updated_columns}
    merged_columns = []
    for column in discovered_columns:
        updates = updated_columns_dict.get(column['name'])
        if updates:
            if updates.get('data_type'):
                column['data_type'] = ValueDataType(updates['data_type']).value
            if updates.get('data_use'):
                column['data_use'] = ValueDataUse(updates['data_use']).value
            else:
                if column.get('data_use'):
                    del column['data_use']

        # Pass through all remaining columns from the orig_columns_dict
        merged_columns.append(column)
    return merged_columns


def set_dataset_default_schema(dataset_id: int, schema: List[Dict[str, Any]]):
    dataset_last_instance = get_latest_dataset_instance(dataset_id)
    if dataset_last_instance:
        schema_values = dataset_last_instance.schema_values
        schema_values['columns'] = merge_columns(schema_values['columns'], schema)
        db.update_table_entry('dataset_instances', 'dataset_instance_id', dataset_last_instance.get_id(),
                              {'schema_values': schema_values})


def get_raw_data_graphs(dataset_id: int, project_id: int, num_items: int, dataset: Dict = None, date: bool = False) -> List:
    dataset_last_instance = get_latest_dataset_instance(dataset_id)
    if not dataset_last_instance:
        raise exceptions.DataNotFoundError('Dataset', hash_id('dataset_id', dataset_id))

    dataset_instance_info = _get_dataset_instance_infos(project_id, [dataset_last_instance.get_id()])[0]
    if not dataset_instance_info.columns:
        raise exceptions.DataNotFoundError('Project', hash_id('project_id', project_id))

    params = {'dataset_instance_info': dataset_instance_info.to_json(),
              'num_items': num_items,
              'rows_to_load': get_raw_data_rows_to_load(dataset_instance_info)}
    response = call_dataset_server('v1/rawGraphs', **params)
    return response.json()['charts']


def _get_dataset_stats_location(organization_id: int, dataset_id: int, dataset_instance_id: int, create=False):
    return os.path.join(cloudartifacts.get_dataset_stats_directory(organization_id, dataset_id, dataset_instance_id, create=create), 'stats.json')


def _load_metrics_data(project_id: int, dataset_id: int):
    dataset = db.read_one(
        'SELECT dataset_instance_id, dataset_instances.lifecycle, metrics_lifecycle, data_usage_config, organization_id FROM dataset_instances JOIN project_datasets USING (dataset_id) JOIN dataset_owners USING (dataset_id) WHERE dataset_id=%s ORDER BY dataset_instances.dataset_instance_id DESC LIMIT 1', (dataset_id,))

    if not dataset:
        raise exceptions.DataNotFoundError('Dataset', hash_id('dataset_id', dataset_id))
    if dataset['lifecycle'] != DatasetLifecycle.COMPLETE.value:
        raise exceptions.DataNotFoundError('Stats', hash_id('dataset_id', dataset_id), 'Dataset ID')
    if dataset['metrics_lifecycle'] == DatasetMetricsLifecycle.PENDING:
        raise exceptions.NotReadyError('Datset Metrics', 100)
    if dataset['metrics_lifecycle'] == DatasetMetricsLifecycle.FAILED:
        raise exceptions.DataNotFoundError('Dataset', hash_id('dataset_id', dataset_id))
    if dataset['metrics_lifecycle'] != DatasetMetricsLifecycle.COMPLETE.value:
        raise exceptions.DataNotFoundError('Stats', hash_id('dataset_id', dataset_id), 'Dataset ID')

    data_usage_config = (dataset['data_usage_config'] or {})
    schema = data_usage_config.get('schema')
    params = {
        'metrics_path': _get_dataset_stats_location(dataset['organization_id'], dataset_id, dataset['dataset_instance_id']),
        'schema': json.dumps(apply_schema_overrides(schema, data_usage_config.get('user_overrides')))
    }
    return call_dataset_server('datasetMetrics', **params).json()


def get_dataset_metrics(project_id: int, dataset_id: int, from_row: int, to_row: int, from_col: int, to_col: int) -> dict:
    data = _load_metrics_data(project_id, dataset_id)
    table = [row[from_col:to_col + 1] for row in data['table'][from_row:to_row + 1]]
    return {'data': table, 'dataset_id': hash_id('dataset_id', dataset_id)}


def get_dataset_metrics_schema(project_id: int, dataset_id: int) -> dict:
    data = _load_metrics_data(project_id, dataset_id)
    return {'fields': data['columns'], 'row_count': len(data['table'])}


def get_shared_model_dataset_metrics(project_id: int, dataset_id: int, rows: int, cols: int = 5) -> dict:
    data = _load_metrics_data(project_id, dataset_id)
    table = [row[:cols] for row in data['table'][:rows]]
    columns = data['columns'][:cols]
    return {'table': table, 'columns': columns, 'row_count': len(data['table'])}


def add_project_dataset(project_id: int, dataset_id: int, project_dataset_type: ProjectDatasetType, pending_column_mapping=None, skip_inspect=False):
    existing_project_dataset = db.read_one('SELECT * FROM project_datasets WHERE project_id = %s AND (dataset_id = %s OR project_dataset_type = %s AND lifecycle = %s)', (project_id, dataset_id, project_dataset_type.value, ProjectDatasetLifecycle.ACTIVE.value))
    if existing_project_dataset:
        if existing_project_dataset['lifecycle'] == ProjectDatasetLifecycle.DETACHED:
            delete_project_dataset(project_id, dataset_id)
        elif existing_project_dataset['dataset_id'] == dataset_id:
            raise exceptions.ConflictError("Dataset '%s' already attached to the project '%s'" % (hash_id('dataset_id', dataset_id), hash_id('project_id', project_id)))

    values = {'project_id': project_id,
              'dataset_id': dataset_id,
              'lifecycle': ProjectDatasetLifecycle.ACTIVE.value,
              'project_dataset_type': project_dataset_type.value
              }
    if pending_column_mapping:
        values['data_usage_config'] = {'schema' if skip_inspect else 'pending_column_mapping': pending_column_mapping}
    create_instance(ProjectDataset, values)
    refresh_project_dataset(project_id, dataset_id)


def refresh_project_dataset(project_id: int, dataset_id: int, dataset_columns: dict = None):
    project = get_project(project_id)
    project_dataset = db.read_one('SELECT project_dataset_type, data_usage_config FROM project_datasets WHERE project_id=%s AND dataset_id=%s ', (project_id, dataset_id))
    problem_type = ProblemType(project.problem_type)
    dataset_columns = dataset_columns or (read_single_value_where('schema_values', Dataset, dataset_id=dataset_id) or {}).get('columns')
    if dataset_columns:
        data_usage_config = project_dataset['data_usage_config'] or {}
        new_columns = {col['name'] for col in dataset_columns}

        column_mappings = data_usage_config.get('pending_column_mapping') or {}
        column_mappings.update({value: {'data_use': ValueDataUse(key)} for key, value in get_project_wizard_state(project_id).items() if ValueDataUse.has_value(key)})
        column_mappings = {col_name: val for col_name, val in column_mappings.items() if col_name in new_columns}
        if data_usage_config.get('user_overrides'):
            data_usage_config['user_overrides'] = {col_name: val for col_name, val in data_usage_config['user_overrides'].items() if col_name in new_columns}

        columns = discover_data_use(problem_type, ProjectDatasetType(project_dataset['project_dataset_type']), dataset_columns, column_mappings)

        if columns:
            data_usage_config['schema'] = columns
            update_instance_where(ProjectDataset, {'data_usage_config': data_usage_config}, project_id=project_id, dataset_id=dataset_id)
            validate_project_datasets(project_id)


def get_project_dataset(project_id: int, dataset_id: int):
    return read_one_instance('SELECT * FROM project_datasets WHERE project_id = %s AND dataset_id = %s', ProjectDataset, (project_id, dataset_id))


def detach_project_dataset(project_id: int, dataset_id: int):
    project_dataset_type = read_single_value_where('project_dataset_type', ProjectDataset, project_id=project_id, dataset_id=dataset_id)
    return delete_instance_where(ProjectDataset, project_id=project_id, project_dataset_type=project_dataset_type)


def delete_project_dataset(project_id: int, dataset_id: int):
    if not read_single_value_where('1', ProjectDataset, project_id=project_id, dataset_id=dataset_id):
        return False

    return delete_instance_where(ProjectDataset, project_id=project_id, dataset_id=dataset_id)


def add_deployment(values: Dict[str, Any]):
    if not values or 'project_id' not in values:
        raise exceptions.MissingParameterError('project_id')
    if not values['name']:
        values['name'] = get_default_name('deployment', values['model_id'])

    # Set some defaults for deployment_config. Uses camelcase due to legacy
    deployment_config = values.get('deployment_config') or {}
    # TODO: Remove setting callsPerSecond in instance deployment_config after launch
    deployment_config.setdefault('callsPerSecond', 5)
    values['deployment_config'] = deployment_config

    # Populate with sane defaults
    org_info = db.read_one('SELECT IFNULL(projects.cluster_name, organizations.cluster_name) AS cluster_name, IFNULL(projects.ingress_type, organizations.ingress_type) AS ingress_type, IFNULL(projects.ingress_name, organizations.ingress_name) AS ingress_name FROM projects JOIN project_owners USING (project_id) JOIN organizations USING (organization_id) WHERE project_id=%s', (values['project_id'],)) or {}
    values['cluster_name'] = org_info.get('cluster_name') or environment.get_cluster_name()
    values['num_replicas'] = 1  # Hardcode for now...
    values['calls_per_second'] = deployment_config['callsPerSecond']
    values['ingress_type'] = org_info['ingress_type']
    values['ingress_name'] = org_info['ingress_name']

    values_deploy_fields = ['project_id', 'model_id', 'name', 'description',
                            'deployment_config', 'cluster_name', 'num_replicas',
                            'calls_per_second', 'ingress_type', 'ingress_name']
    values_deploy = {}
    for field_deploy in values_deploy_fields:
        if values.get(field_deploy) is not None:
            values_deploy[field_deploy] = values.get(field_deploy)

    deployment = create_instance(Deployment, values_deploy)

    deployment_id = deployment.get_id()
    # Upon successful deployment, the deployment instance will be associated with the deployment
    deployment_instance = add_deployment_instance(deployment_id, values)
    deployment.deployment_instance.deployment_instance_id = deployment_instance.deployment_instance_id
    # Also since this is a new deployment, associate the new deployment_instance with the deployment
    db.update_table_entry('deployments', 'deployment_id', deployment_id, {'deployment_instance_id': get_base_table_attr(deployment_instance, 'deployment_instance_id')})
    return {'deployment': deployment, 'deployment_instance': deployment_instance}


def add_deployment_instance(deployment_id: int, values: Dict[str, Any], auto: bool = False):
    query = ('SELECT problem_type, IFNULL(deployments.cluster_name, IFNULL(projects.cluster_name, organizations.cluster_name)) AS cluster_name, deployment_instance_id, '
             'deployment_config, num_replicas, calls_per_second, billing_plan '
             'FROM projects '
             'JOIN deployments USING (project_id) JOIN project_owners USING (project_id) JOIN organizations USING (organization_id) '
             'WHERE deployment_id = %s')
    deployment_info = db.read_one(query, (deployment_id,))
    cluster_name = deployment_info['cluster_name'] or environment.get_cluster_name()

    # TODO(matt): Remove use of deployment_config
    deployment_config = deployment_info['deployment_config'] or {}
    if values.get('deployment_config'):
        deployment_config.update(values['deployment_config'])
    if deployment_info['calls_per_second']:
        deployment_config.setdefault('callsPerSecond', deployment_info['calls_per_second'])
    values['deployment_config'] = deployment_config

    problem_type = get_problem_type(deployment_info['problem_type'])
    disable_tf_serving = problem_type.disable_tf_serving()
    use_datatransform_server = problem_type.use_datatransform_server()

    container_info = kube.get_container_info()
    values_deploy_instance = {
        'deployment_id': deployment_id,
        'deployed_at': datetime.datetime.utcnow(),
        'lifecycle': DeploymentLifecycle.PENDING,
        'docker_sha': container_info.get('docker_sha'),
        'git_hash': container_info['git_hash'],
        'disable_tf_serving': disable_tf_serving,
        'use_datatransform_server': use_datatransform_server,
        'cluster_name': cluster_name,
        'inference_elb': environment.get_k8s_inference_elb(),
        'model_instance_id': values['model_instance_id'],
        'calls_per_second': deployment_info['calls_per_second'],
        'num_replicas': deployment_info['num_replicas'],
    }

    # Invoiced customers don't have auto deploy
    if deployment_info['billing_plan'] == BillingPlan.INVOICE and auto:
        values_deploy_instance['lifecycle'] = DeploymentLifecycle.CANCELLED

    values_deploy_instance_fields = ['model_instance_id', 'deployment_config', 'tag']
    for field_deploy in values_deploy_instance_fields:
        if values.get(field_deploy) is not None:
            values_deploy_instance[field_deploy] = values.get(field_deploy)

    # Treat auto deployments as lower priority. If there is another pending/deploying instance,
    # cancel this one immediately
    if deployment_info['deployment_instance_id'] and auto:
        pending_active = [lifecycle.value for lifecycle in DeploymentLifecycle.pending_or_active()]
        other_pending_active = db.get_single_value(f'SELECT count(1) FROM deployment_instances WHERE deployment_id=%s AND lifecycle in ({", ".join(["%s"] * len(pending_active))})', [deployment_id] + pending_active)
        if other_pending_active > 1:  # another instance is being provisioned...
            logging.info('Found more than one pending/active deployment instance. Cancelling auto-deploy')
            values_deploy_instance['lifecycle'] = DeploymentLifecycle.CANCELLED
            values_deploy_instance['lifecycle_msg'] = 'Auto deployment cancelled. Found multiple active deployments'
    deployment_instance = create_instance(DeploymentInstance, values_deploy_instance)
    if deployment_info['deployment_instance_id'] and values_deploy_instance['lifecycle'] == DeploymentLifecycle.PENDING:
        event_subtype = inference_svc.DeploymentEventSubType.AUTO if auto else inference_svc.DeploymentEventSubType.USER
        inference_svc.record_event(deployment_id, deployment_instance.get_id(), inference_svc.DeploymentEventType.SCHEDULED_PROMOTION, event_subtype)
    return deployment_instance


def promote_deployment_instance(deployment_id: int, model_instance_id: int):
    deployment = db.read_one(('SELECT IF(deployments.deployment_instance_id = deployment_instances.deployment_instance_id, 1, 0) AS active, deployment_instances.deployment_instance_id, deployment_instances.lifecycle '
                              'FROM deployments JOIN model_instances USING (model_id) LEFT JOIN deployment_instances USING (deployment_id, model_instance_id) '
                              'WHERE deployment_id=%s AND model_instance_id=%s '
                              'ORDER BY deployment_instances.deployment_instance_id DESC LIMIT 1'), (deployment_id, model_instance_id))
    if not deployment:
        raise exceptions.InstanceNotModifiedError('promote', 'Deployment')
    if deployment['active']:
        return
    if deployment['lifecycle']:
        lifecycle = DeploymentLifecycle(deployment['lifecycle'])
        if lifecycle.is_pending_or_active():
            return
    active_pending = [lifecycle.value for lifecycle in DeploymentLifecycle.pending_or_active()]
    in_flight = db.get_single_value(f'SELECT COUNT(1) FROM deployment_instances WHERE deployment_id=%s AND lifecycle in ({", ".join(["%s"] * len(active_pending))})', [deployment_id] + active_pending) or 0
    if in_flight > 1:
        raise exceptions.ConflictError('There are too many DeploymentInstances in flight, please try again later')
    deployment_instance_id = deployment['deployment_instance_id']
    if not deployment_instance_id:
        deploy_inst_info = {'model_instance_id': model_instance_id}
        new_instance = add_deployment_instance(deployment_id, deploy_inst_info)
        deployment_instance_id = new_instance.get_id()
    else:
        db.update_table_entry('deployment_instances', 'deployment_instance_id', deployment_instance_id, {'lifecycle': DeploymentLifecycle.PENDING.value})
    inference_svc.record_event(deployment_id, deployment_instance_id, inference_svc.DeploymentEventType.SCHEDULED_PROMOTION, inference_svc.DeploymentEventSubType.USER)


def get_deployment(deployment_id: int, skip_translate=False, dict_results=False):
    deployment = read_one_instance('SELECT * FROM deployments JOIN deployment_instances USING (deployment_instance_id) WHERE deployments.deployment_id=%s', Deployment, (deployment_id,), skip_translate=skip_translate, dict_results=dict_results)
    if deployment:
        model_instance_id = get_base_table_attr(deployment, 'deployment_instance', 'model_instance', 'model_instance_id')
        try:
            metric = get_deployment_model_metrics(model_instance_id)
            if dict_results:
                deployment['metrics'] = metric
            else:
                deployment.metrics = metric
        except exceptions.InvalidRequest:
            pass
        project_id = get_base_table_attr(deployment, 'project', 'project_id')
        project = get_project(project_id=project_id)
        if dict_results:
            deployment['use_case'] = project.use_case
        else:
            deployment.use_case = project.use_case
    return deployment


def get_deployment_instance(deployment_instance_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM deployment_instances WHERE deployment_instance_id=%s', DeploymentInstance, (deployment_instance_id,),
                             skip_translate=skip_translate, dict_results=dict_results)


def get_deployment_instance_by_tag(deployment_id: int, tag: str, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT deployment_instances.* FROM deployment_instances JOIN deployments USING (deployment_id) WHERE deployment_id=%s AND tag=%s', DeploymentInstance, (deployment_id, tag,),
                             skip_translate=skip_translate, dict_results=dict_results)


def edit_deployment(deployment_id: int, changes: dict):
    return update_instance(Deployment, deployment_id, changes)


def edit_deployment_instance_tag(deployment_instance_id: int, tag: str):
    return update_instance(DeploymentInstance, deployment_instance_id, {'tag': tag})


def start_deployment(deployment_id: int):
    deployment_instance_id = db.get_single_value('SELECT deployment_instance_id FROM deployments WHERE deployment_id=%s ORDER BY deployment_instance_id DESC LIMIT 1', (deployment_id,))
    if not deployment_instance_id:
        raise exceptions.DataNotFoundError('Deployment', hash_id('deployment_id', deployment_id))

    instance_info = db.read_one('SELECT lifecycle FROM deployment_instances WHERE deployment_instance_id=%s', (deployment_instance_id,))
    lifecycle = DeploymentLifecycle(instance_info['lifecycle'])
    if lifecycle == DeploymentLifecycle.DEPLOYING:
        raise exceptions.ConflictError('Deployment is currently being provisioned')
    elif lifecycle == DeploymentLifecycle.ACTIVE:
        raise exceptions.ConflictError('Deployment is already active')
    elif lifecycle in (DeploymentLifecycle.PENDING_STOPPING, DeploymentLifecycle.STOPPING):
        raise exceptions.Conflicterror('Deployment is currently stopping, please try again later')
    db.update_table_entry('deployment_instances', 'deployment_instance_id', deployment_instance_id, {'lifecycle': DeploymentLifecycle.PENDING.value})


def stop_deployment(deployment_id: int):
    deployment_instance_id = db.get_single_value('SELECT deployment_instance_id FROM deployments WHERE deployment_id=%s', (deployment_id,))
    if not deployment_instance_id:
        raise exceptions.DataNotFoundError('Deployment', hash_id('deployment_id', deployment_id))
    stop_deployment_instance(deployment_instance_id)


def stop_deployment_instance(deployment_instance_id: int):
    lifecycle = DeploymentLifecycle(db.get_single_value('SELECT lifecycle FROM deployment_instances WHERE deployment_instance_id=%s', (deployment_instance_id,)))
    if lifecycle in (DeploymentLifecycle.PENDING_STOPPING, DeploymentLifecycle.STOPPING, DeploymentLifecycle.STOPPED, DeploymentLifecycle.FAILED):
        return
    db.update_table_entry('deployment_instances', 'deployment_instance_id', deployment_instance_id, {'lifecycle': DeploymentLifecycle.PENDING_STOPPING.value, 'service_url': None})


def add_streaming_auth_token(organization_id: int):
    values = {'organization_id': organization_id, 'auth_token': uuid.uuid4().hex}
    if create_instance(StreamingAuthToken, values):
        return get_streaming_auth_token(values['auth_token'])


def get_streaming_auth_token(auth_token: str):
    return read_one_instance('SELECT * FROM streaming_auth_tokens WHERE auth_token=%s',
                             StreamingAuthToken, (auth_token,))


def list_streaming_auth_tokens(organization_id: int):
    return read_instances('SELECT * FROM streaming_auth_tokens WHERE organization_id=%s',
                          StreamingAuthToken, (organization_id,))


def delete_streaming_auth_token(auth_token: str):
    return delete_instance_where(StreamingAuthToken, auth_token=auth_token)


def add_deployment_auth_token(project_id: int):
    values = {'project_id': project_id, 'auth_token': uuid.uuid4().hex}
    return create_instance(DeploymentAuthToken, values)


def validate_auth_token_with_deployment(auth_token: str, deployment_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM deployment_auth_tokens JOIN deployments USING (project_id) WHERE auth_token=%s AND deployment_id=%s',
                             DeploymentAuthToken, (auth_token, deployment_id), skip_translate=skip_translate, dict_results=dict_results)


def get_deployment_auth_token(auth_token: str, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM deployment_auth_tokens WHERE auth_token=%s',
                             DeploymentAuthToken, (auth_token,), skip_translate=skip_translate, dict_results=dict_results)


def list_deployment_auth_tokens(project_id: int, skip_translate=False, dict_results=False):
    return read_instances('SELECT * FROM deployment_auth_tokens WHERE project_id=%s',
                          DeploymentAuthToken, (project_id,), skip_translate=skip_translate, dict_results=dict_results)


def delete_deployment_auth_token(auth_token: str):
    return delete_instance_where(DeploymentAuthToken, auth_token=auth_token)


def delete_deployment(deployment_id: int):
    deployment_instances = list_deployment_instances(deployment_id) or []
    for instance in deployment_instances:
        delete_deployment_instance(deployment_instance_id=instance.get_id())
    return delete_instance(Deployment, deployment_id)


def delete_deployment_instance(deployment_instance_id: int):
    stop_deployment_instance(deployment_instance_id)
    return delete_instance(DeploymentInstance, deployment_instance_id)


def add_model(values: Dict[str, Any], skip_translate=False, dict_results=False):
    if not values or 'project_id' not in values:
        raise exceptions.MissingParameterError('project_id')

    problem_type = read_single_value('problem_type', Project, values['project_id'])
    if get_problem_type(problem_type).is_valid_algorithm(values['algorithm']):
        raise exceptions.InvalidParameterError('algorithm', values['algorithm'])

    values_model_fields = ['project_id', 'name', 'algorithm', 'model_config']
    values_model = {}
    for field_model in values_model_fields:
        if values.get(field_model) is not None:
            values_model[field_model] = values.get(field_model)
    model = create_instance(Model, values_model)
    model_instance = add_model_instance(model.get_id(), values)

    return {'model': model, 'model_instance': model_instance}


def add_model_instance(model_id: int, values: Dict[str, Any], skip_translate=False, dict_results=False):
    values_model_instance_fields = ['tag', 'algorithm', 'model_config', 'dataset_instance_group_id']
    values_model_instance = {
        'model_id': model_id,
        'lifecycle': ModelLifecycle.TRAINING
    }
    for field_model in values_model_instance_fields:
        if values.get(field_model) is not None:
            values_model_instance[field_model] = values.get(field_model)
    return create_instance(ModelInstance, values_model_instance)


def edit_model(model_id: int, changes: dict):
    if 'project_id' in changes:
        raise exceptions.BaseError('You can\'t change the project of a model')
    return update_instance(Model, model_id, changes)


def get_model(model_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM models JOIN projects USING (project_id) WHERE model_id=%s', Model, (model_id,),
                             skip_translate=skip_translate, dict_results=dict_results)


def load_shared_models(model_ids: List[int], multiple_charts: bool = False, skip_translate: bool = False, editors_choice_info: bool = False):
    ''' Generic shared models loader.
    Given an ordered list of model ids, returns a mostly hydrated list of model objects
    '''
    extra_cols = []
    if editors_choice_info:
        extra_cols.extend([f'editors_choice_{col}' for col in ['at', 'subtitle', 'verdict', 'blurb']])
    extra_cols_str = ''
    if extra_cols:
        extra_cols_str = ',' + ', '.join(extra_cols)
    query = ('SELECT community_models.model_id, use_case, models.name, public_name, model_config, '
             'models.created_at, models.shared_at, models.updated_at, algorithm, '
             'community_models.user_id, user_handle, users.picture as user_pic, '
             'users.name AS user_name, use_case, description, votes, comments, '
             f'community_models.lifecycle AS publish_status, thumbnail, problem_type {extra_cols_str} '
             'FROM models JOIN community_models USING (model_id) JOIN users USING (user_id) JOIN projects USING (project_id) '
             'WHERE model_id in (' + ', '.join(['%s'] * len(model_ids)) + ')')
    models = db.read(query, model_ids) or []
    model_metrics_dict = get_multiple_model_metrics(model_ids, return_graphs=True)
    use_case_info = get_use_case_documentation()
    web_use_case_info = get_all_web_use_cases_yml()
    model_map = {}
    for model in models:
        model_id = model['model_id']
        user = {
            'user_id': model['user_id'] if skip_translate else hash_id('user_id', model['user_id']),
            'name': model['user_name'],
            'user_handle': model['user_handle'],
            'picture': model['user_pic'],
        }
        model['user'] = user
        model['name'] = model['public_name'] or model['name']
        metrics, metric_infos, deployment_display = model_metrics_dict[model_id]
        model['metrics'] = {k: v for k, v in metrics.items() if not isinstance(v, dict)}
        model['metric_names'] = [{key: info['name']} for key, info in metric_infos.items()]
        model['metric_infos'] = metric_infos
        model['deployment_display'] = deployment_display
        chart_group_title, charts = get_shared_model_charts(model_id, model['problem_type'], model_metrics=metrics)
        model['chart'] = charts[0]
        model['chart_group_title'] = chart_group_title
        if multiple_charts and len(charts) > 1:
            model['secondary_chart'] = charts[1]
        model['thumbnail'] = model.get('thumbnail') or get_default_model_image(model['use_case'])
        model['use_case_name'] = use_case_info[model['use_case']]['name']
        model['use_case_url'] = next(iter(use_case['url_name_use_case'] for use_case in web_use_case_info if use_case['use_case'] == model['use_case']), None)
        solution_info = get_solution(model['use_case'])
        if solution_info:
            model['solution_name'] = solution_info['name']
            model['solution_img'] = solution_info['img_src']
        if not skip_translate:
            model['model_id'] = hash_id('model_id', model['model_id'])
        if model['publish_status'] == SharedModelLifecycle.PUBLISHED:
            del model['publish_status']
        model_map[model_id] = model
    return [model_map[model_id] for model_id in model_ids if model_id in model_map]


def annotate_shared_models(models: List[dict], user_id: int, anon_token: str):
    voted_ids = set()
    if user_id or anon_token:
        model_ids = [unhash_id_with_type(m['model_id'], 'model_id') for m in models]
        voted = db.read(f'SELECT model_id FROM model_votes WHERE model_id IN ({", ".join(["%s"] * len(model_ids))}) AND (user_id=%s OR anon_token=%s)', model_ids + [user_id, anon_token]) or []
        voted_ids = set(vote['model_id'] for vote in voted)
        for model_id, model in zip(model_ids, models):
            if model_id in voted_ids:
                model['voted'] = True


def get_shared_model(model_id: int, user_id: int, anon_token: str, skip_translate: bool = False, editors_choice_info: bool = False):
    query = 'SELECT shared FROM models JOIN community_models USING (model_id) WHERE model_id=%s '
    vals = [model_id]
    if user_id:
        query += 'AND (community_models.lifecycle=%s OR community_models.user_id=%s) '
        vals.extend([SharedModelLifecycle.PUBLISHED.value, user_id])
    else:
        query += 'AND community_models.lifecycle=%s '
        vals.append(SharedModelLifecycle.PUBLISHED.value)
    if not db.get_single_value(query, vals):
        raise exceptions.DataNotFoundError('Model', model_id)
    models = load_shared_models([model_id], multiple_charts=True, skip_translate=skip_translate, editors_choice_info=editors_choice_info)
    annotate_shared_models(models, user_id, anon_token)
    return models[0]


def get_editors_choice(user_id: int, anon_token: str):
    model_id = db.get_single_value('SELECT model_id FROM community_models WHERE editors_choice_visible=1')
    if model_id:
        models = load_shared_models([model_id], editors_choice_info=True)
        annotate_shared_models(models, user_id, anon_token)
        model = models[0]
        # clean up the date
        model['editors_choice_at'] = model['editors_choice_at'].date()
        return model
    else:
        return {}


def sign_image(picture, external=False, **kwargs):
    external_config = environment.get_imigix('external' if external else 's3')
    token = external_config['token']
    url = external_config['url']
    query_args = ''
    if kwargs:
        query_args = '&'.join([quote(key, '') + '=' + quote(str(val), '') for key, val in sorted(kwargs.items())])
    encoded_picture = '/' + quote(picture, safe="~()*!.'") if picture.startswith('http') else quote('/' + picture)
    signature = hashlib.md5(str(token + encoded_picture + ('?' + query_args if query_args else '')).encode('utf-8')).hexdigest()
    if query_args:
        query_args += '&'
    return f'{url}{encoded_picture}?{query_args}s={signature}'


def get_default_model_image(use_case: str):
    static_content_url = environment.get_loggedin_ui('static_content_base_url')
    return sign_image(f"{static_content_url}/app/imgs/{get_use_case_yml(use_case, no_copy=True)['web_ui']['img_src']}", external=True, w=256, h=256, bg='white', fit='clip', pad=34)


def get_shared_model_graphs(model_id: int):
    '''
    Renders graphs as SVGs from the dataserver
    '''
    if not db.get_single_value('SELECT shared FROM models WHERE model_id=%s', (model_id,)):
        raise exceptions.DataNotFoundError('Model', model_id)
    instance = get_latest_model_instance(model_id)
    organization_id = db.get_single_value('SELECT organization_id FROM models JOIN project_owners USING (project_id) WHERE model_id=%s', (model_id,))
    model_path = get_model_location(organization_id, instance.get_id(), instance.algorithm)
    model_dir = cloudartifacts.get_model_artifacts_directory(organization_id, instance.get_id())
    metrics_path = os.path.join(cloudartifacts.get_results_directory_from_model_dir(model_dir), instance.algorithm)
    dataset_group_path = cloudartifacts.get_processed_data_directory(organization_id, instance.dataset_instance_group.get_id())
    problem_type_str = db.get_single_value('SELECT problem_type FROM projects WHERE project_id=%s', (instance.project.get_id(),))
    problem_type = get_problem_type(problem_type_str)
    graphs = []
    helptext = set()
    section_header, graph_infos = problem_type.get_model_graphs()
    for graph_info in graph_infos:
        if graph_info.get('helptext'):
            helptext.update(graph_info['helptext'])
        try:
            graph_data = call_dataset_server('v1/chart', model_path=model_path, metrics_path=metrics_path, dataset_group_path=dataset_group_path, chart_type=graph_info['type'], **(graph_info.get('params') or {})).text
            graphs.append({
                'graph': graph_data,
                'name': graph_info['name'],
                'description': graph_info.get('description'),
                'large': graph_info.get('large', False)
            })
        except Exception:
            logging.warn(f'Error while retrieving {graph_info["name"]} graph for model { model_id }')
    return {'graphs': graphs, 'header': section_header, 'helptext': list(helptext)}


def get_shared_model_charts(model_id: int, problem_type: str, model_metrics: dict = None):
    '''
    Returns metrics-based chart
    '''
    problem_type = get_problem_type(problem_type)
    model_metrics = model_metrics or get_model_metrics(model_id, None, return_graphs=True)['metrics']
    return problem_type.format_metrics_chart(model_metrics)


def vote_shared_model(model_id: int, anon_token: str, user_id: int):
    existing = db.get_single_value('SELECT 1 FROM model_votes WHERE model_id=%s AND (user_id=%s OR anon_token=%s)', (model_id, user_id, anon_token))
    if existing:
        return
    data = {
        'model_id': model_id,
    }
    if user_id:
        data['user_id'] = user_id
    if anon_token:
        data['anon_token'] = anon_token
    db.add_row('model_votes', None, None, data)
    db.write('UPDATE community_models SET votes=votes+1 WHERE model_id=%s', (model_id,))


def remove_vote_shared_model(model_id: int, anon_token: str, user_id: int):
    existing = db.get_single_value('SELECT 1 FROM model_votes WHERE model_id=%s AND (user_id=%s OR anon_token=%s)', (model_id, user_id, anon_token))
    if not existing:
        return
    db.delete_row('model_votes', 'model_id=%s AND (user_id=%s OR anon_token=%s)', (model_id, user_id, anon_token))
    db.write('UPDATE community_models SET votes=GREATEST(0, votes-1) WHERE model_id=%s', (model_id,))


def add_comment_shared_model(model_id: int, user_id: int, comment: str):
    shared_model = db.get_single_value('SELECT 1 FROM models WHERE model_id=%s and shared=1', (model_id,))
    if not shared_model:
        raise exceptions.DataNotFoundError('Model', hash_id('model_id', model_id))
    data = {
        'model_id': model_id,
        'user_id': user_id,
        'type': 'comment',
        'comment': comment
    }
    comment_id = db.add_row('community_interactions', None, None, data)
    db.write('UPDATE community_models SET comments=GREATEST(0, comments+1) WHERE model_id=%s', (model_id,))
    return {'community_interaction_id': hash_id('community_interaction_id', comment_id)}


def check_comment_user(community_interaction_id: int, user_id: int):
    exists = db.get_single_value('SELECT 1 FROM community_interactions WHERE community_interaction_id=%s AND user_id=%s', (community_interaction_id, user_id))
    if not exists:
        raise exceptions.DataNotFoundError('community_interaction', hash_id('community_interaction_id', community_interaction_id))


def delete_comment_shared_model(community_interaction_id: int, user_id: int):
    model_id = db.get_single_value('SELECT model_id FROM community_interactions WHERE community_interaction_id=%s', (community_interaction_id,))
    check_comment_user(community_interaction_id, user_id)
    delete_instance(CommunityInteraction, instance_id=community_interaction_id)
    db.write('UPDATE community_models SET comments=GREATEST(0, comments-1) WHERE model_id=%s', (model_id,))


def edit_comment_shared_model(community_interaction_id: int, user_id: int, comment: str):
    check_comment_user(community_interaction_id, user_id)
    db.update_table_entry('community_interactions', 'community_interaction_id', community_interaction_id, {'comment': comment})


_COMMENTS_BASE_QUERY = ('SELECT community_interaction_id, model_id, user_id, user_handle, picture, community_interactions.created_at, comment '
                        'FROM community_interactions JOIN users USING (user_id) JOIN models USING (model_id) WHERE shared=1 ')


def _comment_from_row(row):
    return {
        'community_interaction_id': hash_id('community_interaction_id', row['community_interaction_id']),
        'model_id': hash_id('model_id', row['model_id']),
        'user_id': hash_id('user_id', row['user_id']),
        'user_handle': row['user_handle'],
        'picture': row['picture'],
        'created_at': row['created_at'],
        'comment': row['comment']
    }


def get_comment_shared_model(community_interaction_id: int):
    query = _COMMENTS_BASE_QUERY + 'AND community_interaction_id=%s'
    vals = (community_interaction_id,)
    row = db.read_one(query, vals)
    if row:
        return _comment_from_row(row)
    raise exceptions.DataNotFoundError('community_interaction', hash_id('community_interaction_id', community_interaction_id))


def list_comments_shared_model(model_id: int, user_id: int, community_interaction_id: int = None, limit: int = 30):
    query = _COMMENTS_BASE_QUERY + 'AND model_id=%s '
    vals = [model_id]
    if community_interaction_id:
        query += 'AND community_interaction_id < %s '
        vals.append(community_interaction_id)
    query += 'ORDER BY community_interaction_id ASC LIMIT %s'
    vals.append(limit)
    rows = db.read(query, vals) or []
    comments = []
    for row in rows:
        comments.append(_comment_from_row(row))
    return comments


def list_user_comments(user_handle: str, community_interaction_id: int = None):
    user_id = db.get_single_value('SELECT user_id FROM users WHERE user_handle=%s', (user_handle,))
    if not user_id:
        raise exceptions.DataNotFoundError('User', user_handle)
    query = _COMMENTS_BASE_QUERY + 'AND user_id=%s '
    vals = [user_id]
    if community_interaction_id:
        query += 'AND community_interaction_id < %s '
        vals.append(community_interaction_id)
    query += 'ORDER BY community_interaction_id ASC LIMIT 30'
    rows = db.read(query, vals) or []
    comments = []
    for row in rows:
        comments.append(_comment_from_row(row))
    return comments


def get_latest_model_instance(model_id: int, trained_only: bool = False, skip_translate=False, dict_results=False):
    extra_where = ''
    extra_args = []
    if trained_only:
        extra_where = 'AND model_instances.lifecycle=%s'
        extra_args.append(ModelLifecycle.COMPLETE.value)

    return read_one_instance('SELECT * FROM model_instances JOIN dataset_instance_groups USING (dataset_instance_group_id) JOIN models USING (model_id) JOIN projects ON (models.project_id=projects.project_id) WHERE model_id=%s ' + extra_where + ' ORDER BY model_instances.created_at DESC LIMIT 1', ModelInstance, (model_id, *extra_args),
                             skip_translate=skip_translate, dict_results=dict_results)


def get_model_instance(model_instance_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM model_instances JOIN dataset_instance_groups USING (dataset_instance_group_id) JOIN models USING (model_id) JOIN projects ON (models.project_id=projects.project_id) WHERE model_instance_id=%s', ModelInstance, (model_instance_id,),
                             skip_translate=skip_translate, dict_results=dict_results)


def list_model_instances(model_id: int, skip_translate=False, dict_results=False):
    """ UI currently expects this to be in reverse chronological order
    """
    model_instances = read_instances('SELECT * FROM model_instances JOIN dataset_instance_groups USING (dataset_instance_group_id) JOIN models USING (model_id) JOIN projects ON (models.project_id=projects.project_id) WHERE model_id=%s ORDER BY model_instances.created_at DESC', ModelInstance, (model_id,),
                                     skip_translate=skip_translate, dict_results=dict_results)

    return model_instances


def filter_models(models, deployable=True):
    filtered = []
    if models:
        problem_type_str = models[0].project.problem_type if not isinstance(models[0], dict) else models[0]['project']['problem_type']
        problem_type = get_problem_type(problem_type_str)
        for model in models:
            algorithm = model.algorithm if not isinstance(model, dict) else model['algorithm']
            model_deployable = problem_type.is_deployable_algorithm(algorithm)
            if deployable == model_deployable:
                filtered.append(model)
    return filtered


def list_models(project_id: int, skip_translate=False, dict_results=False):
    return filter_models(read_instances('SELECT * FROM models JOIN projects USING (project_id) WHERE project_id=%s', Model, (project_id,),
                                        skip_translate=skip_translate, dict_results=dict_results))


def create_community_model(model_id: int, user_id: int, name: str = None, description: str = None):
    data = {
        'model_id': model_id,
        'user_id': user_id,
        'lifecycle': SharedModelLifecycle.PENDING.value,
        'public_name': name
    }
    if not name:
        data['public_name'] = read_single_value('name', Model, model_id)
    if description:
        data['description'] = description
    db.add_row('community_models', None, None, data)


def get_community_model(model_id: int):
    return db.read_one('SELECT model_id, description FROM community_models WHERE model_id=%s', (model_id,))


def update_community_model(model_id: int, **changes):
    db.update_table_entry('community_models', 'model_id', model_id, changes)


def get_shared_model_order(loggedin_user_id: int, anon_token: str, use_case: str, user_handle: str, sort_by: str, filter_by: str, limit: int = 100):
    ''' Retrieves ordered list of ids. Ideally should be as light-weight a query as possible.
    '''
    vals = []
    query = ('SELECT community_models.model_id '
             'FROM models JOIN community_models USING (model_id) JOIN users USING (user_id) JOIN projects USING (project_id) ')
    if filter_by == 'votes':
        query += 'JOIN model_votes ON (community_models.model_id = model_votes.model_id AND '
        if loggedin_user_id:
            query += 'model_votes.user_id=%s) '
            vals.append(loggedin_user_id)
        else:
            query += 'anon_token=%s) '
            vals.append(anon_token)
    query += ' WHERE shared=1 '
    if loggedin_user_id:
        query += 'AND (community_models.lifecycle=%s OR community_models.user_id=%s) '
        vals.extend([SharedModelLifecycle.PUBLISHED.value, loggedin_user_id])
    else:
        query += 'AND community_models.lifecycle=%s '
        vals.append(SharedModelLifecycle.PUBLISHED.value)
    if use_case:
        query += 'AND use_case=%s '
        vals.append(use_case.lower())
    if user_handle:
        query += 'AND user_handle=%s '
        vals.append(user_handle)
    if sort_by == 'votes':
        query += 'ORDER BY votes DESC '
    elif sort_by == 'shared_at':
        query += 'ORDER BY shared_at DESC '
    else:
        query += 'ORDER BY model_id DESC '
    query += 'LIMIT %s'
    vals.append(limit)
    model_id_rows = db.read(query, vals) or []
    return [model['model_id'] for model in model_id_rows]


def list_shared_models(loggedin_user_id: int, anon_token: str, limit: int, use_case: str, user_handle: str, sort_by: str, filter_by: str, last_seen_model_id: int = None, skip_translate=False, editors_choice_info: bool = False):
    # TODO: Add some sort of caching such that the sort order is stable for a given session
    model_ids = get_shared_model_order(loggedin_user_id, anon_token, use_case, user_handle, sort_by, filter_by)
    if last_seen_model_id:
        index = -1
        try:
            index = model_ids.index(last_seen_model_id)
        except ValueError:
            pass
        if index >= 0:
            index += 1
            model_ids = model_ids[index:]
    model_ids = model_ids[:limit]
    models = []
    if model_ids:
        models = load_shared_models(model_ids, skip_translate=skip_translate, editors_choice_info=editors_choice_info)
        annotate_shared_models(models, loggedin_user_id, anon_token)
    return models


def list_baseline_models(project_id: int, skip_translate=False, dict_results=False):
    return filter_models(read_instances('SELECT * FROM models JOIN projects USING (project_id) WHERE project_id=%s', Model, (project_id,),
                                        skip_translate=skip_translate, dict_results=dict_results), deployable=False)


def latest_deployable_model(project_id: int, skip_translate=False, dict_results=False):
    models = filter_models(read_instances('SELECT * FROM models JOIN projects USING (project_id) WHERE project_id=%s ORDER BY models.created_at DESC LIMIT 1', Model, (project_id,),
                                          skip_translate=skip_translate, dict_results=dict_results))
    if models:
        return models[0]
    return None


def delete_model_instance(model_instance_id: int):
    return delete_instance(ModelInstance, model_instance_id)


def delete_model(model_id: int):
    deployment_id = db.get_single_value('SELECT deployment_id FROM deployments WHERE model_id=%s and deployment_instance_id is not NULL', (model_id,))
    if deployment_id:
        raise exceptions.ConflictError(f'Model is currently associated with Deployment "{hash_id(deployment_id=deployment_id)}". Please delete this deployment before deleting this model.')
    baseline_model_ids = list([row['model_id'] for row in db.read('SELECT model_id FROM models WHERE primary_model_id = %s', (model_id,)) or []])
    model_instances = list_model_instances(model_id)
    for model_instance in model_instances:
        delete_model_instance(model_instance.get_id())
    delete_instance(Model, model_id)
    if baseline_model_ids:
        for bmi in baseline_model_ids:
            delete_model(bmi)


def get_baseline_model_metrics(model_id: int, dataset_instance_group_id: int = None):
    if dataset_instance_group_id:
        baseline_models = db.read('SELECT name, model_id, model_instance_id FROM model_instances JOIN models USING (model_id) WHERE dataset_instance_group_id=%s AND primary_model_id=%s', (dataset_instance_group_id, model_id)) or []
    else:
        baseline_models = db.read('SELECT name, model_id FROM models WHERE primary_model_id=%s', (model_id,)) or []
    if not baseline_models:  # Backwards compatibility for baseline models without the primary_model_id set
        model = get_model(model_id)
        models = list_baseline_models(model.project.get_id())
        for baseline_model in models:
            if model.model_config == baseline_model.model_config:
                baseline_models.append({'model_id': baseline_model.get_id(), 'name': baseline_model.name})
    baseline_model_metrics = []
    for baseline_model in baseline_models:
        try:
            baseline_model_metrics.append(get_model_metrics(baseline_model['model_id'], baseline_model.get('model_instance_id')))
        except (exceptions.DataNotFoundError, exceptions.InvalidRequest):
            baseline_model_metrics.append({'name': baseline_model['name'], 'metrics': {}})
    return baseline_model_metrics


def get_model_metrics(model_id: int, model_instance_id: int, return_graphs: bool = False):
    model_instance = get_latest_model_instance(model_id, trained_only=True) if model_instance_id is None else get_model_instance(model_instance_id)
    if not model_instance:
        raise exceptions.DataNotFoundError('Model', hash_id('model_id', model_id))
    return get_model_instance_metrics(return_graphs=return_graphs, model_instance_id=model_instance.get_id())


def get_multiple_model_metrics(model_ids: List[int], return_graphs: bool = False) -> dict:
    latest_instance_ids = db.read('SELECT MAX(model_instance_id) as latest_instance_id FROM model_instances WHERE model_id IN (' + ', '.join(['%s'] * len(model_ids)) + ') GROUP BY model_id', model_ids) or []
    instance_ids = [row['latest_instance_id'] for row in latest_instance_ids]
    instances = db.read('SELECT model_id, problem_type, training_output_params FROM model_instances JOIN models USING (model_id) JOIN projects USING (project_id) WHERE model_instance_id IN (' + ', '.join(['%s'] * len(instance_ids)) + ')', instance_ids) or []
    to_return = {}
    for instance in instances:
        raw_metrics = (instance['training_output_params'] or {}).get('metrics') or {}
        to_return[instance['model_id']] = process_model_metrics(raw_metrics, instance['problem_type'], return_graphs=return_graphs)
    return to_return


def process_model_metrics(raw_metrics, problem_type_str, return_graphs: bool = False):
    metrics_infos = get_problem_type(problem_type_str).get_metrics_infos()
    raw_metrics = raw_metrics or {}
    metrics = {}
    metric_infos = {}
    deployment_display = {}
    metric_formats = {}
    for info in metrics_infos:
        key = info['key']
        if key not in raw_metrics or (not return_graphs and isinstance(raw_metrics[key], dict)):
            continue
        if info.get('format'):
            metric_formats[key] = info['format']
        metrics[key] = raw_metrics[key]
        metric_infos[key] = {'name': info['name']}
        if info.get('format'):
            metric_infos[key]['format'] = info['format']
        if not deployment_display and info.get('deployment_display'):
            deployment_display[key] = True
    return metrics, metric_infos, deployment_display


def get_model_instance_metrics(model_instance_id: int, return_graphs: bool = False):
    model_instance = get_model_instance(model_instance_id=model_instance_id)
    if model_instance.lifecycle != ModelLifecycle.COMPLETE:
        raise exceptions.InvalidRequest('Model is still being processed')
    if not model_instance.training_output_params and not (model_instance.training_output_params or {}).get('metrics'):
        raise exceptions.InvalidRequest('Metrics for model do not exist')
    problem_type = read_single_value('problem_type', Project, model_instance.project.get_id())
    raw_metrics = (model_instance.training_output_params or {}).get('metrics')
    metrics, metric_infos, deployment_display = process_model_metrics(raw_metrics, problem_type, return_graphs)
    return {
        'model_id': model_instance.model.model_id,
        'model_instance_id': model_instance.model_instance_id,
        'training_completed_at': model_instance.training_completed_at,
        'name': model_instance.model.name,
        'model_config': model_instance.model_config,
        'algorithm': model_instance.algorithm,
        'metrics': metrics,
        'metric_names': [{key: info['name']} for key, info in metric_infos.items()],
        'metric_infos': metric_infos,
        'deployment_display': deployment_display,
    }


def get_data_augmentation_comparison(organization_id: int, model_id: int, model_instance_id: int, variation: int, num_items: int = 10):
    model_instance = get_latest_model_instance(model_id, trained_only=True) if model_instance_id is None else get_model_instance(model_instance_id)
    if not model_instance:
        raise exceptions.DataNotFoundError('Model', hash_id('model_id', model_id))
    if model_instance.lifecycle not in (ModelLifecycle.COMPLETE, ModelLifecycle.EVALUATING, ModelLifecycle.EVALUATING_FAILED):
        raise exceptions.NotReadyError('Model', 10)
    if not model_instance.model_config.get('USE_DATA_AUGMENTATION'):
        raise exceptions.InvalidRequest('Specified model was not trained with data augmentation')
    dataset_instance_group = db.read_one('SELECT dataset_instance_ids, data_usage_config, project_id FROM dataset_instance_groups WHERE dataset_instance_group_id=%s', (model_instance.dataset_instance_group.get_id(),)) or {}
    dataset_instance_ids = dataset_instance_group['dataset_instance_ids']

    dataset_instances = _get_dataset_instance_infos(dataset_instance_group['project_id'], dataset_instance_ids)
    dataset_instance_info = next(iter([d for d in dataset_instances if d.project_dataset_type == ProjectDatasetType.TIMESERIES]))
    if not dataset_instance_info:
        # TODO: Extend to support other types of data
        raise exceptions.InvalidRequest('Augmentation comparison currently only supports timeseries data')
    model_loc = get_model_location(organization_id, model_instance.get_id(), model_instance.algorithm)
    synthetic_data_loc = model_loc.replace(f'{model_instance.algorithm}.model', 'synthetic_data.csv')

    params = {'dataset_instance_info': dataset_instance_info.to_json(),
              'synth_data_loc': synthetic_data_loc,
              'variation': variation,
              'num_items': num_items}

    graphs = call_dataset_server('v1/dataAugmentComparison', **params).json()
    return [
        {
            'name': 'Original data',
            'is_synthetic': False,
            'charts': graphs['orig_charts'],
        }, {
            'name': 'Synthesized data',
            'is_synthetic': True,
            'charts': graphs['synth_charts'],
        }
    ]


def get_dataset_instance_ids_for_project(project_id):
    return [row['dataset_instance_id'] for row in db.read('SELECT dataset_instances.dataset_id, MAX(dataset_instance_id) AS dataset_instance_id '
                                                          'FROM project_datasets JOIN projects USING (project_id) JOIN dataset_instances USING (dataset_id) JOIN datasets ON (dataset_instances.dataset_id=datasets.dataset_id)'
                                                          'WHERE project_id=%s AND project_datasets.lifecycle=%s GROUP BY dataset_instances.dataset_id',
                                                          (project_id, ProjectDatasetLifecycle.ACTIVE.value)) or []]


def get_dataset_instances_for_project(project_id):
    dataset_instance_ids = get_dataset_instance_ids_for_project(project_id)
    if dataset_instance_ids:
        return read_instances('SELECT dataset_instances.*, datasets.name, datasets.source_type FROM dataset_instances JOIN datasets USING (dataset_id) WHERE dataset_instance_id IN (' + ', '.join(['%s'] * len(dataset_instance_ids)) + ')',
                              DatasetInstance, dataset_instance_ids)
    return None


@cache.cached(time=900)
def get_test_data(organization_id, dataset_instance_group_id, compressed=True):
    processed_data_path = cloudartifacts.get_processed_data_directory(organization_id, dataset_instance_group_id)
    data_path = os.path.join(cloudartifacts.get_testdata_directory_from_dataset_path(processed_data_path), 'data_info.json')
    if compressed:
        data_path += '.gz'
    return cloud.CloudLocation(data_path).read_json_from_file()


def list_test_data_info(organization_id: int, model_instance_id: int = None, dataset_instance_group_id: int = None):
    if not dataset_instance_group_id:
        dataset_instance_group_id = read_single_value('dataset_instance_group_id', ModelInstance, model_instance_id)
    error = None
    project_id = read_single_value('project_id', DatasetInstanceGroup, dataset_instance_group_id)
    project = get_project(project_id)
    display_type = get_use_case_yml(project.use_case)['info'].get('prediction_ui_display_type')
    for compressed in (True, False):
        try:
            test_data = get_test_data(organization_id, dataset_instance_group_id, compressed=compressed)
            if display_type:
                test_data['display_info'].update({'display_type': display_type})
            return test_data
        except cloud.NotFound:
            error = exceptions.DataNotFoundError('TestData', hash_id('model_instance_id', model_instance_id))
        except Exception as e:
            error = e
    raise error


def add_dataset_upload(organization_id: int, dataset_instance_id: int, dataset_id: int, skip_translate=False, dict_results=False):
    cloud_location = cloud.CloudLocation(get_uploaded_location(organization_id, dataset_id, dataset_instance_id, create=True))
    mpu_id = cloud_location.create_upload()
    row = {
        'upload_id': mpu_id,
        'cloud_url': cloud_location.location,
        'dataset_id': dataset_id,
        'dataset_instance_id': dataset_instance_id,
        'lifecycle': DatasetUploadLifecycle.PENDING,
        'upload_type': 'upload'
    }
    return create_instance(DatasetUpload, row)


def storage_upload_file_part(organization_id: int, dataset_upload_id: int, part_number: int, data: io.BytesIO):
    operation_row = db.read_one('SELECT * FROM dataset_uploads WHERE dataset_upload_id=%s ', (dataset_upload_id,))
    if operation_row is None or operation_row['lifecycle'] != DatasetUploadLifecycle.PENDING.value:
        raise exceptions.DataNotFoundError('Upload', hash_id('dataset_upload_id', dataset_upload_id))
    cloud_location = cloud.CloudLocation(operation_row['cloud_url'])
    part = cloud_location.upload_part(part_number, operation_row['upload_id'], data)
    row = {
        'etag': part['ETag'],
        'destination': operation_row['cloud_url'],
        'part_number': part_number,
        'dataset_upload_id': operation_row['dataset_upload_id']
    }
    part_row = db.read_one('SELECT * FROM upload_dataset_parts WHERE dataset_upload_id=%s AND part_number=%s', (dataset_upload_id, part_number))
    if part_row:
        db.update_table_entry('upload_dataset_parts', 'dataset_upload_id', part_row['dataset_upload_id'], row)
    else:
        db.add_row('upload_dataset_parts', None, None, row)

    res = {'etag': part['ETag']}
    if part.get('md5'):
        res['md5'] = part['md5']
    return res


def storage_complete_upload_file(dataset_upload_id: int):
    operation_row = db.read_one('SELECT * FROM dataset_uploads WHERE dataset_upload_id=%s ', (dataset_upload_id,))
    if operation_row is None or operation_row['lifecycle'] != DatasetUploadLifecycle.PENDING.value:
        raise exceptions.DataNotFoundError('Upload', hash_id('dataset_upload_id', dataset_upload_id))
    part_rows = db.read('SELECT * FROM upload_dataset_parts WHERE dataset_upload_id=%s', (dataset_upload_id,))
    if part_rows is None:
        raise exceptions.DataNotFoundError('File Parts from Upload', hash_id('dataset_upload_id', dataset_upload_id))
    file_parts = []
    for file in sorted(part_rows, key=lambda k: k['part_number']):
        file_parts.append({'PartNumber': file['part_number'], 'ETag': file['etag']})
    cloud_location = cloud.CloudLocation(operation_row['cloud_url'])
    cloud_location.complete_upload(operation_row['upload_id'], parts=file_parts)
    file_size = cloud_location.get_file_size()
    update_instance(DatasetUpload, dataset_upload_id, {'lifecycle': DatasetUploadLifecycle.COMPLETE})

    dataset_instance_id = operation_row['dataset_instance_id']
    update = {'lifecycle': DatasetLifecycle.INSPECTING, 'size': file_size, 'metrics_lifecycle': DatasetMetricsLifecycle.PENDING}
    update_instance(DatasetInstance, dataset_instance_id, update)
    start_dataset_instance_pipeline(dataset_instance_id)
    db.delete_row('upload_dataset_parts', 'dataset_upload_id=%s', (operation_row['dataset_upload_id'],))

    return {'dataset_id': hash_id(dataset_id=operation_row['dataset_id']), 'dataset_instance_id': hash_id(dataset_instance_id=dataset_instance_id)}


def wait_until_dataset_instance_ready(dataset_instance_id: int):
    status = DatasetLifecycle.IMPORTING
    while status not in (DatasetLifecycle.COMPLETE, DatasetLifecycle.IMPORTING_FAILED, DatasetLifecycle.INSPECTING_FAILED):
        time.sleep(2)
        status_str = db.get_single_value('SELECT lifecycle FROM dataset_instances WHERE dataset_instance_id=%s', (dataset_instance_id,))
        status = DatasetLifecycle(status_str)


def _list_uploaded_file_parts(dataset_upload_id: int):
    part_rows = db.read('SELECT * FROM upload_dataset_parts WHERE dataset_upload_id=%s', (dataset_upload_id,))
    if not part_rows:
        return []
    parts = [{'part_number': part['part_number'], 'etag': part['etag']} for part in part_rows]
    return parts


def get_upload_by_dataset_instance(dataset_instance_id: int):
    dataset_upload_id = read_single_value_where('dataset_upload_id', DatasetUpload, dataset_instance_id=dataset_instance_id)
    return get_upload(dataset_upload_id)


def get_upload(dataset_upload_id: int):
    dataset_upload = read_one_instance('SELECT * FROM dataset_uploads WHERE dataset_upload_id=%s', DatasetUpload, (dataset_upload_id,))
    if not dataset_upload:
        return None
    upload = dataset_upload.get_dict()
    if dataset_upload.upload_type == 'upload':
        parts = _list_uploaded_file_parts(dataset_upload_id)
        if parts:
            parts = sorted(parts, key=lambda k: k['part_number'])
        upload['parts'] = parts
    return upload


def cancel_upload(dataset_upload_id: int):
    operation_row = db.read_one('SELECT * FROM dataset_uploads WHERE dataset_upload_id=%s', (dataset_upload_id,))
    if operation_row is None or operation_row.get('lifecycle') != DatasetUploadLifecycle.PENDING:
        raise exceptions.DataNotFoundError('DatasetUpload', hash_id('dataset_upload_id', dataset_upload_id))
    cloud_location = cloud.CloudLocation(operation_row['cloud_url'])
    cloud_location.abort_upload(UploadId=operation_row['upload_id'])
    update_instance(DatasetUpload, operation_row['dataset_upload_id'], {'lifecycle': DatasetUploadLifecycle.CANCELLED})
    db.delete_row('upload_dataset_parts', 'dataset_upload_id=%s', (operation_row['dataset_upload_id'],))
    return None


def list_uploads(organization_id: int):
    operations = read_instances('SELECT dataset_uploads.* FROM dataset_uploads JOIN dataset_owners USING (dataset_id) WHERE organization_id=%s', DatasetUpload, (organization_id,), dict_results=True) or []
    uploads = []
    for operation in operations:
        uploads.append({
                       'dataset_upload_id': operation['dataset_upload_id'],
                       'lifecycle': operation['lifecycle'],
                       'created_at': operation['created_at'],
                       'dataset_id': operation['dataset']['dataset_id'],
                       'dataset_instance_id': operation['dataset_instance']['dataset_instance_id']
                       })
    return uploads


def add_signup(name, email, org_name, comments, useragent, ip_addr):
    ip = ip_addr
    try:
        # Try to parse and format, to be safe
        ip = str(ipaddress.ip_address(ip_addr))
    except Exception:
        pass
    row = {
        'name': name,
        'email': email,
        'organization': org_name,
        'comment': comments or '',
        'user_agent': useragent,
        'ip_addr': ip
    }
    db.add_row('signups', None, None, row)


def add_beta_signup(email, useragent, ip_addr, blacklist=False, tag=None, consultation=False):
    ip = ip_addr
    try:
        # Try to parse and format, to be safe
        ip = str(ipaddress.ip_address(ip_addr))
    except Exception:
        pass
    row = {
        'email': email,
        'user_agent': useragent,
        'ip_addr': ip,
        'blacklist': blacklist,
        'tag': tag,
        'consultation': consultation
    }
    return create_instance(BetaSignup, row)


def get_beta_signup(beta_signup_id, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM beta_signups WHERE beta_signup_id=%s',
                             BetaSignup, (beta_signup_id,), skip_translate=skip_translate, dict_results=dict_results)


def edit_beta_signup(beta_signup_id, info):
    update_instance(BetaSignup, beta_signup_id, info)


def is_invited_user(email: str):
    return read_single_value_where('invited_at', BetaSignup, email=email) is not None or environment.is_jenkins() or environment.in_devpod()


def hash_password(password: str):
    return base64.b64encode(bcrypt.hashpw(base64.b64encode(hashlib.sha256(password.encode('utf-8')).digest()), bcrypt.gensalt())).decode('utf-8')


def set_user_password(user_id: int, password: str):  # base64 encoding the password prior to hashing allows us to hash passwords larger than 72 bytes, which is the limit on bcrypt https://pypi.org/project/bcrypt/3.1.0/
    update_instance(User, user_id, {'password': hash_password(password)})


def update_user(user_id: int, values: dict):
    return update_instance(User, user_id, values)


def get_user_preferences(user_id: int):
    info = read_single_value('info', User, user_id) or {}
    return info.get('preferences', {}) or {}


def get_user_org_preferences(user_id: int, organization_id: int):
    return read_single_value_where('preferences', OrganizationUser, organization_id=organization_id, user_id=user_id) or {}


def create_user_alert(user_id: int, organization_id: int, title: str, description: str, link: str = None):
    return create_instance(Alert, {'user_id': user_id, 'organization_id': organization_id, 'title': title, 'description': description, 'link': link})


def get_user_alerts(user_id: int, organization_id: int, unread_only=False, since=0, skip_translate=False, dict_results=False):
    statement = 'SELECT * FROM alerts WHERE user_id=%s AND organization_id=%s'
    variables = [user_id, organization_id]
    if unread_only:
        statement += ' AND seen=%s'
        variables.append(False)
    if since:
        statement += ' AND created_at>%s'
        variables.append(datetime.datetime.fromtimestamp(since, tz=datetime.timezone.utc))
    return read_instances(statement, Alert, variables, skip_translate, dict_results)


def update_alert(alert_id: int, changes: dict):
    return update_instance(Alert, alert_id, changes)


def update_all_alerts_for_user(user_id: int, changes: dict):
    return update_instance_where(Alert, changes, user_id=user_id)


def update_user_preferences(user_id: int, preferences: dict):
    info = read_single_value('info', User, user_id) or {}
    existing_preferences = info.get('preferences', {})
    existing_preferences.update(preferences)
    info['preferences'] = existing_preferences
    return update_instance(User, user_id, {'info': info})


def update_user_org_preferences(user_id: int, organization_id: int, preferences: dict):
    existing_preferences = get_user_org_preferences(user_id, organization_id)
    existing_preferences.update(preferences)
    return update_instance_where(OrganizationUser, {'preferences': json.dumps(existing_preferences)}, user_id=user_id, organization_id=organization_id)


def update_org_preferences(org_id: int, preferences: dict):
    info = read_single_value('info', Organization, org_id) or {}
    existing_preferences = info.get('preferences', {})
    existing_preferences.update(preferences)
    info['preferences'] = existing_preferences
    return update_instance(Organization, org_id, {'info': info})


def _get_verification_path(organization_id: int, bucket: str, write_path=False):
    if write_path:
        return f'{bucket}/_realityengines_write_permission_{hash_id("organization_id", organization_id)}'
    return f'{bucket}/_realityengines_verification_file_{hash_id("organization_id", organization_id)}.txt'


def add_external_data_connection(organization_id: int, service: CloudStorageProvider, service_id: str, auth: dict):
    return create_instance(ExternalConnection, {'organization_id': organization_id, 'service': service, 'service_id': service_id, 'auth': auth})


def get_external_connection(external_connection_id: int):
    return read_one_instance('SELECT * FROM external_connections WHERE external_connection_id=%s',
                             ExternalConnection, (external_connection_id,))


def set_connection_status(external_connection_id: int, status: ConnectionStatus, auth: dict = None):
    updates = {'status': status}
    if auth:
        updates['auth'] = auth
    update_instance(ExternalConnection, external_connection_id, updates)


def list_external_connections(organization_id: int):
    return read_instances('SELECT * FROM external_connections WHERE organization_id=%s',
                          ExternalConnection, (organization_id,))


def delete_external_connection(external_connection_id: int):
    delete_instance(ExternalConnection, external_connection_id)


def get_bucket_owner(organization_id: int, bucket: str):
    return db.read_one('SELECT * FROM bucket_owners WHERE organization_id=%s AND bucket=%s', (organization_id, bucket)) or {}


def update_bucket_owner_auth(organization_id: int, bucket: str, extra_auth: dict):
    db.update_table_entry_where('bucket_owners', {'organization_id': organization_id, 'bucket': bucket}, {'extra_auth': json.dumps(extra_auth), 'verified': 0, 'write_permission': 0})


def delete_bucket_owner(organization_id: int, bucket: str):
    return db.delete_row('bucket_owners', 'organization_id=%s AND bucket=%s', (organization_id, bucket))


def get_bucket_ownership_test(organization_id: int, bucket: str, write_permission: bool = False):
    bucket_owner = get_bucket_owner(organization_id, bucket)
    if not bucket_owner:
        bucket_owner = {'organization_id': organization_id,
                        'bucket': bucket,
                        'verification_token': uuid.uuid4().hex
                        }
        db.add_row('bucket_owners', None, None, bucket_owner)
    cloud_location = cloud.CloudLocation(bucket)

    template = cloud_location.get_iam_template(hashed_organization_id=hash_id('organization_id', organization_id), write_permission=write_permission)
    cloud_location.add_bucket_permission(hash_id('organization_id', organization_id))
    return {'verified': verify_bucket_ownership(organization_id, bucket),
            'write_permission': verify_write_permission(organization_id, bucket),
            'auth_options': template,
            'service': cloud_location.storage_provider}


def verify_bucket_ownership(organization_id: int, bucket: str):
    bucket_owner = get_bucket_owner(organization_id, bucket)
    if not bucket_owner:
        return False
    if bucket_owner['verified']:
        return True
    path = _get_verification_path(organization_id, bucket)

    try:
        cloud_location = get_authed_cloud_location(bucket, organization_id)
        if cloud_location.can_list():
            db.update_table_entry_where('bucket_owners', {'organization_id': organization_id, 'bucket': bucket}, {'verified': True})
            return True
    except Exception as e:
        logging.exception(f'Error verifying {path}: {e}')
    return False


def verify_write_permission(organization_id: int, bucket: str):
    bucket_owner = get_bucket_owner(organization_id, bucket)
    if not bucket_owner or not bucket_owner['verified']:
        return False
    if bucket_owner['write_permission']:
        return True
    upload_path = _get_verification_path(organization_id, bucket, write_path=True) + '_write_verification'
    cloud_location = get_authed_cloud_location(upload_path, organization_id)
    if cloud_location.file_exists() or cloud_location.can_upload():
        db.update_table_entry_where('bucket_owners', {'organization_id': organization_id, 'bucket': bucket}, {'write_permission': True})
        return True
    return False


def get_buckets_for_organization(organization_id: int):
    buckets = db.read('SELECT bucket, verified, write_permission, extra_auth FROM bucket_owners WHERE organization_id=%s', (organization_id,)) or []
    return [{'bucket': bucket['bucket'], 'verified': bool(bucket['verified']), 'write_permission': bool(bucket['write_permission']), 'role_arn': (bucket['extra_auth'] or {}).get('role_arn')} for bucket in buckets]


def resolve_extra_auth(location: str, organization_id: int):
    qualified_bucket = cloud.CloudLocation.parse_location(location).qualified_bucket
    hashed_org_id = hash_id('organization_id', organization_id)
    return get_bucket_owner(organization_id, qualified_bucket).get('extra_auth') or cloud.CloudLocation(location).get_default_auth(hashed_organization_id=hashed_org_id, internal_org=read_single_value('domain', Organization, organization_id) == environment.get_internal_org_domain())


def get_authed_cloud_location(location: str, organization_id: int, **data_source_args):
    return cloud.CloudLocation(location, hashed_organization_id=hash_id('organization_id', organization_id), **resolve_extra_auth(location, organization_id), **data_source_args)


def dataset_requires_import(dataset_id: int):
    row = db.read_one('SELECT organization_id, cluster_name, data_source FROM datasets JOIN dataset_owners USING (dataset_id) JOIN organizations USING (organization_id) WHERE dataset_id=%s', (dataset_id,))
    if row['data_source']['location_type'] == LocationType.EXTERNAL_SERVICE:
        return True
    cluster_name = row['cluster_name'] or environment.get_cluster_name()
    cloud_location = cloud.CloudLocation(row['data_source']['location'])
    return cloud_location.requires_import(resolve_extra_auth(row['data_source']['location'], row['organization_id']), cluster_name)


def verify_user_password(user_id: int, password: str):
    hashed_password = read_single_value('password', User, user_id)
    if hashed_password is None:
        raise exceptions.DataNotFoundError('User', hash_id('user_id', user_id))
    return bcrypt.checkpw(base64.b64encode(hashlib.sha256(password.encode('utf-8')).digest()), base64.b64decode(hashed_password))


def add_password_reset_request(user_id: int):
    values = {'user_id': user_id,
              'request_token': uuid.uuid4().hex,
              'expires_at': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    return create_instance(PasswordResetRequest, values)


def get_password_reset_request_by_token(request_token: str, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM password_reset_requests WHERE request_token=%s',
                             PasswordResetRequest, (request_token,), skip_translate=skip_translate, dict_results=dict_results)


def get_password_reset_request_by_user(user_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM password_reset_requests WHERE user_id=%s',
                             PasswordResetRequest, (user_id,), skip_translate=skip_translate, dict_results=dict_results)


def delete_password_reset_request(user_id: int):
    password_reset_request = get_password_reset_request_by_user(user_id=user_id)
    if password_reset_request:
        delete_instance(PasswordResetRequest, password_reset_request.get_id())


def add_user(values):
    return create_instance(User, values)


def add_request_for_help(user_id: int):
    row = {'user_id': user_id}
    db.add_row('help_requests', None, None, row)


def add_user_invite(values):
    try:
        return create_instance(UserInvite, values)
    except db.DuplicateEntryError:
        raise exceptions.AlreadyExistsError('Invite with email', values['email'])


def update_user_invite(values, user_invite_id: int):
    return update_instance(UserInvite, user_invite_id, values)


def get_user_invites(organization_id: int, skip_translate=False, dict_results=False):
    return read_instances('SELECT * FROM user_invites WHERE organization_id=%s', UserInvite, (organization_id,), skip_translate, dict_results)


def get_user_invite(user_invite_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM user_invites WHERE user_invite_id=%s', UserInvite, (user_invite_id,), skip_translate, dict_results)


def get_user_invite_by_email(email: str, organization_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM user_invites WHERE email=%s AND organization_id=%s', UserInvite, (email, organization_id), skip_translate, dict_results)


def delete_user_invite(user_invite_id: int):
    delete_instance(UserInvite, user_invite_id)


def add_organization(values):
    return create_instance(Organization, values)


def update_organization(organization_id: int, changes: dict):
    update_instance(Organization, organization_id, changes)


def get_unjoined_orgs(user_id: int):
    user = get_user(user_id)
    domain = user.email.split('@')[1]
    public_orgs = get_organizations_by_domain(domain)
    user_orgs = db.read('SELECT organization_id FROM organization_users WHERE user_id=%s', (user.user_id,)) or []
    return [org for org in public_orgs if org.get_id() not in user_orgs]


def get_organizations_by_domain(domain, skip_translate=False, dict_results=False):
    return read_instances('SELECT * FROM organizations WHERE discoverable=1 AND domain=%s',
                          Organization, (domain,), skip_translate=skip_translate, dict_results=dict_results)


def get_organization_by_workspace(workspace, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM organizations WHERE workspace=%s',
                             Organization, (workspace,), skip_translate=skip_translate, dict_results=dict_results)


def add_api_key(user_id: int, organization_id: int, tag: str = None):
    values = {'user_id': user_id, 'organization_id': organization_id, 'api_key': uuid.uuid4().hex, 'tag': tag}
    return create_instance(ApiKey, values)


def get_api_key(api_key: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM api_keys WHERE api_key=%s',
                             ApiKey, (api_key,), skip_translate=skip_translate, dict_results=dict_results)


def get_api_keys_for_user(user_id: int, skip_translate=False, dict_results=False):
    return read_instances('SELECT * FROM api_keys WHERE user_id=%s',
                          ApiKey, (user_id,), skip_translate=skip_translate, dict_results=dict_results)


def delete_api_key(api_key_id: int):
    return delete_instance(ApiKey, api_key_id)


def get_user_by_email(email, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM users WHERE email=%s',
                             User, (email,), skip_translate=skip_translate, dict_results=dict_results)


def is_user_handle_available(user_handle: str):
    return not db.get_single_value('SELECT 1 FROM users WHERE user_handle=%s', (user_handle,))


def add_login_service(user_id: int, service: LoginService, service_id: str):
    values = {'user_id': user_id,
              'service': service,
              'service_id': service_id
              }
    create_instance(SocialLogin, values)


def get_user_by_service(service: LoginService, service_id: str):
    user_id = read_single_value_where('user_id', SocialLogin, service=service.value, service_id=service_id)
    if user_id:
        return get_user(user_id)


def get_medium_posts():
    rss_feed = environment.get_config()['medium']['rssfeed']
    feed = feedparser.parse(rss_feed)
    posts = []
    for post in feed.entries:
        posts.append({
            'title': post.title,
            'author': post.author,
            'created_at': post.published,
            'link': post.link,
            'content': post.summary
        })
    return {'posts': posts}


def get_last_meetup():
    default_url = "https://www.meetup.com/An-AI-Paper-and-A-Drink"

    curr_row = db.read_one('SELECT date_string, speakers, url, img_src, img_style, img_style_mobile FROM web_static_meetup WHERE visible = 1 ORDER BY id DESC')
    if curr_row:
        return {
            "date_string": curr_row["date_string"],
            "speakers": curr_row["speakers"],
            "url": curr_row["url"] or default_url,
            "img_src": curr_row["img_src"],
            "img_style": curr_row["img_style"],
            "img_style_mobile": curr_row["img_style_mobile"]
        }
    return {
        "date_string": "-",
        "speakers": "-",
        "url": default_url
    }


def add_unsubscribe_request(email: str):
    row = {'email': email}
    db.add_row('unsubscribe_requests', None, None, row)


def get_unsubscribe_request(email: str):
    return db.read_one('SELECT 1 from unsubscribe_requests WHERE email=%s', (email,))


def remove_unsubscribe_request(email: str):
    return db.delete_row('unsubscribe_requests', 'email=%s', (email,))


def validate_signup_token(signup_token: str):
    signup_token_info = db.read_one('SELECT * from signup_tokens WHERE signup_token=%s', (signup_token,))
    if not signup_token_info or \
       (signup_token_info['expires_at'] and signup_token_info['expires_at'] < datetime.datetime.now(pytz.utc)) or \
       (signup_token_info['signup_limit'] and signup_token_info['signup_limit'] <= signup_token_info['signup_count']):
        return False
    db.update_table_entry_where('signup_tokens', {'signup_token': signup_token}, {'signup_count': signup_token_info['signup_count'] + 1})
    return True


def get_supported_regions(service: str = None):
    where = ''
    where_args = []
    if service:
        where = ' WHERE cloud=%s'
        where_args = [service]
    return db.read('SELECT * FROM supported_clouds' + where, (*where_args,))


def select_organization_region(organization_id: int, service: str, region: str):
    cloud_region = db.read_one('SELECT cluster_name, global_default FROM supported_clouds WHERE status=%s AND cloud=%s AND region=%s',
                               ('supported', service, region))
    if not cloud_region:
        raise exceptions.InvalidParameterError('Service(Region)', f'{service}({region})', detail='This region is not yet supported')
    update_organization(organization_id, {'cluster_name': None if cloud_region['global_default'] else cloud_region['cluster_name']})


def get_cloud_from_cluster(cluster_name: str):
    if not cluster_name:
        return db.read_one('SELECT region, cloud FROM supported_clouds WHERE global_default=1')
    return db.read_one('SELECT region, cloud FROM supported_clouds WHERE cluster_name=%s', (cluster_name,))


def get_signup_token_plans(signup_token: str):
    return db.read_one('SELECT billing_plan, pricing_plan, promotion from signup_tokens WHERE signup_token=%s', (signup_token,))


def get_promotion_value(promotion: str):
    return db.read_one('SELECT promotion, train, inference, batch, credit_expires_at as expires_at FROM promotion_credits ' +
                       'WHERE promotion=%s AND (expires_at=%s OR expires_at>%s)',
                       (promotion, '0000-00-00 00:00:00', datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))


def add_promotion_value(organization_id: int, promotion: str):
    promotion_values = get_promotion_value(promotion)
    if promotion_values:
        promotion_values['organization_id'] = organization_id
        if not promotion_values['expires_at']:
            promotion_values.pop('expires_at')
        db.add_row('organization_credits', None, None, promotion_values)


def update_promotion_value(organization_id: int, updates: dict):
    db.update_table_entry('organization_credits', 'organization_id', organization_id, updates)


def list_deployments(project_id: int, skip_translate=False, dict_results=False):
    query = 'SELECT * FROM deployments JOIN deployment_instances ON (deployments.deployment_instance_id=deployment_instances.deployment_instance_id) WHERE project_id=%s'
    params = [project_id]

    deployment_list = read_instances(query, Deployment, params, skip_translate=skip_translate, dict_results=dict_results)

    if deployment_list:
        for deployment in deployment_list:
            model_instance_id = get_base_table_attr(deployment, 'deployment_instance', 'model_instance', 'model_instance_id')
            try:
                metrics = get_deployment_model_metrics(model_instance_id)
                if dict_results:
                    deployment['metrics'] = metrics
                else:
                    deployment.metrics = metrics
            except Exception:
                pass
    return deployment_list


def start_batch_prediction(batch_prediction_id: int):
    from pipeline import batch_predict
    batch_predict.BatchPredict().initialize_task_db_state(batch_prediction_id)


def create_batch_prediction(deployment_id: int, input_location: str = None, output_location: str = None, name: str = None, model_instance_id: int = None, serving_dataset_instance_group_id: int = None):
    deployment = get_deployment(deployment_id)
    name = name if name else get_default_name('batch_prediction', deployment.model.get_id())
    values = {'deployment_id': deployment_id,
              'model_instance_id': model_instance_id or deployment.deployment_instance.model_instance.get_id(),
              'lifecycle': BatchPredictionLifecycle.PENDING,
              'internal_input': not input_location,
              'internal_output': not output_location,
              'name': name}
    if serving_dataset_instance_group_id:
        values['serving_dataset_instance_group_id'] = serving_dataset_instance_group_id

    project = get_project(deployment.project.get_id())
    problem_type = get_problem_type(project.problem_type)
    default_output_type = problem_type.batch_prediction_output_type()

    if output_location:
        values['output_location'] = output_location
    if input_location:
        values['data_source'] = {'location': input_location}
    else:
        if problem_type.disable_full_batch_prediction():
            raise exceptions.InvalidRequest(f'inputLocation is required for batch predictions in use case: {project.use_case.upper()}')
    instance = create_instance(BatchPrediction, values)
    if not output_location:
        organization_id = db.get_single_value('SELECT organization_id FROM project_owners WHERE project_id=%s', (project.get_id(),))
        updates = {'output_location': os.path.join(cloudartifacts.get_batch_prediction_directory(organization_id, instance.batch_prediction_id, create=True), f'predictions.{default_output_type}')}
        update_instance(BatchPrediction, instance.get_id(), updates)
    start_batch_prediction(instance.get_id())
    return instance


def create_batch_prediction_from_file(deployment_id: int, data: io.BytesIO, name: str = None):
    deployment = get_deployment(deployment_id)
    if not name:
        name = get_model(deployment.model.get_id()).name + ' Batch'
    values = {'deployment_id': deployment_id,
              'model_instance_id': deployment.deployment_instance.model_instance.get_id(),
              'internal_input': True,
              'internal_output': True,
              'name': name,
              'lifecycle': BatchPredictionLifecycle.UPLOADING}
    instance = create_instance(BatchPrediction, values)
    batch_prediction_id = instance.get_id()
    organization_id = db.get_single_value('SELECT organization_id FROM project_owners WHERE project_id=%s', (deployment.project.get_id(),))
    batch_pred_dir = cloudartifacts.get_batch_prediction_directory(organization_id, instance.batch_prediction_id, create=True)
    input_location = cloud.CloudLocation(os.path.join(batch_pred_dir, 'input'))
    input_location.write_bytes_to_file(data.read())

    project = get_project(deployment.project.get_id())
    problem_type = get_problem_type(project.problem_type)
    default_output_type = problem_type.batch_prediction_output_type()

    updates = {
        'data_source': json.dumps({'location': input_location.location}),
        'output_location': os.path.join(batch_pred_dir, f'predictions.{default_output_type}'),
        'lifecycle': BatchPredictionLifecycle.PENDING
    }
    update_instance(BatchPrediction, batch_prediction_id, updates)
    start_batch_prediction(batch_prediction_id)
    return instance


def get_batch_prediction(batch_prediction_id: int, skip_translate=False, dict_results=False):
    return read_one_instance('SELECT * FROM batch_predictions WHERE batch_prediction_id=%s',
                             BatchPrediction, (batch_prediction_id,), skip_translate=skip_translate, dict_results=dict_results)


def list_batch_predictions(deployment_id: int, skip_translate=False, dict_results=False):
    return read_instances('SELECT * FROM batch_predictions WHERE deployment_id=%s',
                          BatchPrediction, (deployment_id,), skip_translate=skip_translate, dict_results=dict_results)


def cancel_batch_prediction(batch_prediction_id: int):
    return update_instance(BatchPrediction, batch_prediction_id, {'lifecycle': BatchPredictionLifecycle.CANCELLED})


def delete_batch_prediction(batch_prediction_id: int):
    delete_instance(BatchPrediction, batch_prediction_id)


def get_deployment_model_metrics(model_instance_id: int):
    metrics = get_model_instance_metrics(model_instance_id=model_instance_id)
    metric_vals = {key: value for key, value in metrics['metrics'].items() if metrics['deployment_display'].get(key)}
    metric_names = [metric_name for metric_name in metrics['metric_names'] if metrics['deployment_display'].get(next(iter(metric_name)))]
    return {'metrics': metric_vals,
            'metric_names': metric_names}


def list_deployment_instances(deployment_id: int, skip_translate=False, dict_results=False):
    query = 'SELECT * FROM deployment_instances WHERE deployment_id=%s'
    params = [deployment_id]

    return read_instances(query, DeploymentInstance, params, skip_translate=skip_translate, dict_results=dict_results)


def get_serving_dataset_instance_infos(serving_dataset_instance_group_id: int):
    serving_dataset_instance_group = db.read_one('SELECT project_id, dataset_instance_ids FROM serving_dataset_instance_groups WHERE serving_dataset_instance_group_id=%s', (serving_dataset_instance_group_id,))
    if not serving_dataset_instance_group:
        raise Exception(f'Unknown serving dataset instance group id: {serving_dataset_instance_group_id}')
    project_id = serving_dataset_instance_group['project_id']
    dataset_instances = serving_dataset_instance_group['dataset_instance_ids']
    return _get_dataset_instance_infos(project_id, dataset_instances)


def get_dataset_instance_infos(dataset_instance_group_id: int):
    dataset_instance_group = db.read_one('SELECT project_id, dataset_instance_ids FROM dataset_instance_groups WHERE dataset_instance_group_id=%s', (dataset_instance_group_id,))
    if not dataset_instance_group:
        raise Exception(f'Unknown dataset instance group id: {dataset_instance_group_id}')
    project_id = dataset_instance_group['project_id']
    dataset_instances = dataset_instance_group['dataset_instance_ids']
    return _get_dataset_instance_infos(project_id, dataset_instances)


def get_dataset_instance_infos_for_project(project_id: int):
    rows = db.read('SELECT dataset_id FROM project_datasets WHERE project_id = %s AND lifecycle=%s', (project_id, ProjectDatasetLifecycle.ACTIVE.value))
    if rows:
        dataset_ids = [row['dataset_id'] for row in rows]
        rows = db.read('SELECT MAX(dataset_instance_id) AS dataset_instance_id FROM dataset_instances WHERE dataset_id IN (' + ', '.join(['%s'] * len(dataset_ids)) + ') GROUP BY dataset_id', dataset_ids)
        dataset_instance_ids = [row['dataset_instance_id'] for row in rows]
        return _get_dataset_instance_infos(project_id, dataset_instance_ids)
    return {}


def _get_dataset_instance_infos(project_id: int, dataset_instance_ids: List[int]) -> List[DatasetInstanceInfo]:
    datasets = db.read('SELECT project_dataset_type, project_datasets.data_usage_config, dataset_instances.location, dataset_instances.schema_values, dataset_instances.file_format FROM dataset_instances JOIN datasets USING (dataset_id) JOIN project_datasets ON (datasets.dataset_id=project_datasets.dataset_id) WHERE dataset_instance_id in (' + ', '.join(['%s'] * len(dataset_instance_ids)) + ') AND project_id=%s AND location IS NOT NULL', (*dataset_instance_ids, project_id)) or []
    dataset_instance_infos = []
    for dataset in datasets:
        data_usage_config = (dataset['data_usage_config'] or {})
        schema = data_usage_config.get('schema')
        instance_schema = (dataset['schema_values'] or {})
        dataset_instance_infos.append(DatasetInstanceInfo(ProjectDatasetType(dataset['project_dataset_type']),
                                                          location=dataset['location'],
                                                          file_format=dataset.get('file_format'),
                                                          columns=apply_schema_overrides(schema, data_usage_config.get('user_overrides')),
                                                          num_rows=instance_schema.get('row_count'),
                                                          delimiter=instance_schema.get('delimiter'),
                                                          encoding=instance_schema.get('encoding')))
    return dataset_instance_infos


def get_resolved_schema(project_id: int, dataset_id: int):
    data_usage_config = read_single_value_where('data_usage_config', ProjectDataset, project_id=project_id, dataset_id=dataset_id) or {}
    schema = data_usage_config.get('schema') or data_usage_config.get('fields')
    return apply_schema_overrides(schema, data_usage_config.get('user_overrides'))


def apply_schema_overrides(schema: list, overrides: dict):
    if not schema:
        return []
    if not overrides:
        return schema
    for col in schema:
        if col['name'] in overrides:
            col['data_use'] = overrides[col['name']].get('data_use', col.get('data_use'))
            col['data_type'] = overrides[col['name']].get('data_type', col['data_type'])
    return schema


def validate_project_datasets(project_id: int, ignore_dataset_processing: bool = False):
    project = get_project(project_id)
    project_datasets = db.read('SELECT dataset_instances.lifecycle, project_dataset_type, data_usage_config, datasets.dataset_id dataset_id, name, ui_wizard_state, dataset_instances.schema_values schema_values, inspecting_completed_at, source_type FROM project_datasets LEFT JOIN datasets USING (dataset_id) LEFT JOIN dataset_instances ON dataset_instances.dataset_instance_id = (SELECT MAX(dataset_instance_id) FROM dataset_instances di WHERE di.dataset_id = datasets.dataset_id)  WHERE project_datasets.lifecycle="ACTIVE" AND project_id=%s', (project_id,)) or []

    result = {'valid': True, 'required_datasets': [], 'optional_datasets': [], 'confirmed': True, 'error': []}
    data_use_id_columns = {}
    dataset_types = get_data_use_dataset_types(project.use_case)

    problem_type = get_problem_type(project.problem_type)
    problem_type_data_validations = problem_type.validate_datasets(project_datasets)
    project_columns = {}

    # fix for having batch + streaming of the same type by ignoring the streaming dataset
    dataset_by_type = {}
    for dataset in project_datasets[:]:
        dataset_type = dataset['project_dataset_type']
        if dataset_type in dataset_by_type:
            if dataset['source_type'] == SourceType.STREAMING:
                project_datasets.remove(dataset)
            else:
                project_datasets.remove(dataset_by_type[dataset_type])
        dataset_by_type[dataset_type] = dataset

    for project_dataset_type, dataset_type_requirements in dataset_types.items():
        required_dataset = dataset_type_requirements.get('required')
        dataset_type = ProjectDatasetType(project_dataset_type)
        project_dataset = next((pd for pd in project_datasets if pd['project_dataset_type'] == dataset_type), None)
        required_data_uses = [ValueDataUse(data_use) for data_use, data_use_desc in get_project_dataset_column_types(project.use_case, project_dataset_type).items() if not data_use_desc['optional']]
        dataset_validation = {'name': None,
                              'uploaded': False,
                              'dataset_type': dataset_type,
                              'required_columns': {data_use: False for data_use in required_data_uses},
                              'invalid_columns': [],
                              'data_validations': []}

        dataset_is_processing = ignore_dataset_processing and project_dataset and project_dataset.get('lifecycle') in [DatasetLifecycle.IMPORTING, DatasetLifecycle.UPLOADING, DatasetLifecycle.INSPECTING]

        if dataset_is_processing:
            continue
        elif not project_dataset:
            if required_dataset:
                result['valid'] = False
                result['error'].append(ProjectValidationError('MISSING_REQUIRED_DATASET', "Missing required dataset '{dataset}'.", dataset=dataset_type))
        elif not project_dataset['data_usage_config'] or project_dataset.get('schema'):
            result['valid'] = False
            result['error'].append(ProjectValidationError('MISSING_SCHEMA', "Missing schema for dataset '{dataset}'.", dataset=dataset_type))
            dataset_validation['status'] = get_latest_dataset_instance(project_dataset['dataset_id']).lifecycle.value
            continue
        else:

            dataset_validation['name'] = project_dataset['name']
            schema = project_dataset['data_usage_config'].get('schema') or project_dataset['data_usage_config'].get('fields')
            dataset_validation['uploaded'] = True
            dataset_validation['dataset_id'] = hash_id('dataset_id', project_dataset['dataset_id'])
            if project_dataset['source_type'] == SourceType.STREAMING:
                dataset_validation['required_columns'].update({col_data_use: True for col_data_use in dataset_validation['required_columns']})
                result['required_datasets' if required_dataset else 'optional_datasets'].append(dataset_validation)
                continue
            for col in apply_schema_overrides(schema, project_dataset['data_usage_config'].get('user_overrides', {})):
                column_name = col['name']
                col_data_use = col.get('data_use') and ValueDataUse(col['data_use'])
                if col_data_use in dataset_validation['required_columns']:
                    if col_data_use in data_use_id_columns and data_use_id_columns[col_data_use]['name'] != column_name:
                        result['valid'] = False
                        result['error'].append(ProjectValidationError("COLUMN_MISMATCH",
                                                                      "Column '{column_name}' in Dataset '{dataset}' with column mapping '{column_mapping}' does not match the column name of '{other_dataset_column_name}' found in Dataset '{other_dataset}'.",
                                                                      dataset=dataset_type,
                                                                      column_name=column_name,
                                                                      data_use=col_data_use,
                                                                      other_dataset=data_use_id_columns[col_data_use]['dataset'],
                                                                      other_dataset_column_name=data_use_id_columns[col_data_use]['name']))
                        dataset_validation['invalid_columns'].append({column_name: f"This column's name (\"{column_name}\") does not match the column name with the same mapping found in dataset: (\"{data_use_id_columns[col_data_use]['name']}\")"})
                    data_use_id_columns[col_data_use] = {'name': column_name, 'dataset': dataset_validation['name']}
                    dataset_validation['required_columns'][col_data_use] = True
                if column_name in project_columns and (not col_data_use or not col_data_use.value.endswith('_key') or project_columns[column_name]['data_use'] != col_data_use):
                    result['valid'] = False
                    result['error'].append(ProjectValidationError("DUPLICATE_COLUMN",
                                                                  "Column '{column_name}' in Dataset '{dataset}' has a duplicate column in dataset '{other_dataset}'. Only ID columns can share the same column name.",
                                                                  column_name=column_name,
                                                                  dataset=dataset_type,
                                                                  other_dataset=project_columns[column_name]['dataset']))
                project_columns[column_name] = {'dataset': dataset_type, 'data_use': col_data_use}
            if not all(dataset_validation['required_columns'].values()):
                result['valid'] = False
                missing_required_columns = [column.value for column in dataset_validation['required_columns'] if dataset_validation['required_columns'][column] is False]
                result['error'].append(ProjectValidationError("MISSING_REQUIRED_COLUMNS", "Missing required columns {columns} in dataset '{dataset}'", dataset=dataset_type, columns=missing_required_columns))

            confirmed = (len((project_dataset.get('ui_wizard_state') or {}).get('confirm', [])) > 0)
            dataset_validation['confirmed'] = confirmed
            if not confirmed:
                result['confirmed'] = False
            data_validation = problem_type_data_validations.get(project_dataset['dataset_id'], {})
            dataset_validation.update(data_validation)
            if dataset_validation['data_validations']:
                result['error'].extend(dataset_validation['data_validations'])
                result['valid'] = False
        result['required_datasets' if required_dataset else 'optional_datasets'].append(dataset_validation)
    if result.get('error'):
        organization = db.read_one('SELECT organization_id, organizations.name FROM organizations JOIN project_owners USING (organization_id) WHERE project_id=%s', (project_id,))
        if environment.get_config_from_env().endswith('prod') and any([pd['inspecting_completed_at'] and pd['inspecting_completed_at'].replace(tzinfo=None) > (datetime.datetime.utcnow() - datetime.timedelta(minutes=1)) for pd in project_datasets]):
            errors_string = '\n'.join(e.to_sentence(get_project_dataset_column_types(project.use_case), get_dataset_type_translations(project.use_case)) for e in result['error'] if 'MISSING' not in e.error['error'])
            dataset_instance_count = db.get_single_value('SELECT COUNT(dataset_instance_id) FROM dataset_instances WHERE dataset_id IN (' + ', '.join(str(pd['dataset_id']) for pd in project_datasets) + ')')
            if errors_string and dataset_instance_count == len(project_datasets) and any(error.error['type'] == ProjectErrorType.DATA for error in result['error']):  # Only including first time uploads in email blast
                send_email.send_error_email(f'Project Validation Error: {project_id}',
                                            f"Organization: {organization['name']} ({organization['organization_id']})\n" +
                                            f'Project: {project.name} ({project_id})\n' +
                                            'Datasets: ' + ', '.join([f"{pd['name']} ({pd['dataset_id']})" for pd in project_datasets]) +
                                            '\n\n' + errors_string)
    return result


def get_dataset_type_translations(use_case: str):
    translations = {internal_type: desc['dataset_type'] for internal_type, desc in get_use_case_schema(use_case).items() if internal_type != 'list'}
    # Allow for join tables for all use cases. Only used in personalization in a undocumented way at the moment.
    if 'table' not in translations:
        translations['table'] = 'CUSTOM_TABLE'
    return translations


def get_next_name_number(potential_name, names):
    largest_number = 0
    match_regex = re.compile('^' + potential_name + ' (\d+)$')
    for name in names:
        if potential_name == name:
            largest_number = max(largest_number, 1)
            continue
        match = match_regex.match(name)
        if match and match.groups():
            largest_number = max(int(match.groups()[0]) + 1, largest_number)
    return largest_number


def get_default_name(creation_type: str, input_id: any):
    if creation_type == 'model':
        potential_name = read_single_value('name', Project, input_id) + ' Model'
        models = db.read('SELECT name FROM models where project_id=%s', (input_id,)) or []
        name_number = get_next_name_number(potential_name, [model['name'] for model in models])
        if name_number:
            potential_name = f'{potential_name} {name_number}'
        return potential_name
    elif creation_type == 'batch_prediction':
        return read_single_value('name', Model, input_id) + ' Batch'
    elif creation_type == 'deployment':
        model = get_model(input_id)
        potential_name = model.name + ' Deployment'
        deployments = db.read('SELECT name FROM deployments where project_id=%s', (model.project.get_id(),)) or []
        name_number = get_next_name_number(potential_name, [deployment['name'] for deployment in deployments])
        if name_number:
            potential_name = f'{potential_name} {name_number}'
        return potential_name
    return 'Untitled'


def start_automl(project_id: int, training_config: dict = None, retrain_model_id: int = None, name: str = None,
                 run_locally: bool = False, skip_validation: bool = False, dataset_instance_ids: List[int] = None,
                 dataset_instance_group_id: int = None, deployable_only: bool = False, baseline_only: bool = False):
    project_dataset_validation = validate_project_datasets(project_id)
    model_ids = []
    algos = []
    deployable_model = None
    new_model_instance_ids = []

    if retrain_model_id:
        deployable_model = get_model(retrain_model_id)
        curr_model_config = deployable_model.model_config or {}
        if training_config is None:
            training_config = curr_model_config

        if training_config != curr_model_config:
            logging.info(f'Updating model_config for model: {retrain_model_id} to new instance config: {training_config}')
            db.update_table_entry('models', 'model_id', retrain_model_id, {'model_config': training_config})

        if not baseline_only:
            model_ids.append(retrain_model_id)
            algos.append(deployable_model.algorithm)
        if not deployable_only or baseline_only:
            baseline_models = db.read('SELECT model_id, algorithm from models WHERE primary_model_id = %s', (retrain_model_id,))
            if baseline_models:
                algos.extend([model['algorithm'] for model in baseline_models])
                model_ids.extend([model['model_id'] for model in baseline_models])
    if not skip_validation and not project_dataset_validation['valid']:
        raise exceptions.ConflictError("Cannot begin training due to dataset validation error(s)", extra_data={'errors': project_dataset_validation['error']})

    dataset_instance_ids = dataset_instance_ids or get_dataset_instance_ids_for_project(project_id)
    problem_type_str = read_single_value('problem_type', Project, project_id)
    problem_type = get_problem_type(problem_type_str)

    if not dataset_instance_group_id:
        dataset_instance_group = add_dataset_instance_group(project_id=project_id, dataset_instances=dataset_instance_ids, training_config=training_config)
        dataset_instance_group_id = dataset_instance_group.get_id()

    # NOTE: order of model_type_instance_ids has to match the output order of model_types
    # Figure out the model_ids to associate new model_instances to
    primary_model_id = None
    if not deployable_model:  # creating new models
        for (algo, algo_name, deployable) in problem_type.get_algorithms(training_config):
            if deployable_only and not deployable:
                continue
            algos.append(algo)
            new_model = {
                'project_id': project_id,
                'algorithm': algo,
                'name': name if deployable else algo_name,
                'model_config': json.dumps(training_config)
            }
            if not deployable:
                new_model['primary_model_id'] = primary_model_id
            model = create_instance(Model, new_model)
            model_ids.append(model.get_id())
            if deployable_model is None and deployable:
                deployable_model = model
                primary_model_id = model.get_id()

    # Create the new model_instances:
    model_instance_id_algos = []
    for model_id, algo in zip(model_ids, algos):
        new_model_instance = {
            'model_id': model_id,
            'algorithm': algo,
            'dataset_instance_group_id': dataset_instance_group_id,
            'lifecycle': ModelLifecycle.PENDING,
            'model_config': json.dumps(training_config)
        }
        model_instance = create_instance(ModelInstance, new_model_instance)
        new_instance_id = model_instance.get_id()
        new_model_instance_ids.append(new_instance_id)
        model_instance_id_algos.append((new_instance_id, algo))
        if deployable_model.algorithm == algo:
            deployable_model.model_instance = model_instance

    # Setup DB state for workflow.
    from pipeline import ml_pipeline
    mlp = ml_pipeline.PipelineRunner(problem_type_str, dataset_instance_group_id, model_instance_id_algos, run_locally=run_locally)
    mlp.initialize_workflow_db_state()

    return deployable_model, new_model_instance_ids


def create_model_from_files(project_id: int, organization_id: int, model_data: io.BytesIO, embeddings_data: io.BytesIO, verifications: io.BytesIO, name: str = None):
    if not name:
        name = get_default_name('model', project_id)
    values = {
        'project_id': project_id,
        'name': name,
        'algorithm': 'custom'
    }
    model = create_instance(Model, values)
    model.model_instance = create_model_instance_from_files(model.get_id(), organization_id, model_data, embeddings_data, verifications)
    return model


def create_model_instance_from_files(model_id: int, organization_id: int, model_data: io.BytesIO, embeddings_data: io.BytesIO, verifications: io.BytesIO):
    instance_values = {
        'model_id': model_id,
        'lifecycle': ModelLifecycle.UPLOADING,
        'algorithm': 'custom',
        'dataset_instance_group_id': 0  # TODO: Will likely need to create one...
    }
    model_instance = create_instance(ModelInstance, instance_values)
    # From model instance we get the model path and store in a sub-directory in that path. We will rely
    # on the pipelin to arrange the artifacts into the appropriate locations
    model_dir = os.path.join(cloudartifacts.get_model_artifacts_directory(organization_id, model_instance.get_id()), 'upload')
    model_loc = cloud.CloudLocation(os.path.join(model_dir, 'model.tgz'))
    model_loc.write_bytes_to_file(model_data.read())
    embeddings_loc = cloud.CloudLocation(os.path.join(model_dir, 'embeddings.csv'))
    embeddings_loc.write_bytes_to_file(embeddings_data.read())
    verifications_loc = cloud.CloudLocation(os.path.join(model_dir, 'verifications.jsonl'))
    verifications_loc.write_bytes_to_file(verifications.read())
    return model_instance


def how_it_works_process(row: dict, is_solutions=False):
    how_it_works_field = 'how_it_works_solution' if is_solutions else 'how_it_works'

    if row and row.get(how_it_works_field) and row.get(how_it_works_field) != '':
        list_how = row.get(how_it_works_field).split('|||')
        res = []
        for item in list_how:
            use_case = row.get('use_case')
            title1 = None

            if '###' in item:
                ss = item.split('###')
                if len(ss) == 3:
                    use_case = ss[0]
                    title1 = ss[1]
                    item = ss[2]
                elif len(ss) == 2:
                    title1 = ss[0]
                    item = ss[1]
                elif len(ss) > 0:
                    item = ss[-1]
                else:
                    continue

            if item[-1:] == 's':
                res.append({'index': item[:-1], 'run': True, 'title': title1 or '', 'use_case': use_case})
            else:
                res.append({'index': item, 'run': False, 'title': title1 or '', 'use_case': use_case})

        how_it_works_processed_field = 'how_it_works_processed_solution' if is_solutions else 'how_it_works_processed'
        row[how_it_works_processed_field] = res
    return row


def get_use_case_documentation():
    use_case_documentation = get_use_case_documentation_yml()
    use_cases = {use_case: get_use_case_yml(use_case)
                 for use_case, data in get_all_use_cases_yml().items()
                 if data and not data.get('hidden') and data['info']}
    return {use_case: {'name': val['info']['real_name'],
                       'prediction_api': val.get('prediction_api', 'predict'),
                       'model_metrics': [{'key': key, **metric} for key, metric in use_case_documentation['metrics'].items() if key in use_case_documentation['use_cases'][use_case]['documentation'].get('metrics', [])],
                       'training': [option for key, option in use_case_documentation['training_options'].items() if key in use_case_documentation['use_cases'][use_case]['documentation'].get('training_options', [])],
                       'advanced_training': [option for key, option in use_case_documentation['training_options'].items() if key in use_case_documentation['use_cases'][use_case]['documentation'].get('advanced_training_options', [])],
                       'datasets': [dataset for key, dataset in val['info']['uiCustom']['schemas'].items() if key != 'list'],
                       **use_case_documentation['use_cases'][use_case]['documentation']}
            for use_case, val in use_cases.items()}


def get_prediction_examples(func):
    return get_use_case_documentation_yml()['prediction_apis'].get(func)


def get_web_use_case(name: str, show_hidden=False, force_show: List[str] = []):
    web_use_case_data = get_all_web_use_cases_yml()

    def update_use_case_legacy_fields(use_case_info: dict):
        updated_info = use_case_info.copy()
        updated_info['pretty_name_web'] = use_case_info.get('info').get('real_name')
        updated_info['web_name'] = use_case_info.get('info').get('real_name')
        if 'web_ui' in use_case_info:
            updated_info['how_it_works'] = use_case_info['web_ui']['how_it_works']
            updated_info['img_src'] = use_case_info['web_ui']['img_src']
            del updated_info['web_ui']
        return updated_info

    one_use_case = None
    for item in web_use_case_data:
        if item.get('url_name_use_case') == name and item.get('use_case'):
            one_use_case = get_use_case_yml(item.get('use_case'))
            if one_use_case:
                one_use_case = update_use_case_legacy_fields(one_use_case)
                c1 = item.copy()
                one_use_case.update(c1)
                one_use_case = how_it_works_process(how_it_works_process(one_use_case), True)
            break

    is_group = True
    use_case_name = name
    if one_use_case:
        is_group = False
        for item2 in web_use_case_data:
            if item2.get('use_case') == one_use_case.get('use_case') and (item2.get('use_case') in force_show or show_hidden or (not item2.get('hidden') and not one_use_case.get('hidden'))):
                use_case_name = item2.get('url_name')
                break

    group_use_cases = []
    if use_case_name:
        for item2 in web_use_case_data:
            one_use_case2 = get_use_case_yml(item2.get('use_case'))
            if item2.get('url_name') == use_case_name and (item2.get('use_case') in force_show or show_hidden or (not item2.get('hidden') and not one_use_case2.get('hidden'))):
                group_use_cases.append(item2.copy())

    if len(group_use_cases) == 0:
        group_use_cases = None
    else:
        for item in group_use_cases:
            use_case_info = get_use_case_yml(item.get('use_case'))
            if use_case_info:
                use_case_info = update_use_case_legacy_fields(use_case_info)
                item.update(use_case_info)

        group_use_cases = [how_it_works_process(how_it_works_process(row), True) for row in group_use_cases]
        group_use_cases.sort(key=lambda x: x.get('order_in_group'))

    return group_use_cases, one_use_case, is_group


def project_supports_streaming(project_id: int):
    use_case = db.get_single_value('SELECT use_case FROM projects WHERE project_id=%s', (project_id,))
    return get_use_case_yml(use_case)['info']['uiCustom'].get('streaming')


@cache.cached(time=10)
def get_prediction_deployment_info(deployment_id, auth_token=None):
    if not deployment_id:
        raise exceptions.InvalidParameterError('deployment_id', deployment_id)
    query = 'SELECT model_instance_id, deployment_instance_id, organization_id, deployment_instances.service_url, deployment_instances.cluster_name, use_case, problem_type, dataset_instance_group_id, algorithm, deployment_instances.lifecycle FROM deployments '
    query += 'JOIN projects USING (project_id) JOIN project_owners USING (project_id) JOIN deployment_instances USING (deployment_instance_id) JOIN model_instances USING (model_instance_id) '
    vals = (deployment_id,)
    if auth_token:
        query += 'JOIN deployment_auth_tokens USING (project_id) '
        vals += (auth_token,)
    query += 'WHERE deployments.deployment_id = %s '
    if auth_token:
        query += 'AND auth_token = %s'
    deployment_info = db.read_one(query, vals)
    if not deployment_info:
        raise exceptions.DataNotFoundError('Deployment', hash_id('deployment_id', deployment_id))
    if deployment_info['lifecycle'] in (DeploymentLifecycle.PENDING.value, DeploymentLifecycle.DEPLOYING.value):
        raise exceptions.NotReadyError('Deployment', 30)
    elif deployment_info['lifecycle'] != DeploymentLifecycle.ACTIVE.value:
        raise exceptions.FailedDependencyError('Requested deployment is not active')
    return deployment_info


def get_model_location(organization_id, model_instance_id, algorithm):
    return os.path.join(cloudartifacts.get_model_artifacts_directory(organization_id, model_instance_id), f'{algorithm}.model')


def get_prediction_schema(deployment_id, host):
    prediction_schema = {}
    model_instance_id = get_deployment(deployment_id, dict_results=True, skip_translate=True)['deployment_instance']['model_instance']['model_instance_id']
    model_instance = get_model_instance(model_instance_id, skip_translate=True, dict_results=True)
    if 'use_case' in model_instance['project']:
        project = model_instance['project']
    else:
        project = model_instance['model']['project']
    pred_fn_name, pred_args = get_use_case_prediction_api(project['use_case'], host)
    prediction_schema['prediction_api'] = pred_fn_name
    problem_type = get_problem_type(project['problem_type'])
    dataset_instance_infos = get_dataset_instance_infos_for_project(project['project_id'])
    prediction_schema = problem_type.get_prediction_input_schema(prediction_schema, dataset_instance_infos, pred_fn_name)
    return prediction_schema


def validate_prediction_input(caller, deployment_id, data, **kwargs):
    prediction_schema = get_prediction_schema(deployment_id, '')
    if caller != 'predict' and prediction_schema['prediction_api'] != caller:
        raise exceptions.InvalidRequest(f"Invalid request. Prediction API is {prediction_schema['prediction_api']}")
    input_type_map = {'string': (str, int), 'list': (list,), 'number': (int, float)}
    valid = True
    for field_name, field_description in prediction_schema['query_data_schema'].items():
        if field_name not in data and field_description['required']:
            valid = False
            break
        field_val = data[field_name]
        if (not field_val and field_val != 0):
            valid = False
        valid_type = False
        for allowed_type in input_type_map[field_description['type']]:
            if isinstance(field_val, allowed_type):
                valid_type = True
        valid = valid and valid_type
    for field_name in data:
        if field_name not in prediction_schema['query_data_schema']:
            valid = False
    if not valid:
        param_name = 'queryData' if caller not in ('predict', 'predict_raw') else 'data'
        raise exceptions.InvalidParameterError(param_name, data, f"Query data input schema: {prediction_schema['query_data_schema']}")


def make_prediction(deployment_id: int, deployment_auth_token: str, data, caller: str = 'predict', **kwargs):
    deployment_info = get_prediction_deployment_info(deployment_id, deployment_auth_token)
    model_instance_id = deployment_info['model_instance_id']

    if kwargs.get('enable_tracking'):
        kwargs['tracking_model_id'] = model_instance_id

    if isinstance(data, dict) or isinstance(data, list):
        data = json.dumps(data)
    model_location = get_model_location(deployment_info['organization_id'], model_instance_id, deployment_info['algorithm'])
    from modelserver import client
    return client.run_inference(deployment_info['deployment_instance_id'], deployment_info['service_url'], deployment_info['cluster_name'], model_location, deployment_info['dataset_instance_group_id'], data, **kwargs)


def make_prediction_for_ui(deployment_id: int, data: str, **kwargs):
    deployment_info = get_prediction_deployment_info(deployment_id)
    problem_type = get_problem_type(deployment_info['problem_type'])
    prediction_args, format_args = problem_type.split_prediction_format_args(kwargs)
    model_location = get_model_location(deployment_info['organization_id'], deployment_info['model_instance_id'], deployment_info['algorithm'])
    from modelserver import client
    prediction, augmented_input_data, actual, explanations = client.run_inference(deployment_info['deployment_instance_id'], deployment_info['service_url'], deployment_info['cluster_name'], model_location, deployment_info['dataset_instance_group_id'], data, **prediction_args)
    return problem_type.format_prediction_for_ui(deployment_info['deployment_instance_id'], deployment_info['service_url'], deployment_info['cluster_name'], deployment_info['dataset_instance_group_id'], augmented_input_data, prediction, actual, explanations, deployment_info['organization_id'], **format_args)


def append_dataset_data(dataset_id: int, timestamp: int, user_id: str, data: dict, **kwargs):
    response = utils.requests_retry_session().post(
        f'{environment.get_streaming_url()}/append',
        data=json.dumps({
            "dataset_id": str(dataset_id),
            "interactions": [{
                "key": user_id,
                "timestamp": timestamp,
                "data": data
            }]
        }))
    if response.status_code != 200:
        raise exceptions.NotReadyError('Dataset', 60)


def upsert_dataset_data(dataset_id: int, key: str, data: dict, **kwargs):
    response = utils.requests_retry_session().post(
        f'{environment.get_streaming_url()}/append',
        data=json.dumps({
            "dataset_id": str(dataset_id),
            "attributes": {
                "key": key,
                "data": data
            }
        }))
    if response.status_code != 200:
        raise exceptions.NotReadyError('Dataset', 60)


def record_interactions(deployment_id: int, deployment_auth_token: str, interactions: List[Any], **kwargs):
    deployment_info = get_prediction_deployment_info(deployment_id, deployment_auth_token)
    model_instance_id = deployment_info['model_instance_id']
    model_location = get_model_location(deployment_info['organization_id'], model_instance_id, deployment_info['algorithm'])
    from modelserver import client
    return client.record(
        deployment_info['deployment_instance_id'],
        deployment_info['service_url'],
        deployment_info['cluster_name'],
        model_location,
        deployment_info['dataset_instance_group_id'],
        interactions, **kwargs)


def get_config_flags(name: str, default_config: str):
    default_flags = db.get_single_value('SELECT info FROM config_flags WHERE name=%s', (default_config,)) or {}
    if name:
        config_flag_one = db.get_single_value('SELECT info FROM config_flags WHERE name=%s', (name,)) or {}
        default_flags.update(config_flag_one)
    return default_flags


def get_pricing(plan: str):
    sub_line_items = ['train', 'predictions', 'qps']
    return db.read('SELECT line_item, sub_line_item, item_rate, item_units_interval, item_units_type FROM pricing WHERE sub_line_item IN (' + ', '.join(['%s'] * len(sub_line_items)) + ') AND pricing_plan=%s', (*sub_line_items, plan,)) or []


def use_dev_billing(organization_id: int):
    org_info = read_single_value('info', Organization, organization_id) or {}
    return bool(org_info.get(Flags.USE_DEV_BILLING.value) or environment.get_test_run_id())


def get_historical_usage(organization_id: int, start_time: datetime.datetime, end_time: datetime.datetime):
    extra_where = ' '
    extra_where_args = []
    if start_time:
        extra_where += 'AND yyyy_mm_dd >= %s '
        extra_where_args.append(start_time.strftime('%Y_%m_%d'))
    if end_time:
        extra_where += 'AND yyyy_mm_dd <= %s '
        extra_where_args.append(end_time.strftime('%Y_%m_%d'))
    usage = db.read('SELECT yyyy_mm_dd, hh, line_item, total_units, total_price FROM billing.billing_log_day_hour WHERE organization_id=%s' + extra_where + 'ORDER BY yyyy_mm_dd, hh', (organization_id, *extra_where_args)) or []
    return [item for item in usage
            if not (start_time and item['yyyy_mm_dd'] == start_time.strftime('%Y_%m_%d') and item['hh'] <= start_time.strftime('%H')
                    or end_time and item['yyyy_mm_dd'] == end_time.strftime('%Y_%m_%d') and item['hh'] > end_time.strftime('%H'))
            ]  # need to exclude specific hours not excluded in query


def get_item_usage(organization_id: int, start_time: datetime.datetime, end_time: datetime.datetime, daily=False):
    extra_where = ' '
    extra_where_args = []
    if start_time:
        extra_where += 'AND start_time >= %s '
        extra_where_args.append(start_time)
    if end_time:
        extra_where += 'AND start_time <= %s '
        extra_where_args.append(end_time)
    query = 'SELECT date_format(start_time, \'%%Y_%%m_%%d\') bill_day, db_id, line_item, SUM(item_units) units, SUM(price) price, db_id_desc name, project_id, item_rate rate FROM billing.billing_log WHERE organization_id=%s ' + extra_where
    if daily:
        query += ' GROUP BY bill_day, db_id ORDER BY bill_day, db_id'
    else:
        query += ' GROUP BY db_id ORDER BY db_id'
    return db.read(query, (organization_id, *extra_where_args)) or []


def summarize_charges(organization_id: int, billing_period_start: datetime.datetime, billing_period_end: datetime.datetime):
    invoice_items = get_historical_usage(organization_id, billing_period_start, billing_period_end)
    summed_invoice_items = {}
    for item in invoice_items:
        timestamp = int(datetime.datetime.strptime(f"{item['yyyy_mm_dd']} {item['hh']}", '%Y-%m-%d %H').timestamp())
        summed_item = summed_invoice_items.setdefault(item['line_item'],
                                                      {'start': timestamp,
                                                       'end': timestamp,
                                                       'price': 0,
                                                       'units': 0})
        summed_item['start'] = min(summed_item['start'], timestamp)
        summed_item['end'] = max(summed_item['end'], timestamp)
        summed_item['price'] += item['total_price']
        summed_item['units'] += item['total_units']
    return summed_invoice_items


def get_organization_credits(organization_id: int):
    return db.read_one('SELECT train, inference, batch, expires_at FROM organization_credits WHERE organization_id=%s', (organization_id,))


def web_land_pages_by_url(url: str):
    if not url:
        return None

    page_one = db.read_one('SELECT * FROM web_landing_pages WHERE page=%s', (url,))
    if page_one:
        return page_one['info'] or {}
    return None


def validate_cron(cron: str, param_name: str = 'cron'):
    try:
        cron_obj = croniter(cron, ret_type=datetime.datetime)
        next_run_time = cron_obj.get_next()
        if cron_obj.expanded[0] == ['*']:
            raise exceptions.InvalidParameterError(param_name, cron, detail='Please specify a particular minute to run at')
        if cron_obj.expanded[1] == ['*']:
            raise exceptions.InvalidParameterError(param_name, cron, detail='Please specify a particular hour to run at')

        # simple check for frequency, limiting to only a few per day
        week = [0] * 7
        start = cron_obj.get_current()
        stop = start + datetime.timedelta(days=7)
        run_time = next_run_time
        while run_time < stop:
            week[run_time.weekday()] += 1
            run_time = cron_obj.get_next()
        daily_freq_limit = 5
        if max(*week) > daily_freq_limit:  # Limit to a few times per day
            raise exceptions.InvalidParameterError(param_name, cron, detail=f'Please limit the frequency to less than {daily_freq_limit + 1} times per day')

        return next_run_time
    except exceptions.BaseError:
        raise
    except Exception:
        raise exceptions.InvalidParameterError(param_name, cron)


def add_refresh_policy(organization_id: int, name: str, cron: str, refresh_type: str, project_id: int = None, dataset_ids: List[int] = None, model_ids: List[int] = None, deployment_ids: List[int] = None, discover_ids: bool = False):
    try:
        refresh_policy = RefreshPolicyType(refresh_type)
    except Exception:
        raise exceptions.InvalidParameterError('refreshType', refresh_type)
    if refresh_policy == RefreshPolicyType.DEPLOYMENT:  # Deployment only is not allowed, since we won't know which model to pull from
        raise exceptions.InvalidParameterError('refreshType', refresh_type)
    if refresh_policy in RefreshPolicyType.policies_with_serving_data() and not project_id:
        raise exceptions.InvalidParameterError('refreshType', refresh_type, detail='Cannot select this refreshType without specifying a project id')
    if project_id and discover_ids:
        project_resources = get_project_resource_ids(project_id)
        dataset_ids = project_resources['dataset_ids']
        model_ids = project_resources['model_ids']
        deployment_ids = project_resources['deployment_ids']
    else:
        if dataset_ids:
            num_owned = db.get_single_value(f'SELECT COUNT(1) FROM dataset_owners WHERE organization_id=%s AND dataset_id IN ({", ".join(["%s"] * len(dataset_ids))})', [organization_id] + dataset_ids)
            if len(dataset_ids) != num_owned:
                raise exceptions.DataNotFoundError('Dataset', [hash_id('dataset_id', val) for val in dataset_ids])
        # TODO: Add a check across model_ids and deployment_ids to make sure they are in the same project. And for deployment_ids, limit to only one model_id
        if model_ids:
            num_owned = db.get_single_value(f'SELECT COUNT(1) FROM project_owners JOIN models USING (project_id) WHERE organization_id=%s AND model_id IN ({", ".join(["%s"] * len(model_ids))})', [organization_id] + model_ids)
            if len(model_ids) != num_owned:
                raise exceptions.DataNotFoundError('Model', [hash_id('model_id', val) for val in model_ids])
        if deployment_ids:
            num_owned = db.get_single_value(f'SELECT COUNT(1) FROM project_owners JOIN deployments USING (project_id) WHERE organization_id=%s AND deployment_id IN ({", ".join(["%s"] * len(deployment_ids))})', [organization_id] + deployment_ids)
            if len(deployment_ids) != num_owned:
                raise exceptions.DataNotFoundError('Deployment', [hash_id('deployment_id', val) for val in deployment_ids])
    if not dataset_ids and not model_ids and not deployment_ids:
        raise exceptions.InvalidRequest('Must specify at least one of datasetIds, modelIds or deploymentIds')
    next_run_time = validate_cron(cron)
    new_instance = {
        'organization_id': organization_id,
        'name': name,
        'cron': cron,
        'refresh_type': refresh_type,
        'next_run_time': next_run_time
    }
    if project_id:
        new_instance['project_id'] = project_id
    for key, val in [('dataset_ids', dataset_ids), ('model_ids', model_ids), ('deployment_ids', deployment_ids)]:
        if val:
            new_instance[key] = json.dumps(val)
    return create_instance(RefreshPolicy, new_instance)


def delete_refresh_policy(refresh_policy_id: int):
    delete_instance(RefreshPolicy, refresh_policy_id)


def get_refresh_policy(refresh_policy_id: int):
    return read_one_instance('SELECT * FROM refresh_policies WHERE refresh_policy_id=%s',
                             RefreshPolicy, (refresh_policy_id,))


def get_refresh_pipeline_run(refresh_pipeline_run_id: int):
    return read_one_instance('SELECT * FROM refresh_pipeline_runs WHERE refresh_pipeline_run_id=%s',
                             RefreshPipelineRun, (refresh_pipeline_run_id,))


def list_refresh_policies(organization_id: int, dataset_ids: List[int] = None, deployment_ids: List[int] = None, model_ids: List[int] = None, strict_match: bool = False, policy_types: List[RefreshPolicyType] = None):
    ''' strict_match performs an and across multiple ids of the same type. Between say datasets and deployments, there is always an and.

    For example, for dataset_ids 2, 4, 6:
        strict_match = True -> must contain all 3 ids
        strict_match = False -> contain at least one of the ids
    '''
    query = 'SELECT * FROM refresh_policies WHERE organization_id=%s'
    vals = [organization_id]
    policy_types = set(policy_types if policy_types else RefreshPolicyType)
    json_func = 'JSON_OVERLAPS'
    if strict_match:
        json_func = 'JSON_CONTAINS'
    where_clauses = []
    if dataset_ids:
        where_clauses.append(f'{json_func}(%s, dataset_ids)')
        vals.append(json.dumps(dataset_ids))
        policy_types.intersection_update(RefreshPolicyType.policies_with_dataset())
    if deployment_ids:
        where_clauses.append(f'{json_func}(%s, deployment_ids)')
        vals.append(json.dumps(deployment_ids))
        policy_types.intersection_update(RefreshPolicyType.policies_with_deployment())
    if model_ids:
        where_clauses.append(f'{json_func}(%s, model_ids)')
        vals.append(json.dumps(model_ids))
        policy_types.intersection_update(RefreshPolicyType.policies_with_model())

    if where_clauses:
        query += f' AND {" AND ".join(where_clauses)} AND refresh_type IN ({", ".join(["%s"] * len(policy_types))})'
        vals.extend([policy.value for policy in policy_types])
    return read_instances(query, RefreshPolicy, vals)


def list_refresh_pipeline_runs(refresh_policy_id: int):
    return read_instances('SELECT * FROM refresh_pipeline_runs WHERE refresh_policy_id=%s',
                          RefreshPipelineRun, (refresh_policy_id,))


def update_refresh_policy(refresh_policy_id: int, name: str = None, cron: str = None):
    changes = {}
    if name:
        changes['name'] = name
    if cron:
        changes['cron'] = cron
        try:
            cron_obj = croniter(cron)
            changes['next_run_time'] = cron_obj.get_next(datetime.datetime)
        except Exception:
            raise exceptions.InvalidParameter('cron', cron)
    if changes:
        update_instance_where(RefreshPolicy, changes, refresh_policy_id=refresh_policy_id)
