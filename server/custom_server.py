#!/usr/bin/env python3

__author__ = "Igor Royzis"
__copyright__ = "Copyright 2023, Kinect Consulting"
__license__ = "Commercial"
__email__ = "iroyzis@kinect-consulting.com"

import logging
import json
import os
import pprint

from boto3.dynamodb.conditions import Attr

logger = logging.getLogger("server")
logger.setLevel(logging.INFO)


def example_data():
    return [{"name": "example"}]


def example_vpc_2():
    return [{
        "type": "Theia::Option",
        "label": "Yes",
        "value": "true"
    }, {
        "type": "Theia::Option",
        "label": "No",
        "value": "false"
    }]


def pp(d):
    if 'RAPIDCLOUD_TEST_MODE_AWS_EKS' in os.environ and os.environ.get('RAPIDCLOUD_TEST_MODE_AWS_EKS') == "true":
        print(pprint.pformat(d))


def module_eks_subnets(boto3_session, user_session, params):
    metadata_dict = module_eks_metadata(boto3_session, user_session, 'create_subnet', 'net')
    aws_dict = {}
    output_list = []
    ec2_client = boto3_session.client('ec2')

    try:
        f = [{'Name': 'tag:profile', 'Values': [user_session['env']]}]
        r = ec2_client.describe_subnets(Filters=f)
        for subnet in r['Subnets']:
            for tag in subnet['Tags']:
                if tag['Key'] == 'fqn':
                    aws_dict[tag['Value']] = subnet['SubnetId']
    except Exception as e:
        print(e)

    for fqn, subnet_name in metadata_dict.items():
        output_dict = {}
        label = f"{subnet_name} (not deployed yet)"
        if fqn in aws_dict.keys():
            label = f"{subnet_name} ({aws_dict[fqn]})"
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = label
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = subnet_name
        output_dict['value']['disableControls'] = ["vpc_id"]
        output_list.append(output_dict)
    return output_list


def module_eks_clusters(boto3_session, user_session, params):
    metadata_dict = module_eks_metadata(boto3_session, user_session, 'create_cluster', 'eks')
    output_list = []
    for fqn, cluster_name in metadata_dict.items():
        output_dict = {}
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = cluster_name
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = cluster_name
        output_list.append(output_dict)
    return output_list


def module_eks_compute_resources(boto3_session, user_session, params):
    metadata_dict = module_eks_metadata(boto3_session, user_session, 'create_cluster', 'eks')
    output_list = []
    for fqn, cluster_name in metadata_dict.items():
        output_dict = {}
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = cluster_name
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = cluster_name
        output_list.append(output_dict)
    return output_list


def module_eks_addon_version(boto3_session, user_session, params):
    # {
    #         "addons": [
    #                     "aws-ebs-csi-driver",
    #                     "coredns",
    #                     "kube-proxy",
    #                     "vpc-cni"
    #                 ]
    # }
    d = boto3_session.resource('dynamodb')
    try:
        cmdfilter = Attr('profile').eq(
            user_session["env"]) & Attr('command').eq('create_cluster') & Attr('eks_cluster_name').eq(params['v'])
        t = d.Table('metadata')
        r = t.scan(FilterExpression=cmdfilter)
        cluster_version = r['Items'][0]['params']['eks_eks_version']
    except Exception as e:
        print(e)

    addon_name = f"{params['a']}"
    eks_client = boto3_session.client('eks')
    r = eks_client.describe_addon_versions(kubernetesVersion=cluster_version, addonName=addon_name)
    output_list = []
    for v in r['addons'][0]['addonVersions']:
        output_dict = {}
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = v['addonVersion']
        output_dict['value']['value'] = v['addonVersion']
        output_dict['value']['type'] = "Theia::DataOption"
        if v['compatibilities'][0]['defaultVersion']:
            output_dict['value']['value'] = v['addonVersion']
            output_dict['label'] = f"{v['addonVersion']} (Default/Current)"
            output_list.insert(0, output_dict)
        else:
            output_list.append(output_dict)
    return output_list


def module_eks_versions(boto3_session, user_session, params):
    versions = list()
    output_list = list()
    eks_client = boto3_session.client('eks')
    try:
        r = eks_client.describe_addon_versions(addonName="coredns")
        for a in r['addons']:
            for v in a['addonVersions']:
                for c in v['compatibilities']:
                    if c['clusterVersion'] not in versions:
                        versions.append(c['clusterVersion'])
    except Exception as e:
        print(e)

    for v in sorted(versions)[-5:]:
        output_dict = {}
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = v
        output_dict['value']['value'] = v
        output_dict['value']['type'] = "Theia::DataOption"
        output_list.append(output_dict)
    return output_list


def format_eks_aws_auth_metadata(i):
    data = {}
    data['module'] = i['module']
    data['command'] = i['command']
    data['cmd_id'] = i['cmd_id']
    data['fqn'] = i['fqn']
    data['eks_name'] = i['resource_name']
    data['eks_cluster_name'] = i['params']['cluster_name']
    data['eks_fargate_profiles'] = i['params']['fargate_profiles']
    data['eks_node_groups'] = i['params']['node_groups']
    map_list = ['map_users_values', 'map_roles_values']
    for v in map_list:
        if v in i['params'].keys():
            data[f"eks_{v}"] = json.dumps(i['params'][v]).replace("\\", "")
        elif f"eks_{v}" in i['params'].keys():
            data[f"eks_{v}"] = i['params'][f"eks_{v}"].replace("\\", "")
        else:
            data[f"eks_{v}"] = []
    return data


def module_eks_aws_auth(boto3_session, user_session, params):
    metadata_list = []
    d = boto3_session.resource('dynamodb')
    try:
        cmdfilter = Attr('profile').eq(user_session["env"]) & Attr('command').eq('manage_aws_auth')
        t = d.Table('aws_infra')
        r = t.scan(FilterExpression=cmdfilter)
        for i in r['Items']:
            metadata_list.append(format_eks_aws_auth_metadata(i))
        while 'LastEvaluatedKey' in r:
            r = t.scan(FilterExpression=cmdfilter, ExclusiveStartKey=r['LastEvaluatedKey'])
            for i in r['Items']:
                metadata_list.append(format_eks_aws_auth_metadata(i))
    except Exception as e:
        print(e)
    return metadata_list


def module_eks_efs_filesystems(boto3_session, user_session, params):
    metadata_dict = module_eks_metadata(boto3_session, user_session, 'create', 'efs')
    output_list = []
    for fqn, fs_name in metadata_dict.items():
        output_dict = {}
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = fs_name
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = fs_name
        output_list.append(output_dict)
    return output_list


def module_eks_metadata(boto3_session, user_session, cmd, phase):
    # this is a generic function, it queries the aws_infra tables and filters results
    # based on "cmd"
    # when we create subnets, we give the user the option to create a route table
    # with the subnet OR use an existing subnet.
    # when we list route tables from our metadata we pass the `create_subnet` cmd
    # which means that some subnets will end up listed in the route table drop down
    # when `route_tables`is set to True we only include subnets if the `create_route_table`
    # is set to true
    metadata_dict = {}
    d = boto3_session.resource('dynamodb')
    try:
        cmdfilter = Attr('profile').eq(user_session["env"]) & Attr('command').eq(cmd) & Attr('phase').eq(phase)
        t = d.Table('aws_infra')
        r = t.scan(FilterExpression=cmdfilter)
        for i in r['Items']:
            metadata_dict[i['fqn']] = i['resource_name']

        while 'LastEvaluatedKey' in r:
            r = t.scan(FilterExpression=cmdfilter, ExclusiveStartKey=r['LastEvaluatedKey'])
            for i in r['Items']:
                metadata_dict[i['fqn']] = i['resource_name']
    except Exception as e:
        print(e)
    sorted_metadata_tuple = sorted(metadata_dict.items(), key=lambda x: x[1])
    sorted_metadata_dict = {k: v for k, v in sorted_metadata_tuple}
    return sorted_metadata_dict


def module_eks_vpcs(boto3_session, user_session, params):
    metadata_dict = module_eks_metadata(boto3_session, user_session, 'create_vpc', 'net')
    aws_dict = {}
    output_list = []
    ec2_client = boto3_session.client('ec2')

    try:
        f = [{'Name': 'tag:profile', 'Values': [user_session['env']]}]
        r = ec2_client.describe_vpcs(Filters=f)
        for vpc in r['Vpcs']:
            for tag in vpc['Tags']:
                if tag['Key'] == 'fqn':
                    aws_dict[tag['Value']] = vpc['VpcId']
    except Exception as e:
        print(e)

    for fqn, vpc_name in metadata_dict.items():
        output_dict = {}
        label = f"{vpc_name} (not deployed yet)"
        if fqn in aws_dict.keys():
            label = f"{vpc_name} ({aws_dict[fqn]})"
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = label
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = vpc_name
        output_list.append(output_dict)
    return output_list


def custom_endpoint(action, params, boto3_session, user_session):
    if action == "example":
        return example_data()
    elif action == "module_eks_subnets":
        return module_eks_subnets(boto3_session, user_session, params)
    elif action == "module_eks_clusters":
        return module_eks_clusters(boto3_session, user_session, params)
    elif action == "module_eks_addon_version":
        return module_eks_addon_version(boto3_session, user_session, params)
    elif action == "module_eks_versions":
        return module_eks_versions(boto3_session, user_session, params)
    elif action == "module_eks_aws_auth":
        return module_eks_aws_auth(boto3_session, user_session, params)
    elif action == "module_eks_efs_filesystems":
        return module_eks_efs_filesystems(boto3_session, user_session, params)
    elif action == "module_eks_vpcs":
        return module_eks_vpcs(boto3_session, user_session, params)
    else:
        return ["no such endpoint"]

    return []
