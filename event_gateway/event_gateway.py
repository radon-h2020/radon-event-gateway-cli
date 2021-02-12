import argparse
import json
import logging
import os
import subprocess
from getpass import getpass
from os import path
from pathlib import Path
from sys import executable
from time import sleep

from botocore.exceptions import ClientError

try:
    import boto3
    import botocore

    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
    pass

try:
    import azure.cli
except ImportError:
    HAS_AZURE_CLI = False
else:
    HAS_AZURE_CLI = True

env_path = os.getenv("HOME") + "/.config/eventgateway"


def init_aws_client(aws_access_key, aws_secret_key, region):
    client = boto3.client('lambda', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    return client


def get_zip_file(path):
    try:
        blob = Path(path)
        with open(blob, 'rb') as f:
            data = f.read()
    except Exception as results:
        data = ""
    return data


def update_function(client, function_name, runtime, handler,
                    role, memory_size, timeout, lambda_env,
                    zip_file):
    function_arn = ""
    api_params = dict(FunctionName=function_name, Role=role, Handler=handler,
                      MemorySize=memory_size, Timeout=timeout, Runtime=runtime)
    if lambda_env:
        api_params.update(Environment=dict(Variables={**lambda_env}))

    try:
        results = client.update_function_configuration(**api_params)
        function_arn = dict(results)['FunctionArn']
    except Exception as results:
        logging.debug(results)
    api_params = dict(FunctionName=function_name)

    if zip_file:
        data = get_zip_file(zip_file)
        api_params.update(ZipFile=data)
    try:
        results = client.update_function_code(**api_params)
    except Exception as results:
        logging.debug(results)
    return function_arn


def create_function(client, function_name, runtime, handler,
                    role, memory_size, timeout, lambda_env,
                    zip_file):
    api_params = dict(FunctionName=function_name, Role=role, Handler=handler,
                      MemorySize=memory_size, Timeout=timeout, Runtime=runtime)

    if lambda_env:
        api_params.update(Environment=dict(Variables={**lambda_env}))

    code = dict()
    if zip_file:
        data = get_zip_file(zip_file)
        code.update(ZipFile=data)

    api_params.update(Code={**code})

    try:
        results = client.create_function(**api_params)
        function_arn = dict(results)['FunctionArn']
    except client.exceptions._code_to_exception['ResourceConflictException'] as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            function_arn = update_function(client, function_name, runtime, handler,
                                           role, memory_size, timeout, lambda_env, zip_file)
    return function_arn


def execute_azure_command(azure_command, MAX_TRIES):
    response = ""
    try:
        for i in range(MAX_TRIES):
            p = subprocess.Popen(azure_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response = p.stdout.read()
            (stdout, stderr) = p.communicate()
            if stderr:
                print("Shell script gave some error...")
                print(stderr)
                sleep(3)
            else:
                break
    except Exception as e:
        logging.debug(e)
    return response


def main():
    parser = argparse.ArgumentParser()
    command_options = parser.add_subparsers(dest='command')

    generate_credentials = command_options.add_parser('configure-aws',
                                                      help='Configure credentials for user and service '
                                                           'applications.')
    generate_credentials = command_options.add_parser('configure-azure', help='Configure credentials for user and '
                                                                              'service applications.')

    args = parser.parse_args()
    if args.command == "configure-aws":
        try:
            os.mkdir(env_path)
        except Exception as e:
            logging.debug(e)

        setup_file = open(env_path + "/setup-gateway.sh", "w")
        print("Service is hosted on: \n 1. Different account \n 2. User account")
        accounts = input("Select an option (1 or 2):")

        setup_content = "#!/bin/sh\n"
        if accounts == "1":
            service_access = input("Service account access key:")
            service_secret = input("Service account secret key:")

            setup_content += "export AWS_ACCESS_KEY_ID=" + service_access + "\n"
            setup_content += "export AWS_SECRET_ACCESS_KEY=" + service_secret + "\n"
            user_access = input("User account access key:")
            user_secret = input("User account secret key:")
        else:
            user_access = input("User account access key:")
            user_secret = input("User account secret key:")

            setup_content += "export AWS_ACCESS_KEY_ID=" + user_access + "\n"
            setup_content += "export AWS_SECRET_ACCESS_KEY=" + user_secret + "\n"

        setup_content += "export AWS_USER_ACCESS_KEY=" + user_access + "\n"
        setup_content += "export AWS_USER_SECRET_KEY=" + user_secret + "\n"

        setup_file.write(setup_content)
        setup_file.close()
        exit(0)

    if args.command == "configure-azure":
        try:
            os.mkdir(env_path)
        except Exception as e:
            logging.debug(e)

        setup_file_azure = open(env_path + "/setup-gateway-azure.json", "w")
        print("Service is hosted on: \n 1. Different account \n 2. User account")
        accounts = input("Select an option (1 or 2):")
        data = {}
        if accounts == "1":
            service_username = input("Service account username:")
            service_password = getpass("Service account password:")
            data["service_username"] = service_username
            data["service_password"] = service_password

            user_username = input("User account username:")
            user_password = getpass("User account password:")

            data["user_username"] = user_username
            data["user_password"] = user_password
        else:
            user_username = input("User account username:")
            user_password = getpass("User account password:")

            data["service_username"] = user_username
            data["service_password"] = user_password

            data["user_username"] = user_username
            data["user_password"] = user_password

        json.dump(data, setup_file_azure)
        setup_file_azure.close()
        exit(0)

    print("If you need help with a parameter write 'h' and press enter to get more information.")
    source_provider = input("Source provider: ")
    if source_provider == "h":
        print("Name of the provider from where the event originates. Options: AWS, Azure")
        source_provider = input("Source provider: ")

    source_microservice = input("Source microservice: ")
    if source_microservice == "h":
        if source_provider == "AWS":
            print("Name of the microservice from where the event originates. Currently supported options: S3")
        if source_provider == "Azure":
            print("Name of the microservice from where the event originates. Currently supported options: container")
        source_microservice = input("Source microservice: ")

    destination_provider = input("Destination provider: ")
    if destination_provider == "h":
        print("Name of the provider where you want to send the event. Options: AWS, Azure")
        destination_provider = input("Destination provider: ")

    destination_microservice = input("Destination microservice: ")
    if destination_microservice == "h":
        if destination_provider == "AWS":
            print("Name of the microservice to intercepts the event. Currently supported options: lambda")
        if destination_provider == "Azure":
            print("Name of the microservice to intercepts the event. Currently supported options: Function")
        destination_microservice = input("Destination microservice: ")

    # --------------------------- Service Configuration ---------------------------
    if source_provider == "AWS":
        source_setup = [".", "." + env_path + "/setup-gateway.sh"]
        execute_azure_command(source_setup, 1)
        role_name = "RadonEventGatewayRole"
        client_acc_id_service = boto3.client("sts", aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                                             aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"])
        service_acc_id = client_acc_id_service.get_caller_identity()["Account"]

        role_arn = "arn:aws:iam::" + service_acc_id + ":role/" + role_name

        assume_role_document = get_zip_file("event_gateway/policy.json")
        logging.debug(assume_role_document)

        role_client = boto3.client('iam')
        try:
            response = role_client.create_role(RoleName=role_name,
                                               AssumeRolePolicyDocument=assume_role_document.decode("utf-8"),
                                               Description='Event gateway role')
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                logging.debug(e)

        client = init_aws_client(os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"],
                                 os.environ["AWS_REGION"])

        client_acc_id = boto3.client("sts", aws_access_key_id=os.environ["AWS_USER_ACCESS_KEY"],
                                     aws_secret_access_key=os.environ["AWS_USER_SECRET_KEY"])
        source_account_id = client_acc_id.get_caller_identity()["Account"]

        function_name = "connection_lambda_" + source_account_id
        lambda_runtime = "python3.6"
        lambda_handler = "connection_lambda.handler"
        lambda_timeout = 5
        lambda_memory = 128

        zip_file_path = "event_gateway/connection_lambda.zip"

        if destination_microservice == "Function":
            print("-----------Destination microservice information-----------")
            azure_function_endpoint = input("Azure function endpoint:")

            env_vars = {'AZURE_FUNCTION_ENDPOINT': azure_function_endpoint}
        else:
            # TODO: if endpoint is anything else than azure function
            env_vars = {}

        function_arn = create_function(client, function_name, lambda_runtime, lambda_handler, role_arn, lambda_memory,
                                       lambda_timeout, env_vars, zip_file_path)

        try:
            response = client.create_alias(
                FunctionName=function_name,
                Name='test',
                FunctionVersion='$LATEST',
            )
        except client.exceptions._code_to_exception['ResourceConflictException'] as e:
            if e.response['Error']['Code'] == 'ResourceConflictException':
                logging.debug(e)

        print("-------------Source microservice information-------------")

        if source_microservice == "S3":

            bucket_name = input("Bucket name: ")
            try:
                response = client.add_permission(
                    FunctionName=function_name,
                    StatementId='lambda_test_permission03',
                    Action='lambda:InvokeFunction',
                    Principal='s3.amazonaws.com',
                    Qualifier='test',
                    SourceArn='arn:aws:s3:::' + bucket_name,
                    SourceAccount=source_account_id,
                )
            except client.exceptions._code_to_exception['ResourceConflictException'] as e:
                if e.response['Error']['Code'] == 'ResourceConflictException':
                    logging.debug(e)

            # --------------------------- User Configuration ---------------------------

            s3 = boto3.resource('s3', aws_access_key_id=os.environ["AWS_USER_ACCESS_KEY"],
                                aws_secret_access_key=os.environ["AWS_USER_SECRET_KEY"])
            bucket_notification = s3.BucketNotification(bucket_name)
            try:
                response = bucket_notification.put(
                    NotificationConfiguration={'LambdaFunctionConfigurations': [
                        {
                            'LambdaFunctionArn': function_arn + ':test',
                            'Events': [
                                's3:ObjectCreated:*'
                            ],
                        },
                    ]})
            except Exception as e:
                print(e)
        elif source_microservice == "API Gateway":
            api_gateway = input("API gateway ID string: ")

            api_client = boto3.client('apigateway', aws_access_key_id=os.environ["AWS_USER_ACCESS_KEY"],
                                      aws_secret_access_key=os.environ["AWS_USER_SECRET_KEY"],
                                      region_name=os.environ["AWS_REGION"])

            try:
                # Parent id is the string in braces that shows up when you click on / path in the api
                resource_resp = api_client.create_resource(
                    restApiId=api_gateway,
                    parentId='8kuph9y5yh',
                    pathPart=function_name
                )
            except api_client.exceptions._code_to_exception['ConflictException'] as e:
                logging.debug(e)
                resource_resp = api_client.get_resource(
                    restApiId=api_gateway,
                    resourceId='8kuph9y5yh'
                )

            try:
                put_method_resp = api_client.put_method(
                    restApiId=api_gateway,
                    resourceId=resource_resp['id'],
                    httpMethod="POST",
                    authorizationType="NONE",
                    apiKeyRequired=True,
                )
            except api_client.exceptions._code_to_exception['ConflictException'] as e:
                logging.debug(e)

            try:
                uri_data = {
                    "aws-region": "eu-central-1",
                    "api-version": "2015-03-31",
                    "aws-acct-id": service_acc_id,
                    "lambda-function-name": function_name + ":test",
                }
                uri = "arn:aws:apigateway:{aws-region}:lambda:path/{api-version}/functions/arn:aws:lambda:{" \
                      "aws-region}:{aws-acct-id}:function:{lambda-function-name}/invocations".format(**uri_data)

                integration_resp = api_client.put_integration(
                    restApiId=api_gateway,
                    resourceId=resource_resp['id'],
                    httpMethod="POST",
                    type="AWS",
                    integrationHttpMethod="POST",
                    uri=uri,
                )

                api_client.put_integration_response(
                    restApiId=api_gateway,
                    resourceId=resource_resp['id'],
                    httpMethod="POST",
                    statusCode="200",
                    selectionPattern=".*"
                )

                api_client.put_method_response(
                    restApiId=api_gateway,
                    resourceId=resource_resp['id'],
                    httpMethod="POST",
                    statusCode="200",
                )

            except api_client.exceptions._code_to_exception['ConflictException'] as e:
                logging.debug(e)

            try:
                response = client.add_permission(
                    FunctionName='arn:aws:lambda:eu-central-1:' + service_acc_id + ':function:' + function_name + ':test',
                    StatementId='api_test_permission07',
                    Action='lambda:InvokeFunction',
                    Principal='apigateway.amazonaws.com',
                    SourceArn='arn:aws:execute-api:eu-central-1:' + source_account_id + ':' + api_gateway + '/*/POST/' + function_name,
                    SourceAccount=source_account_id,
                )

                api_client.create_deployment(
                    restApiId=api_gateway,
                    stageName="production",
                )
            except client.exceptions._code_to_exception['ResourceConflictException'] as e:
                if e.response['Error']['Code'] == 'ResourceConflictException':
                    logging.debug(e)

        else:
            # TODO: permissions for a different service
            pass

    if source_provider == "Azure":
        str(path.dirname(executable)) + "/az"
        azure_login_file = open(env_path + "/setup-gateway-azure.json", "r")
        login_data = json.loads(azure_login_file.read())
        az_login_no_prompt = ["az", "login", "-u", login_data['service_username'], "-p", login_data['service_password']]
        execute_azure_command(az_login_no_prompt, 1)

        storage_acc = ["az", "storage", "account", "create"]
        storage_acc += ["--name", "eventgateway"]
        storage_acc += ["--resource-group", os.environ['AZURE_RESOURCE_GROUP']]
        storage_acc += ["--access-tier", "Hot"]
        storage_acc += ["--kind", "StorageV2"]
        storage_acc += ["--location", "westeurope"]
        storage_acc += ["--sku", "Standard_RAGRS"]
        execute_azure_command(storage_acc, 1)

        functionapp_create = ["az", "functionapp", "create"]
        functionapp_create += ["--resource-group", os.environ['AZURE_RESOURCE_GROUP']]
        functionapp_create += ["--os-type", "Linux"]
        functionapp_create += ["--consumption-plan-location", "westeurope"]
        functionapp_create += ["--runtime", "python"]
        functionapp_create += ["--runtime-version", "3.7"]
        functionapp_create += ["--name", "app-azure-gateway"]
        functionapp_create += ["--storage-account", "eventgateway"]
        execute_azure_command(functionapp_create, 1)

        print("-----------Destination microservice information-----------")
        aws_api_host = input("AWS API Gateway host name:")

        app_settings = ["az", "webapp", "config", "appsettings", "set"]
        app_settings += ["-g", os.environ['AZURE_RESOURCE_GROUP']]
        app_settings += ["-n", "app-azure-gateway"]
        app_settings += ["--settings", "AWS_ACCESS_KEY_ID=" + os.environ['AWS_USER_ACCESS_KEY']]
        app_settings += ["AWS_SECRET_ACCESS_KEY=" + os.environ['AWS_USER_SECRET_KEY']]

        if destination_microservice == "Lambda":
            app_settings += ["API_HOST=" + aws_api_host]
        else:
            # TODO: add different destination microservice
            exit(1)
        execute_azure_command(app_settings, 1)

        functionapp_publish = ["cd", "event_gateway/connection_function/", "&&", "func", "azure", "functionapp",
                               "publish"]
        functionapp_publish += ["app-azure-gateway", "--build", "remote", "--python"]
        execute_azure_command(functionapp_publish, 1)

        az_login_no_prompt = ["az", "login", "-u", login_data['user_username'], "-p", login_data['user_password']]
        execute_azure_command(az_login_no_prompt, 1)
        azure_login_file.close()

        print("-------------Source microservice information-------------")
        if source_microservice == "Container":
            storage_account_name = input("Storage account name:")
            container_name = input("Container name: ")

            subscription_info = ["az", "account", "list", "--all"]
            subscription_info_dict = execute_azure_command(subscription_info, 1)
            subscription_id_json = json.loads(subscription_info_dict.decode("utf-8"))
            subscription_id = subscription_id_json[0]['id']

            function_default_key_info = ["az", "rest", "--method", "post"]
            url = "https://management.azure.com/subscriptions/" + subscription_id + "/resourceGroups/" + os.environ[
                "AZURE_RESOURCE_GROUP"] + "/providers/Microsoft.Web/sites/app-azure-gateway/functions/connection_function/listKeys?api-version=2019-08-01"
            function_default_key_info += ["--uri", url]
            function_default_key_dict = execute_azure_command(function_default_key_info, 3)
            function_default_key_json = function_default_key_dict.decode("utf-8")
            function_default_key = (json.loads(function_default_key_json))['default']

            event_grid = ["az", "eventgrid", "event-subscription", "create"]
            event_grid += ["--name", "event-gateway-subscription"]
            event_grid += ["--source-resource-id",
                           "/subscriptions/" + subscription_id + "/resourceGroups/" + os.environ[
                               'AZURE_RESOURCE_GROUP'] + "/providers/Microsoft.Storage/storageAccounts/" + storage_account_name]
            event_grid += ["--included-event-types", "Microsoft.Storage.BlobCreated"]
            event_grid += ["--endpoint",
                           "https://app-azure-gateway.azurewebsites.net/api/connection_function?code=" + function_default_key]
            event_grid += ["--subject-begins-with", "/blobServices/default/containers/" + container_name + "/"]
            event_grid += ["--subject-ends-with", ".jpg", "--max-delivery-attempts", "1", "--event-ttl", "120"]
            execute_azure_command(event_grid, 1)
        else:
            # TODO: handle different source microservice
            exit(1)
