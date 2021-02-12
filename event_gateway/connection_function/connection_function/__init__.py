import datetime
import hashlib
import hmac
import json
import logging
import os
import sys

import azure.functions as func
import requests

aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
host = os.getenv('API_HOST')


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    SUBSCRIPTION_VALIDATION_EVENT = "Microsoft.EventGrid.SubscriptionValidationEvent"
    CUSTOM_EVENT = "Microsoft.Storage.BlobCreated"

    try:
        postreqdata = req.get_json()

        for event in postreqdata:
            event_data = event['data']
            logging.info(event['eventType'])
            if event['eventType'] == SUBSCRIPTION_VALIDATION_EVENT:
                validation_code = event_data['validationCode']
                validation_url = event_data.get('validationUrl', None)

                answer_payload = {
                    "validationResponse": validation_code
                }
                logging.info(answer_payload)
                return func.HttpResponse(json.dumps(answer_payload))

            elif event['eventType'] == CUSTOM_EVENT:
                print("Got a custom event {} and received {}".format(CUSTOM_EVENT, event_data))
                blob_url = event_data['url']
                blob_data = blob_url.split("/")
                blob = blob_data[-1]
                container_name = blob_data[-2]

                forward_notification(blob=blob, container=container_name)
                return func.HttpResponse()
    except ValueError:
        pass


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def forward_notification(blob, container):
    # ************* REQUEST VALUES *************
    method = 'POST'
    service = 'execute-api'
    region = 'eu-central-1'
    endpoint = 'https://' + host + '/production'
    # POST requests use a content type header. For DynamoDB,
    # the content is JSON.
    content_type = 'application/x-amz-json-1.1'
    # DynamoDB requires an x-amz-target header that has this format:
    #     DynamoDB_<API version>.<operationName>
    request_parameters = '{"Records": [{"s3": {"bucket": {"name": "' + container + '"},"object": {"key": "' + blob + '"}}}]}'

    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key is None or secret_key is None:
        print('No access key is available.')
        sys.exit()

    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    canonical_uri = '/production'
    canonical_querystring = ''
    canonical_headers = 'host:' + host + '\n' + 'x-amz-content-sha256:' + '' + '\n' + 'x-amz-date:' + amz_date + '\n'

    signed_headers = 'host;x-amz-content-sha256;x-amz-date'

    payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    print("cn_r:" + canonical_request)

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(
        canonical_request.encode('utf-8')).hexdigest()
    print("string:" + string_to_sign)

    signing_key = get_signature_key(secret_key, date_stamp, region, service)

    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    headers = {'Content-Type': content_type,
               'X-Amz-Date': amz_date,
               'Authorization': authorization_header}

    logging.info(str(headers) + '\n')

    # ************* SEND THE REQUEST *************
    logging.info('Request URL = ' + endpoint)
    logging.info('Request parameters = ' + request_parameters)

    r = requests.post(endpoint, data=request_parameters, headers=headers)

    logging.info('Response code: %d\n' % r.status_code)
    logging.info(r.text)
