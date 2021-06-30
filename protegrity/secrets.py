import json
import config
from botocore.exceptions import ClientError
import boto3

####################### Secrets Manager #######################


def get_secret():
    secret_name = config.SECRET_NAME
    region_name = config.REGION
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region_name,
    )
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        app_config = json.loads(get_secret_value_response["SecretString"])
        return app_config

    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print("The requested secret " + secret_name + " was not found")
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            print("The request was invalid due to:", e)
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            print("The request had invalid params:", e)
        return "Some Error in secret manager" + str(e)
        