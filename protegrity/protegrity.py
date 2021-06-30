"""This module uses the Protegrity Service to tokenize and detokenize the data."""
import json
import time
import datetime
import secrets
import requests
import logging
from common.config import (
    secret_meta_data, 
    TOKENIZATION_FIELDS, 
    firstNmPolicy,
    lastNmPolicy,
    datePolicy,
    ssnPolicy,
    idPolicy
    )

from flask_restful import abort

RETRIES = 3
BATCHSIZE = 500
PROTECTLIST = 1
UNPROTECTLIST = 2
POLICYLIST = [firstNmPolicy, lastNmPolicy, datePolicy, ssnPolicy, idPolicy]

protegrity_host = secret_meta_data.get("protegityHost")

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def validate_prot_response(response):
    """Validate a response items and clears policyName"""
    results = []
    if not response:
        return True, results
    for item in response.json():
        if len(item) < 2:
            return True, results
        item.pop("policyName", None)
        results.append(item)
    return False, results


def make_protegrity_request(payload, req_type):
    """Issues a protegrity call and validate response."""
    start_time = time.time()
    HEADERS = {"Content-Type": "application/json"}
    ROUTE = ""

    # Identify type of request
    if req_type == PROTECTLIST:
        ROUTE = "protectList"
    elif req_type == UNPROTECTLIST:
        ROUTE = "unprotectList"

    uri = f"{protegrity_host}/{ROUTE}"

    # Retry until request is complete
    attempts = RETRIES
    response_needed = True
    response = None
    retry_counter = 0
    protegrity_results = []
    try:
        while response_needed and attempts:
            response = requests.post(uri, headers=HEADERS, data=payload, verify=False)
            attempts -= 1

            response_needed, protegrity_results = validate_prot_response(response)
            if response_needed:
                retry_counter += 1
                if not attempts:
                    raise Exception("Failed to get a proper detokenization response.")
    except Exception as e:
        logging.error(e)
        abort(503, description="Unable to get a valid response from Protegrity service.")
    logging.debug("Total time to get Protegrity response {} after {} attemps".format(round(datetime.datetime.now().timestamp() - start_time,4),  RETRIES - attempts))
    return protegrity_results


########################################### Tokenization ###########################################


def create_tokenized_vals_dict(tokenized_response):
    """Creates a tokenized dictionary from the list of Protegrity Response."""

    tokenized_vals = {}
    for res in tokenized_response:
        for key, value in res.items():
            if key in tokenized_vals:
                if isinstance(tokenized_vals[key], str):
                    tokenized_vals[key] = [
                        tokenized_vals[key],
                        value,
                    ]
                elif isinstance(tokenized_vals[key], list):
                    tokenized_vals[key].append(value)
            else:
                tokenized_vals[key] = value
    return tokenized_vals


def tokenize_request(args):
    values_to_tokenize = []
    for key, value in args.items():
        if key in TOKENIZATION_FIELDS.keys() and isinstance(value, datetime.date):
            values_to_tokenize.append(
                {key: datetime.datetime.strftime(value, "%Y%m%d"), "policyName": TOKENIZATION_FIELDS[key]}
            )
        elif key in TOKENIZATION_FIELDS.keys() and isinstance(value, list):
            for val in value:
                values_to_tokenize.append(
                    {key: str(val), "policyName": TOKENIZATION_FIELDS[key]}
                )
        elif key in TOKENIZATION_FIELDS.keys():
            values_to_tokenize.append(
                {key: str(value), "policyName": TOKENIZATION_FIELDS[key]}
            )
    payload = json.dumps(values_to_tokenize)
    tokenized_response = make_protegrity_request(payload, PROTECTLIST)

    return create_tokenized_vals_dict(tokenized_response)


########################################### Detokenization ###########################################

def create_request_payload(records, detok_request_payload):
    """Creates the protegrity payload."""

    # Crawl response for all the tokenized attributes to add to request
    if records:
        for rec in records:
            recursive_tokenized_search(rec, detok_request_payload)
    return detok_request_payload


def create_payload_batches(detok_request_payload):
    """Creates batches of protegrity request payloads."""

    n = BATCHSIZE
    detok_batches = [
        detok_request_payload[i * n : (i + 1) * n]
        for i in range((len(detok_request_payload) + n - 1) // n)
    ]
    logging.debug(
        "Total values to detokenize: {}".format(len(detok_request_payload))
    )
    logging.debug("Broken into {} chunks of size {}".format(len(detok_batches), n))

    return detok_batches


def create_detok_response(records, unprotected_vals):
    """Iterates over the protegrity response to replace vals in record."""

    # Convert to string to replace
    string_record = json.dumps(records)

    # Iterate over protegrity response to replace values
    for detok_val in unprotected_vals:
        for key in detok_val.keys():
            string_record = string_record.replace(key, detok_val[key], 1)
    
    return json.loads(string_record)


def detokenize_response(grapqhl_respone):
    """Call detokenization for every root in response."""

    for key in grapqhl_respone.data:
        grapqhl_respone.data[key] = detok_query_response(grapqhl_respone.data[key])
    return grapqhl_respone


def detok_query_response(records):
    """Returns the detokenized records."""

    detok_request_payload = []
    unprotected_vals = []

    create_request_payload(records, detok_request_payload)
    if detok_request_payload:
        detok_batches = create_payload_batches(detok_request_payload)

        # Call API to detokenize values
        for batch in detok_batches:
            detok_request_payload_chunk = json.dumps(batch)
            unprotected_vals.extend(
                make_protegrity_request(detok_request_payload_chunk, UNPROTECTLIST)
            )

    detok_records = create_detok_response(records, unprotected_vals)

    return detok_records


def recursive_tokenized_search(data, detok_request):
    """Recursively iterate over the record to find values to be tokenized and append to detok_request."""

    if data:
        for key, value in data.items():
            if isinstance(value, str) and "$$" in value and value.split('$$')[-1] in POLICYLIST:
                temp_id = secrets.token_urlsafe(10)
                data[key] = temp_id
                detok_request.append(
                    {
                        "policyName": str(value).split("$$")[1],
                        temp_id: str(value).split("$$")[0],
                    }
                )
            elif isinstance(value, list):
                if any(
                        item in POLICYLIST
                        for item in value
                ):
                    policy = value[-1]
                    del value[-1]
                    for index, item in enumerate(value):
                        temp_id = secrets.token_urlsafe(10)
                        data[key][index] = temp_id
                        detok_request.append({"policyName": policy, temp_id: str(item)})
                else:
                    for val in value:
                        if type(val) == type(str()):
                            pass
                        elif type(val) == type(list()):
                            pass
                        else:
                            recursive_tokenized_search(val, detok_request)

            elif isinstance(value, dict):
                recursive_tokenized_search(value, detok_request)

