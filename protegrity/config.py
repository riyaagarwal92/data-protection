import secrets

# AWS Configuration Settings
SECRET_NAME = "Data-Protection-ConfigServer"
REGION = "us-east-1"

# Query fields to be tokenized
TOKENIZATION_FIELDS = {"dob": "DOB", "firstNm": "firstName", "lastNm": "lastName", "ssn": "SSN"}

# Protegrity Policies
firstNmPolicy = "firstName"
lastNmPolicy = "lastName"
datePolicy = "DOB"
ssnPolicy = "SSN"
idPolicy = "OtherID"

secret_meta_data = secrets.get_secret()
