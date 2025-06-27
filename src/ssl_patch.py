import os
import ssl
import urllib3
import boto3.compat

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set environment variables to disable SSL verification
os.environ['PYTHONWARNINGS'] = 'ignore:Unverified HTTPS request'
os.environ['REQUESTS_CA_BUNDLE'] = ''

# Patch SSL context creation in boto3
original_create_default_context = ssl._create_default_https_context
ssl._create_default_https_context = ssl._create_unverified_context

# Patch boto3's verify parameter
boto3.compat.VERIFY_CERTIFICATE = False