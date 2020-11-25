#!/bin/python3

"""
Description:
    Static variables file
"""

#####################
# Proxy Variables
#####################
# (String) API URL
API_URL     = 'https://example:8082/api/' # Management System
NODE_URL    = 'https://example:8082/' # Admistration proxy 

#####################
# Policy Variables
#####################
# (Int) Proxy explicit port for policy trace
proxy_port = 8080

#(str) Authentication method, group-base in xml
AUTH_METHOD = ''

# (String List)
EXCLUDE_LAYERS = ['Test_LAYER']

#####################
# Script Variables
#####################
# (Boolean) Select if make requests to proxy or not
ONLINE = True

# (String) Log file name
LOG_FILE_NAME = 'trace.log'

# (String) xml file path
FILE_PATH = '/home/bluecoat_tracer/bluecoat_policy.xml'
