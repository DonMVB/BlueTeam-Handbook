#!/usr/bin/python3
############################################################
# Script Name : greynoise_lookup_V_01.py
# Version     : V_01
# Last Update : 2026-07-26 19:57 EDT
# Description : Queries the GreyNoise Community API for
#               an IP or domain and prints the pretty-
#               printed JSON response.
############################################################

import json

import requests

IP_OR_DOMAIN = "77.83.240.4"
GN_API_KEY = "YOUR-API-KEY-HERE"
BASE_URL = "https://api.greynoise.io/v3/community"

headers = {"Key": GN_API_KEY}
url = f"{BASE_URL}/{IP_OR_DOMAIN}"

r = requests.get(
    url,
    headers=headers,
    timeout=8,
)
data = r.json()

pretty_json_string = json.dumps(data, indent=5)
print(pretty_json_string)
