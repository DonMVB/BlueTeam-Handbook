#!/bin/sh
############################################################
# Script Name : domainlookup_V_01.sh
# Version     : V_01
# Last Update : 2026-07-26 19:45 EDT
# Description : Queries VirusTotal for domain info and
#               prints formatted analysis results.
############################################################
#
# Command line options:
#   $1  DOMAIN  Domain name to look up (required)
#
# Example:
#   ./domainlookup_V_01.sh example.com
#

DOMAIN=$1
API_KEY="YOUR-KEY-GOES-HERE"
API_URL="https://www.virustotal.com/api/v3"
OUTFILE="domainlookup"

curl -s --request GET \
     --url "${API_URL}/domains/${DOMAIN}" \
     --header 'accept: application/json' \
     --header "x-apikey: ${API_KEY}" \
     > "${OUTFILE}"

jq -r '
  .data.attributes as $a |

  # Convert dates to human readable format
  "Last Analysis Date: "
    + ($a.last_analysis_date | todate),
  "Last Update Date: "
    + ($a.last_update_date | todate),
  "WHOIS Date: "
    + ($a.whois_date | todate),
  "Last Modification Date: "
    + ($a.last_modification_date | todate),
  "Last DNS Records Date: "
    + ($a.last_dns_records_date | todate),
  "",

  # Extract Creation Date from whois
  "Creation Date: "
    + ($a.whois
       | split("\n")[]
       | select(startswith("Creation Date:"))
       | split(": ")[1]),
  "",

  # Iterate over last_analysis_results
  "=== Analysis Results (excluding" +
  " undetected/unrated and harmless/clean) ===",
  ($a.last_analysis_results
    | to_entries[]
    | select(
        (.value.category == "undetected"
          and .value.result == "unrated")
        or
        (.value.category == "harmless"
          and .value.result == "clean")
        | not
      )
    | "  \(.key): category=\(.value.category)"
      + ", result=\(.value.result)"
  ),
  "",
  "--- End of Results ---"
' "${OUTFILE}"
