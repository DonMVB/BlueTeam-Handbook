  1 #!/bin/bash
  2 # count_successful_ips_method1.sh
  3 # Counts successful SSH authentication attempts by source IP
  4 # Uses: grep, sed, cut, sort, uniq
  5 if [ $# -eq 0 ]; then
  6     echo "Usage: $0 "
  7     exit 1
  8 fi
  9 LOGFILE=$1
 10 if [ ! -f "$LOGFILE" ]; then
 11     echo "Error: File '$LOGFILE' not found"
 12     exit 1
 13 fi
 14 echo "=== Successful SSH Authentication Attempts by Source IP (Method 1) ==="
 15 echo ""
 16 # Method using sed to extract IP addresses
 17 grep "Accepted" "$LOGFILE" | \
 18     sed -n 's/.*from \([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/p' | \
 19     sort | \
 20     uniq -c | \
 21     sort -rn | \
 22     awk 'BEGIN {printf "%-8s %-17s\n", "COUNT", "SOURCE_IP"; print "-------- -----------------"} 
 23          {printf "%-8s %-17s\n", $1, $2}'
 24 echo ""
 25 echo "Breakdown by Authentication Method:"
 26 echo ""
 27 echo "Password Authentication:"
 28 grep "Accepted password" "$LOGFILE" | \
 29     sed -n 's/.*from \([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/p' | \
 30        sort | \
 31        uniq -c | \
 32        sort -rn | \
 33        awk 'BEGIN {printf "  %-8s %-17s\n", "COUNT", "SOURCE_IP"} 
 34          {printf "  %-8s %-17s\n", $1, $2}'
 35 echo ""
 36 echo "Public Key Authentication:"
 37 grep "Accepted publickey" "$LOGFILE" | \
 38     sed -n 's/.*from \([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/p' | \
 39     sort | \
 40     uniq -c | \
 41     sort -rn | \
 42     awk 'BEGIN {printf "  %-8s %-17s\n", "COUNT", "SOURCE_IP"} 
 43          {printf "  %-8s %-17s\n", $1, $2}'
