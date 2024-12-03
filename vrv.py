import csv
from collections import defaultdict
import re

# Define the log file path
log_file_path = 'sample.log'

# Threshold for failed login attempts
failed_login_threshold = 10

# Initialize dictionaries for counting
ip_request_count = defaultdict(int)
endpoint_count = defaultdict(int)
failed_login_attempts = defaultdict(int)

# Regex pattern for parsing the log line
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d+) \S+'
)

# Function to process each log line
def process_log_line(line):
    match = log_pattern.match(line)
    if match:
        ip = match.group('ip')
        endpoint = match.group('endpoint')
        status_code = match.group('status')
        
        # Increment IP request count
        ip_request_count[ip] += 1
        
        # Increment endpoint count
        endpoint_count[endpoint] += 1
        
        # Detect suspicious activity (failed login attempts with 401 status code or "Invalid credentials")
        if status_code == '401' or 'Invalid credentials' in line:
            failed_login_attempts[ip] += 1

# Read the log file and process each line
with open(log_file_path, 'r') as file:
    for line in file:
        process_log_line(line)

# Sort the IP addresses by request count in descending order
sorted_ip_requests = sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)

# Find the most frequently accessed endpoint
most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1])

# Filter IPs with failed login attempts exceeding the threshold
suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > failed_login_threshold}

# Print the results
print("IP Address           Request Count")
for ip, count in sorted_ip_requests:
    print(f"{ip:<20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

print("\nSuspicious Activity Detected:")
print(f"IP Address           Failed Login Attempts")
for ip, count in suspicious_ips.items():
    print(f"{ip:<20} {count}")

# Write the results to a CSV file
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    
    # Write Requests per IP
    csvwriter.writerow(['IP Address', 'Request Count'])
    for ip, count in sorted_ip_requests:
        csvwriter.writerow([ip, count])
    
    # Write Most Accessed Endpoint
    csvwriter.writerow(['Endpoint', 'Access Count'])
    csvwriter.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
    
    # Write Suspicious Activity
    csvwriter.writerow(['IP Address', 'Failed Login Count'])
    for ip, count in suspicious_ips.items():
        csvwriter.writerow([ip, count])
