#!/bin/bash
# One-click setup and execution

echo "🚀 Setting up Suspicious Login Detector..."

# Create directories
mkdir -p sample_logs output

# Install dependencies
pip3 install -r requirements.txt

# Download GeoIP database (optional)
echo "📍 Downloading GeoIP database (optional)..."
wget -O GeoLite2-City.mmdb.gz "https://git.io/GeoLite2-City.mmdb.gz" || echo "GeoIP download failed - continuing without geolocation"
gunzip GeoLite2-City.mmdb.gz 2>/dev/null || true

# Generate sample logs
echo "📄 Generating sample log files..."
python3 -c "
import pandas as pd
from datetime import datetime, timedelta
import random

def generate_sample_log(n=10000):
    ips = ['192.168.1.' + str(i) for i in range(1, 255)] + ['10.0.0.' + str(i) for i in range(1, 100)]
    paths = ['/login', '/admin', '/wp-login.php', '/']
    statuses = [200, 404, 401, 403]
    
    logs = []
    base_time = datetime.now() - timedelta(days=1)
    
    for i in range(n):
        log = f'{random.choice(ips)} - - [{base_time + timedelta(minutes=i//100, seconds=i)} +0000] \"GET {random.choice(paths)} HTTP/1.1\" {random.choice(statuses)} - \"-\" \"Mozilla/5.0 (compatible; Scanner/1.0)\"'
        logs.append(log)
    
    with open('sample_logs/access.log', 'w') as f:
        f.write('\n'.join(logs))
    
generate_sample_log()
print('Sample logs generated!')
"

# Run analysis
echo "🔍 Running analysis..."
python3 main.py

echo "✅ Complete! Check output/ directory for results."