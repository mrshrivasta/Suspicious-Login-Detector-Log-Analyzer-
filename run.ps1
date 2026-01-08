@"
#!/usr/bin/env pwsh
Write-Host "🚀 Setting up Suspicious Login Detector..." -ForegroundColor Cyan

# Create directories
New-Item -ItemType Directory -Force -Path "sample_logs", "output", "test_logs", "output_test" | Out-Null

# Install Python dependencies
pip install -r requirements.txt

# Generate sample logs
python -c @"
import pandas as pd
from datetime import datetime, timedelta
import random, os
from pathlib import Path

def generate_sample_log(n=5000):
    ips = [f'192.168.1.{i}' for i in range(1, 255)]
    paths = ['/', '/about', '/contact']
    statuses = [200, 404]
    
    logs = []
    base_time = datetime.now() - timedelta(hours=2)
    
    for i in range(n):
        ip = random.choice(ips)
        path = random.choice(paths)
        status = random.choice(statuses)
        timestamp = base_time + timedelta(minutes=i//50, seconds=i%50)
        log = f'{ip} - - [{timestamp.strftime(\"%d/%b/%Y:%H:%M:%S +0000\")}] \"GET {path} HTTP/1.1\" {status} 1234 \"-\" \"Mozilla/5.0 (Windows NT 10.0)\"'
        logs.append(log)
    
    Path('sample_logs/access.log').write_text('\\n'.join(logs))
    print('✅ Sample logs generated!')

generate_sample_log()
"@

# Run analysis
python main.py sample_logs/ -o output/results.json
Write-Host "✅ Setup complete! Results in output/" -ForegroundColor Green
"@ | Out-File -FilePath "run.ps1" -Encoding UTF8