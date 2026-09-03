# AWS Security Monitoring

Monitor AWS CloudTrail events, detect IAM anomalies, and identify security threats in your AWS infrastructure.

## Features

- CloudTrail event analysis
- IAM anomaly detection (privilege escalation, credential exposure)
- Root account usage detection
- Data access pattern analysis
- AWS security compliance scoring
- Real-time finding generation
- Risk-based alert prioritization

## Detections

- Privilege escalation attempts
- Brute force API attacks
- Root account direct access
- Credential exposure patterns
- Excessive data access
- Unauthorized configuration changes

## API Endpoints

- POST /api/analyze/cloudtrail — Analyze CloudTrail events
- GET /api/findings — Get security findings
- GET /api/compliance — Get compliance status
- GET /api/report — Generate security report
- POST /api/demo/load-events — Load sample events

## Quick Start

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:5008
```

