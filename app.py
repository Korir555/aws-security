from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from aws_monitor import AWSSecurityMonitor
import json

app = Flask(__name__, template_folder='templates')
CORS(app)

aws_monitor = AWSSecurityMonitor()

# Sample CloudTrail events
SAMPLE_EVENTS = [
    {'eventTime': '2024-09-03T10:00:00', 'userIdentity': {'principalId': 'user-123', 'userName': 'john.doe'}, 'sourceIPAddress': '203.0.113.5', 'eventSource': 'iam.amazonaws.com', 'eventName': 'CreateAccessKey', 'resources': [{'ARN': 'arn:aws:iam::123456789:user/admin'}], 'errorCode': ''},
    {'eventTime': '2024-09-03T10:05:00', 'userIdentity': {'principalId': 'root', 'userName': 'root'}, 'sourceIPAddress': '203.0.113.10', 'eventSource': 'ec2.amazonaws.com', 'eventName': 'AuthorizeSecurityGroupIngress', 'resources': [{'ARN': 'arn:aws:ec2:us-east-1:sg-123'}], 'errorCode': ''},
    {'eventTime': '2024-09-03T10:10:00', 'userIdentity': {'principalId': 'user-456', 'userName': 'attacker'}, 'sourceIPAddress': '203.0.113.99', 'eventSource': 'iam.amazonaws.com', 'eventName': 'AttachUserPolicy', 'resources': [{'ARN': 'arn:aws:iam::123456789:user/attacker'}], 'errorCode': ''},
    {'eventTime': '2024-09-03T10:15:00', 'userIdentity': {'principalId': 'user-456'}, 'sourceIPAddress': '203.0.113.99', 'eventSource': 'iam.amazonaws.com', 'eventName': 'CreatePolicy', 'resources': [{'ARN': 'arn:aws:iam::policy'}], 'errorCode': ''},
    {'eventTime': '2024-09-03T10:20:00', 'userIdentity': {'principalId': 'user-456'}, 'sourceIPAddress': '203.0.113.99', 'eventSource': 'iam.amazonaws.com', 'eventName': 'PutUserPolicy', 'resources': [{'ARN': 'arn:aws:iam::user'}], 'errorCode': 'UnauthorizedOperation'},
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze/cloudtrail', methods=['POST'])
def analyze_cloudtrail():
    try:
        data = request.json
        events = data.get('events', [])
        
        for event in events:
            aws_monitor.analyze_cloudtrail_event(event)
        
        aws_monitor.detect_iam_anomalies()
        aws_monitor.detect_data_access_anomalies()
        
        return jsonify({'status': 'success', 'events_analyzed': len(events)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings', methods=['GET'])
def get_findings():
    try:
        limit = request.args.get('limit', 50, type=int)
        findings = [
            {
                'finding_id': f.finding_id,
                'risk_level': f.risk_level.name,
                'finding_type': f.finding_type,
                'principal': f.principal,
                'description': f.description,
                'remediation': f.remediation
            }
            for f in aws_monitor.findings[-limit:]
        ]
        return jsonify({'total_findings': len(aws_monitor.findings), 'findings': findings}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/compliance', methods=['GET'])
def get_compliance():
    try:
        compliance = aws_monitor.get_compliance_status()
        return jsonify(compliance), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report', methods=['GET'])
def get_report():
    try:
        report = aws_monitor.export_security_report()
        return jsonify(report), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/demo/load-events', methods=['POST'])
def load_demo_events():
    try:
        for event in SAMPLE_EVENTS:
            aws_monitor.analyze_cloudtrail_event(event)
        
        aws_monitor.detect_iam_anomalies()
        
        return jsonify({'status': 'success', 'events_loaded': len(SAMPLE_EVENTS)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'aws-security-monitor'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5008)
