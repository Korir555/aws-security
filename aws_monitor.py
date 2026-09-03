"""
AWS Security Monitoring - CloudTrail, IAM, and Threat Detection
Monitors AWS security events, detects anomalies, and provides compliance reporting
"""

from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict, Set
from enum import Enum
from collections import defaultdict
import json
import re

class EventType(Enum):
    API_CALL = "API Call"
    IAM_CHANGE = "IAM Configuration Change"
    SECURITY_GROUP_CHANGE = "Security Group Modified"
    S3_ACCESS = "S3 Bucket Access"
    KMS_KEY_ACCESS = "KMS Key Access"
    RDS_ACCESS = "RDS Database Access"
    LAMBDA_EXECUTION = "Lambda Execution"
    CLOUDFORMATION_CHANGE = "CloudFormation Change"
    LOGIN_ATTEMPT = "Login Attempt"
    DATA_ACCESS = "Data Access"

class RiskLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

@dataclass
class AWSEvent:
    event_time: str
    event_type: EventType
    principal_id: str
    principal_name: str
    source_ip: str
    aws_service: str
    action: str
    resource_arn: str
    event_name: str
    result_code: str
    error_code: str
    risk_level: RiskLevel

@dataclass
class IAMFinding:
    finding_id: str
    timestamp: str
    risk_level: RiskLevel
    finding_type: str
    principal: str
    action: str
    description: str
    remediation: str
    affected_resources: List[str]

class AWSSecurityMonitor:
    """Monitor AWS security events and detect threats"""
    
    def __init__(self):
        self.events: List[AWSEvent] = []
        self.findings: List[IAMFinding] = []
        self.finding_counter = 0
        self.iam_policies: Dict = {}
        self.security_groups: Dict = {}
        self.s3_buckets: Dict = {}
    
    def analyze_cloudtrail_event(self, event_data: Dict) -> AWSEvent:
        """Parse and analyze CloudTrail event"""
        
        # Extract event details
        event_time = event_data.get('eventTime', datetime.utcnow().isoformat())
        principal_id = event_data.get('userIdentity', {}).get('principalId', 'unknown')
        principal_name = event_data.get('userIdentity', {}).get('userName', 'unknown')
        source_ip = event_data.get('sourceIPAddress', '0.0.0.0')
        aws_service = event_data.get('eventSource', '').split('.')[0]
        action = event_data.get('eventName', '')
        resource_arn = event_data.get('resources', [{}])[0].get('ARN', '')
        result_code = event_data.get('responseElements', {}).get('resultCode', 'Success')
        error_code = event_data.get('errorCode', '')
        
        # Determine event type
        event_type = self._classify_event(action, aws_service)
        
        # Calculate risk level
        risk_level = self._calculate_risk_level(event_data, action, principal_id)
        
        event = AWSEvent(
            event_time=event_time,
            event_type=event_type,
            principal_id=principal_id,
            principal_name=principal_name,
            source_ip=source_ip,
            aws_service=aws_service,
            action=action,
            resource_arn=resource_arn,
            event_name=action,
            result_code=result_code,
            error_code=error_code,
            risk_level=risk_level
        )
        
        self.events.append(event)
        return event
    
    def _classify_event(self, action: str, service: str) -> EventType:
        """Classify event type based on action and service"""
        
        if 'Put' in action or 'Update' in action or 'Create' in action or 'Delete' in action:
            if 'IAM' in service:
                return EventType.IAM_CHANGE
            elif 'SecurityGroup' in action or 'ec2' in service:
                return EventType.SECURITY_GROUP_CHANGE
            elif 'CloudFormation' in service:
                return EventType.CLOUDFORMATION_CHANGE
        
        if 's3' in service:
            return EventType.S3_ACCESS
        
        if 'kms' in service:
            return EventType.KMS_KEY_ACCESS
        
        if 'rds' in service:
            return EventType.RDS_ACCESS
        
        if 'lambda' in service:
            return EventType.LAMBDA_EXECUTION
        
        if 'login' in action.lower() or 'authentication' in action.lower():
            return EventType.LOGIN_ATTEMPT
        
        return EventType.API_CALL
    
    def _calculate_risk_level(self, event_data: Dict, action: str, principal_id: str) -> RiskLevel:
        """Calculate risk level for event"""
        
        risk_score = 1
        
        # Failed authentication attempts
        if 'UnauthorizedOperation' in action or event_data.get('errorCode'):
            risk_score = 3
        
        # Privilege escalation attempts
        if any(x in action for x in ['AttachUser', 'PutUser', 'CreateAccessKey', 'CreatePolicy']):
            risk_score = max(risk_score, 4)
        
        # Root account activity
        if 'root' in principal_id.lower():
            risk_score = max(risk_score, 4)
        
        # Sensitive operations
        if any(x in action for x in ['DeleteBucket', 'DeleteTable', 'DeletePolicy', 'PutBucketPolicy']):
            risk_score = max(risk_score, 5)
        
        # Data access from unusual IPs
        source_ip = event_data.get('sourceIPAddress', '')
        if self._is_unusual_ip(source_ip):
            risk_score = max(risk_score, 3)
        
        # After hours access
        event_time = datetime.fromisoformat(event_data.get('eventTime', datetime.utcnow().isoformat()))
        if event_time.hour < 6 or event_time.hour > 22:
            risk_score += 1
        
        return RiskLevel(min(5, risk_score))
    
    def _is_unusual_ip(self, ip: str) -> bool:
        """Check if IP is unusual (non-corporate, non-AWS)"""
        
        # Simplified check - in production would maintain whitelist
        if ip.startswith('10.') or ip.startswith('172.16.'):
            return False
        if ip == '127.0.0.1':
            return False
        
        return True
    
    def detect_iam_anomalies(self) -> List[IAMFinding]:
        """Detect anomalous IAM activity"""
        
        findings = []
        
        # Track events by principal
        principal_events: Dict[str, List[AWSEvent]] = defaultdict(list)
        for event in self.events[-1000:]:
            principal_events[event.principal_id].append(event)
        
        # Detect privilege escalation
        for principal, events in principal_events.items():
            policy_changes = [e for e in events if 'Policy' in e.action]
            if len(policy_changes) >= 3:
                finding = self._create_iam_finding(
                    finding_type='Privilege Escalation',
                    risk_level=RiskLevel.CRITICAL,
                    principal=principal,
                    action='Multiple IAM policy changes',
                    description=f'Principal {principal} made {len(policy_changes)} policy changes in short time',
                    remediation='Review IAM policies, check for unauthorized changes',
                    affected_resources=[e.resource_arn for e in policy_changes]
                )
                findings.append(finding)
        
        # Detect unusual access patterns
        for principal, events in principal_events.items():
            failed_logins = [e for e in events if e.error_code == 'UnauthorizedOperation']
            if len(failed_logins) >= 5:
                finding = self._create_iam_finding(
                    finding_type='Brute Force - AWS API',
                    risk_level=RiskLevel.HIGH,
                    principal=principal,
                    action='Multiple failed authentication attempts',
                    description=f'{len(failed_logins)} failed API calls from {principal}',
                    remediation='Review access keys, rotate credentials, enable MFA',
                    affected_resources=[e.source_ip for e in failed_logins]
                )
                findings.append(finding)
        
        # Detect root account usage
        root_events = [e for e in self.events[-1000:] if 'root' in e.principal_id.lower()]
        if len(root_events) > 0:
            finding = self._create_iam_finding(
                finding_type='Root Account Activity',
                risk_level=RiskLevel.CRITICAL,
                principal='root',
                action='Direct root account access',
                description=f'Root account performed {len(root_events)} actions',
                remediation='Disable root account access keys, use IAM users instead',
                affected_resources=[e.resource_arn for e in root_events]
            )
            findings.append(finding)
        
        # Detect credential exposure
        access_key_events = [e for e in self.events[-1000:] if 'AccessKey' in e.action]
        if len(access_key_events) >= 5:
            finding = self._create_iam_finding(
                finding_type='Potential Credential Exposure',
                risk_level=RiskLevel.HIGH,
                principal='Multiple',
                action='Excessive access key operations',
                description=f'{len(access_key_events)} access key operations detected',
                remediation='Audit access keys, rotate compromised credentials',
                affected_resources=[e.principal_id for e in access_key_events]
            )
            findings.append(finding)
        
        self.findings.extend(findings)
        return findings
    
    def _create_iam_finding(self, finding_type: str, risk_level: RiskLevel,
                           principal: str, action: str, description: str,
                           remediation: str, affected_resources: List[str]) -> IAMFinding:
        """Create IAM security finding"""
        
        self.finding_counter += 1
        finding = IAMFinding(
            finding_id=f"FINDING_{self.finding_counter:06d}",
            timestamp=datetime.utcnow().isoformat(),
            risk_level=risk_level,
            finding_type=finding_type,
            principal=principal,
            action=action,
            description=description,
            remediation=remediation,
            affected_resources=list(set(affected_resources))[:10]
        )
        
        return finding
    
    def detect_data_access_anomalies(self) -> List[IAMFinding]:
        """Detect anomalous data access patterns"""
        
        findings = []
        
        # S3 access patterns
        s3_events = [e for e in self.events[-1000:] if e.aws_service == 's3']
        if len(s3_events) > 100:  # Excessive S3 access
            finding = self._create_iam_finding(
                finding_type='Excessive S3 Access',
                risk_level=RiskLevel.HIGH,
                principal='Multiple',
                action='High volume S3 access',
                description=f'{len(s3_events)} S3 API calls detected in short timeframe',
                remediation='Review S3 access logs, check for data exfiltration',
                affected_resources=[e.resource_arn for e in s3_events]
            )
            findings.append(finding)
        
        # Database access patterns
        rds_events = [e for e in self.events[-1000:] if e.aws_service == 'rds']
        if len(rds_events) > 50:
            finding = self._create_iam_finding(
                finding_type='Excessive Database Access',
                risk_level=RiskLevel.MEDIUM,
                principal='Multiple',
                action='High volume RDS access',
                description=f'{len(rds_events)} RDS API calls in short timeframe',
                remediation='Review database access logs, check for unauthorized queries',
                affected_resources=[e.resource_arn for e in rds_events]
            )
            findings.append(finding)
        
        self.findings.extend(findings)
        return findings
    
    def get_compliance_status(self) -> Dict:
        """Get compliance status for AWS security best practices"""
        
        total_findings = len(self.findings)
        critical_findings = len([f for f in self.findings if f.risk_level == RiskLevel.CRITICAL])
        high_findings = len([f for f in self.findings if f.risk_level == RiskLevel.HIGH])
        
        compliance_score = 100
        if critical_findings > 0:
            compliance_score -= (critical_findings * 15)
        if high_findings > 0:
            compliance_score -= (high_findings * 8)
        
        compliance_score = max(0, compliance_score)
        
        return {
            'compliance_score': compliance_score,
            'status': 'COMPLIANT' if compliance_score >= 80 else 'NON-COMPLIANT',
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'recommendations': self._generate_recommendations(compliance_score)
        }
    
    def _generate_recommendations(self, score: int) -> List[str]:
        """Generate security recommendations based on compliance score"""
        
        recommendations = []
        
        if score < 50:
            recommendations.extend([
                'CRITICAL: Enable MFA for all IAM users',
                'CRITICAL: Rotate all access keys',
                'CRITICAL: Review and restrict security group rules',
                'Enable CloudTrail logging for all regions',
                'Enable AWS Config for compliance tracking'
            ])
        elif score < 80:
            recommendations.extend([
                'Review and update IAM policies for least privilege',
                'Enable encryption for S3 buckets',
                'Review CloudTrail logs for anomalies',
                'Implement resource tagging for cost tracking'
            ])
        else:
            recommendations.extend([
                'Continue monitoring AWS security events',
                'Quarterly compliance reviews recommended',
                'Keep MFA enabled for all accounts'
            ])
        
        return recommendations
    
    def export_security_report(self) -> Dict:
        """Export comprehensive AWS security report"""
        
        return {
            'report_timestamp': datetime.utcnow().isoformat(),
            'total_events': len(self.events),
            'total_findings': len(self.findings),
            'event_breakdown': self._get_event_breakdown(),
            'risk_distribution': self._get_risk_distribution(),
            'compliance_status': self.get_compliance_status(),
            'recent_findings': [
                {
                    'finding_id': f.finding_id,
                    'timestamp': f.timestamp,
                    'risk_level': f.risk_level.name,
                    'finding_type': f.finding_type,
                    'principal': f.principal,
                    'description': f.description,
                    'remediation': f.remediation
                }
                for f in sorted(self.findings, key=lambda x: x.timestamp, reverse=True)[:20]
            ]
        }
    
    def _get_event_breakdown(self) -> Dict[str, int]:
        """Get event type breakdown"""
        
        breakdown = defaultdict(int)
        for event in self.events:
            breakdown[event.event_type.value] += 1
        
        return dict(breakdown)
    
    def _get_risk_distribution(self) -> Dict[str, int]:
        """Get risk level distribution"""
        
        distribution = defaultdict(int)
        for finding in self.findings:
            distribution[finding.risk_level.name] += 1
        
        return dict(distribution)

