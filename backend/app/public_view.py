"""Allowlisted, read-only incident projection for the shareable review dashboard."""
import hashlib
from .schemas import Incident, IncidentType
from .playbooks import get_playbook

TITLES = {'open_ssh_security_group': 'SSH open to the world',
          'public_s3_bucket': 'Public S3 access', 'excessive_iam_permission': 'Excessive IAM permissions'}
REASONS = {'Bucket is publicly accessible (+50)', 'Public WRITE access (+30)',
    'Bucket name suggests sensitive data (+20)', 'Full administrator access granted (+85)',
    'Service-wide wildcard on all resources (+65)', 'Wildcard action limited to specific resources (+45)',
    'SSH reachable from the entire internet (+60)', 'All ports/protocols opened (+25)',
    'Production security group (+20)', 'Non-production security group (-25)'}


def public_incident(incident: Incident):
    # Build each field explicitly. Never copy arbitrary descriptions, policies,
    # response commands, or analyst notes to the public view.
    raw = incident.model_dump(mode='json')
    event, kind = raw['event'], raw['type']
    alias = 'resource-' + hashlib.sha256(raw['resource_id'].encode()).hexdigest()[:8]
    details = {}
    if kind == 'open_ssh_security_group':
        rules = []
        for r in event['details'].get('rules', []):
            if (r.get('protocol') in {'tcp', 'udp', '-1', '6', '17'}
                    and r.get('cidr') in {'0.0.0.0/0', '::/0'}
                    and all(type(r.get(k)) is int and -1 <= r[k] <= 65535
                            for k in ('from_port', 'to_port'))):
                rules.append({k:r[k] for k in ('protocol', 'from_port', 'to_port', 'cidr')})
        details = {'public_rules': rules}
    return {
        'incident_id': raw['incident_id'], 'type': kind, 'title': f'{TITLES[kind]}: {alias}',
        'description': 'A historical configuration change matched the project detection rule. Identifying details are hidden.',
        'severity': raw['severity'], 'severity_score': raw['severity_score'],
        'severity_reasons': [r for r in raw['severity_reasons'] if r in REASONS],
        'status': raw['status'], 'provider': 'aws',
        'resource_type': raw['resource_type'], 'resource_id': alias, 'actor': 'Hidden',
        'event': {
            'event_id': event['event_id'], 'origin': event['origin'], 'provider': 'aws',
            'source': {'open_ssh_security_group':'ec2.amazonaws.com', 'public_s3_bucket':'s3.amazonaws.com',
                       'excessive_iam_permission':'iam.amazonaws.com'}[kind],
            'event_name': event['event_name'], 'event_time': event['event_time'],
            'region': event['region'], 'account_id': 'Hidden', 'actor':'Hidden', 'source_ip': None,
            'resource_type': raw['resource_type'], 'resource_id': alias, 'details': details,
        },
        'playbook': [step.model_dump(mode='json') for step in get_playbook(IncidentType(kind))],
        'history': [{'status':raw['status'], 'timestamp':raw['updated_at'], 'note':'Recorded review baseline'}], 'created_at': raw['created_at'], 'updated_at': raw['updated_at'],
        'shared_demo': True,
    }
