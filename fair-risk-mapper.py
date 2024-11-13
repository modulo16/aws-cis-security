import csv
import json
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum

class FAIRComponent(Enum):
    VULNERABILITY = "vulnerability"
    LOSS_EVENT_FREQUENCY = "loss_event_frequency"
    THREAT_EVENT_FREQUENCY = "threat_event_frequency"
    PRIMARY_LOSS = "primary_loss"
    SECONDARY_LOSS = "secondary_loss"

@dataclass
class ProwlerFinding:
    check_id: str
    check_title: str
    service_name: str
    severity: str
    status: str
    status_extended: str
    compliance: Dict[str, List[str]]
    risk: str

def parse_prowler_csv(file_path: str) -> List[ProwlerFinding]:
    findings = []
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            # Parse compliance string into structured data
            compliance_str = row['COMPLIANCE']
            compliance = {}
            if compliance_str:
                for comp in compliance_str.split('|'):
                    comp = comp.strip()
                    if ':' in comp:
                        framework, controls = comp.split(':')
                        compliance[framework.strip()] = [c.strip() for c in controls.split(',')]

            finding = ProwlerFinding(
                check_id=row['CHECK_ID'],
                check_title=row['CHECK_TITLE'],
                service_name=row['SERVICE_NAME'],
                severity=row['SEVERITY'],
                status=row['STATUS'],
                status_extended=row['STATUS_EXTENDED'],
                compliance=compliance,
                risk=row['RISK']
            )
            findings.append(finding)
    return findings

def map_to_fair_component(finding: ProwlerFinding) -> FAIRComponent:
    """Map Prowler finding to FAIR component based on service and check type"""
    
    # Service-based mapping
    service_mapping = {
        'iam': FAIRComponent.VULNERABILITY,
        'accessanalyzer': FAIRComponent.LOSS_EVENT_FREQUENCY,
        'acm': FAIRComponent.VULNERABILITY,
        'account': FAIRComponent.VULNERABILITY
    }

    # Override based on check characteristics
    if 'monitor' in finding.check_title.lower() or 'logging' in finding.check_title.lower():
        return FAIRComponent.LOSS_EVENT_FREQUENCY
    if 'expir' in finding.check_title.lower():
        return FAIRComponent.THREAT_EVENT_FREQUENCY
    
    return service_mapping.get(finding.service_name.lower(), FAIRComponent.VULNERABILITY)

def calculate_risk_score(finding: ProwlerFinding) -> float:
    """Calculate risk score based on severity and status"""
    severity_multipliers = {
        'critical': 1.0,
        'high': 0.8,
        'medium': 0.5,
        'low': 0.3
    }
    
    base_score = severity_multipliers.get(finding.severity.lower(), 0.1)
    if finding.status == 'FAIL':
        return base_score
    return 0.0

def generate_mapping_report(findings: List[ProwlerFinding]) -> Dict:
    """Generate mapping report with FAIR components and CIS controls"""
    report = {
        'findings_by_fair_component': {},
        'cis_control_coverage': {},
        'risk_scores': {},
        'summary': {
            'total_findings': len(findings),
            'failed_findings': len([f for f in findings if f.status == 'FAIL']),
            'critical_findings': len([f for f in findings if f.severity.lower() == 'critical'])
        }
    }
    
    for finding in findings:
        fair_component = map_to_fair_component(finding)
        risk_score = calculate_risk_score(finding)
        
        # Group by FAIR component
        if fair_component.value not in report['findings_by_fair_component']:
            report['findings_by_fair_component'][fair_component.value] = []
        report['findings_by_fair_component'][fair_component.value].append({
            'check_id': finding.check_id,
            'status': finding.status,
            'risk_score': risk_score
        })
        
        # Track CIS controls
        if 'CIS-3.0' in finding.compliance:
            for control in finding.compliance['CIS-3.0']:
                if control not in report['cis_control_coverage']:
                    report['cis_control_coverage'][control] = []
                report['cis_control_coverage'][control].append(finding.check_id)
        
        # Track risk scores
        report['risk_scores'][finding.check_id] = risk_score
    
    return report

# Example usage
if __name__ == "__main__":
    findings = parse_prowler_csv('/Users/mikewis/CDW-OneDrive/OneDrive - CDW/Client Docs/Clients/FCB/analysis/merged_complete.csv')
    report = generate_mapping_report(findings)
    
    print("\nFindings by FAIR Component:")
    for component, findings in report['findings_by_fair_component'].items():
        print(f"\n{component}:")
        for finding in findings:
            print(f"  - {finding['check_id']}: Risk Score {finding['risk_score']}")
    
    print("\nCIS Control Coverage:")
    for control, checks in report['cis_control_coverage'].items():
        print(f"\nCIS 3.0 Control {control}:")
        for check in checks:
            print(f"  - {check}")