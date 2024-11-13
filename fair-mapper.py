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
    service_mapping = {
        'iam': FAIRComponent.VULNERABILITY,
        'accessanalyzer': FAIRComponent.LOSS_EVENT_FREQUENCY,
        'acm': FAIRComponent.VULNERABILITY,
        'account': FAIRComponent.VULNERABILITY
    }

    if 'monitor' in finding.check_title.lower() or 'logging' in finding.check_title.lower():
        return FAIRComponent.LOSS_EVENT_FREQUENCY
    if 'expir' in finding.check_title.lower():
        return FAIRComponent.THREAT_EVENT_FREQUENCY
    
    return service_mapping.get(finding.service_name.lower(), FAIRComponent.VULNERABILITY)

def calculate_risk_score(finding: ProwlerFinding) -> float:
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

def write_mapping_csv(findings: List[ProwlerFinding], output_file: str):
    """Generate CSV report showing mappings between Prowler, CIS, and FAIR"""
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow([
            'Prowler Check ID',
            'Check Title',
            'Service',
            'Severity',
            'Status',
            'CIS 3.0 Controls',
            'FAIR Component',
            'Risk Score',
            'Risk Description'
        ])
        
        # Write data rows
        for finding in findings:
            cis_controls = finding.compliance.get('CIS-3.0', ['N/A'])
            fair_component = map_to_fair_component(finding)
            risk_score = calculate_risk_score(finding)
            
            writer.writerow([
                finding.check_id,
                finding.check_title,
                finding.service_name,
                finding.severity,
                finding.status,
                ' | '.join(cis_controls),
                fair_component.value,
                f"{risk_score:.2f}",
                finding.risk
            ])

def write_summary_csv(findings: List[ProwlerFinding], output_file: str):
    """Generate summary CSV showing risk scores by FAIR component"""
    fair_components = {component: [] for component in FAIRComponent}
    
    # Group findings by FAIR component
    for finding in findings:
        component = map_to_fair_component(finding)
        fair_components[component].append({
            'check_id': finding.check_id,
            'risk_score': calculate_risk_score(finding)
        })
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow(['FAIR Component', 'Total Findings', 'Failed Findings', 'Average Risk Score'])
        
        # Write component summaries
        for component, component_findings in fair_components.items():
            total = len(component_findings)
            failed = len([f for f in component_findings if f['risk_score'] > 0])
            avg_risk = sum(f['risk_score'] for f in component_findings) / total if total > 0 else 0
            
            writer.writerow([
                component.value,
                total,
                failed,
                f"{avg_risk:.2f}"
            ])

if __name__ == "__main__":
    # Parse findings
    findings = parse_prowler_csv('/Users/mikewis/CDW-OneDrive/OneDrive - CDW/Client Docs/Clients/FCB/analysis/merged_complete.csv')
    
    # Generate detailed mapping CSV
    write_mapping_csv(findings, '/Users/mikewis/CDW-OneDrive/OneDrive - CDW/Client Docs/Clients/FCB/analysis/prowler_fair_mapping.csv')
    
    # Generate summary CSV
    write_summary_csv(findings, '/Users/mikewis/CDW-OneDrive/OneDrive - CDW/Client Docs/Clients/FCB/analysis/prowler_fair_summary.csv')