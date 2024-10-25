import json
import math
from dataclasses import dataclass
from typing import List, Dict
import statistics
from datetime import datetime

@dataclass
class FAIRMetrics:
    threat_event_frequency: float  # Annual rate of threat events
    vulnerability: float          # Probability of threat success (0-1)
    loss_magnitude: float        # Expected loss amount per event
    risk_score: float           # Annual loss expectancy

@dataclass
class RiskFactors:
    threat_capability: float    # Scale of 0-1
    control_strength: float     # Scale of 0-1
    asset_value: float         # Dollar value
    exposure: float            # Hours per year

class FAIRAssessment:
    def __init__(self):
        # Risk scoring weights for different severity levels
        self.severity_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.1,
            'ERROR': 0.5  # Default weight for error conditions
        }
        
        # Base risk factors for different control categories
        self.control_base_factors = {
            'IAM': RiskFactors(
                threat_capability=0.7,    # Sophisticated attackers targeting IAM
                control_strength=0.8,     # Strong IAM controls when properly configured
                asset_value=1000000,      # High value for identity-related assets
                exposure=8760            # 24/7 exposure (hours per year)
            ),
            'LOGGING': RiskFactors(
                threat_capability=0.5,    # Medium sophistication needed
                control_strength=0.6,     # Moderate control effectiveness
                asset_value=500000,       # Medium value for logging assets
                exposure=8760            # 24/7 exposure
            ),
            'NETWORKING': RiskFactors(
                threat_capability=0.8,    # High sophistication for network attacks
                control_strength=0.7,     # Good network controls when proper
                asset_value=750000,       # High value for network assets
                exposure=8760            # 24/7 exposure
            ),
            'MONITORING': RiskFactors(
                threat_capability=0.4,    # Lower sophistication needed
                control_strength=0.5,     # Moderate control effectiveness
                asset_value=250000,       # Lower value for monitoring
                exposure=8760            # 24/7 exposure
            )
        }

    def calculate_vulnerability(self, findings: List[Dict], category: str) -> float:
        """Calculate vulnerability score based on findings and control strength"""
        if not findings:
            return 0.0
        
        base_control_strength = self.control_base_factors[category].control_strength
        total_weight = 0
        weighted_vulnerabilities = 0
        
        for finding in findings:
            severity = finding.get('Severity', 'MEDIUM')
            weight = self.severity_weights.get(severity, 0.4)
            total_weight += weight
            weighted_vulnerabilities += (1 - base_control_strength) * weight
        
        return weighted_vulnerabilities / total_weight if total_weight > 0 else 0

    def calculate_threat_frequency(self, category: str, vulnerability: float) -> float:
        """Calculate annual threat event frequency"""
        base_factors = self.control_base_factors[category]
        
        # Calculate contact frequency based on exposure
        contact_frequency = base_factors.exposure / 24 * 365 * base_factors.threat_capability
        
        # Adjust for vulnerability
        return contact_frequency * vulnerability

    def calculate_loss_magnitude(self, findings: List[Dict], category: str) -> float:
        """Calculate probable loss magnitude per event"""
        base_asset_value = self.control_base_factors[category].asset_value
        
        # Calculate loss factors based on finding severities
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            severity = finding.get('Severity', 'MEDIUM')
            if severity in severity_count:
                severity_count[severity] += 1
        
        # Calculate weighted loss magnitude
        loss_factors = {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.1
        }
        
        total_loss_factor = 0
        for severity, count in severity_count.items():
            if count > 0:
                total_loss_factor += loss_factors[severity] * count
        
        return base_asset_value * (total_loss_factor / max(sum(severity_count.values()), 1))

    def assess_category(self, findings: List[Dict], category: str) -> FAIRMetrics:
        """Perform FAIR assessment for a category of findings"""
        vulnerability = self.calculate_vulnerability(findings, category)
        threat_freq = self.calculate_threat_frequency(category, vulnerability)
        loss_mag = self.calculate_loss_magnitude(findings, category)
        risk_score = threat_freq * loss_mag
        
        return FAIRMetrics(
            threat_event_frequency=threat_freq,
            vulnerability=vulnerability,
            loss_magnitude=loss_mag,
            risk_score=risk_score
        )

def main():
    # Example usage
    fair_assessment = FAIRAssessment()
    
    # Load findings from CIS assessment scripts
    try:
        with open('iam_findings.json', 'r') as f:
            iam_findings = json.load(f)
        with open('logging_findings.json', 'r') as f:
            logging_findings = json.load(f)
        with open('networking_findings.json', 'r') as f:
            networking_findings = json.load(f)
        with open('monitoring_findings.json', 'r') as f:
            monitoring_findings = json.load(f)
            
        # Perform FAIR assessment for each category
        assessments = {
            'IAM': fair_assessment.assess_category(iam_findings, 'IAM'),
            'LOGGING': fair_assessment.assess_category(logging_findings, 'LOGGING'),
            'NETWORKING': fair_assessment.assess_category(networking_findings, 'NETWORKING'),
            'MONITORING': fair_assessment.assess_category(monitoring_findings, 'MONITORING')
        }
        
        # Generate comprehensive risk report
        report = {
            'timestamp': datetime.now().isoformat(),
            'overall_risk_score': sum(a.risk_score for a in assessments.values()),
            'category_assessments': {
                category: {
                    'threat_event_frequency': metrics.threat_event_frequency,
                    'vulnerability_score': metrics.vulnerability,
                    'loss_magnitude': metrics.loss_magnitude,
                    'risk_score': metrics.risk_score
                } for category, metrics in assessments.items()
            },
            'risk_categories': {
                category: 'HIGH' if metrics.risk_score > 1000000 else
                          'MEDIUM' if metrics.risk_score > 100000 else
                          'LOW'
                for category, metrics in assessments.items()
            }
        }
        
        # Output the report
        print(json.dumps(report, indent=2))
        
        # Save the report
        with open('fair_risk_assessment.json', 'w') as f:
            json.dumps(report, f, indent=2)
            
    except FileNotFoundError as e:
        print(f"Error: Could not find findings file: {e}")
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in findings file: {e}")
    except Exception as e:
        print(f"Error performing risk assessment: {e}")

if __name__ == '__main__':
    main()
