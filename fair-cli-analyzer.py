import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pyfair import FairModel
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
import io
from typing import Dict, List, Tuple, Any
import statistics

class EnhancedRiskAnalyzer:
    def __init__(self, historical_data_path: str = None):
        """
        Initialize the risk analyzer with optional historical data
        
        Args:
            historical_data_path: Path to JSON file containing historical Prowler scans
        """
        self.historical_data = None
        if historical_data_path:
            with open(historical_data_path, 'r') as f:
                self.historical_data = json.load(f)
        
        # Define risk levels and their associated costs
        self.severity_costs = {
            'critical': 1000000,
            'high': 500000,
            'medium': 100000,
            'low': 10000
        }
        
        # Define confidence levels for intervals
        self.confidence_levels = [0.90, 0.95, 0.99]
        
    def analyze_findings(self, findings: List[dict]) -> Dict[str, Any]:
        """
        Analyze Prowler findings and generate comprehensive statistics
        """
        # Group findings by service
        services = defaultdict(lambda: defaultdict(int))
        severities = defaultdict(int)
        compliances = defaultdict(int)
        resource_types = defaultdict(int)
        
        for finding in findings:
            severity = finding.get('severity', 'unknown').lower()
            service = finding.get('service', 'unknown')
            compliance = finding.get('compliance', {}).get('status', 'unknown')
            resource = finding.get('resource_type', 'unknown')
            
            severities[severity] += 1
            services[service][severity] += 1
            compliances[compliance] += 1
            resource_types[resource] += 1
        
        return {
            'services': dict(services),
            'severities': dict(severities),
            'compliances': dict(compliances),
            'resource_types': dict(resource_types)
        }

    def calculate_confidence_intervals(self, model: FairModel) -> Dict[str, Dict[float, Tuple[float, float]]]:
        """
        Calculate confidence intervals for risk metrics at different confidence levels
        """
        params = model.export_params()
        intervals = {}
        
        for param_name, param_data in params.items():
            if isinstance(param_data, dict) and 'low' in param_data:
                param_intervals = {}
                for conf_level in self.confidence_levels:
                    lower = param_data['low']
                    upper = param_data['high']
                    mean = (lower + 4 * param_data['mode'] + upper) / 6
                    std = (upper - lower) / 6
                    
                    z_score = statistics.NormalDist().inv_cdf((1 + conf_level) / 2)
                    margin = z_score * std
                    
                    param_intervals[conf_level] = (mean - margin, mean + margin)
                
                intervals[param_name] = param_intervals
        
        return intervals

    def generate_trend_analysis(self, current_findings: List[dict]) -> Dict[str, Any]:
        """
        Generate trend analysis if historical data is available
        """
        if not self.historical_data:
            return None
            
        trend_data = {
            'severity_trends': [],
            'compliance_trends': [],
            'service_trends': []
        }
        
        # Analyze historical data points
        for historical_point in self.historical_data:
            analysis = self.analyze_findings(historical_point['findings'])
            trend_data['severity_trends'].append({
                'date': historical_point['date'],
                'severities': analysis['severities']
            })
            
        # Add current findings to trends
        current_analysis = self.analyze_findings(current_findings)
        trend_data['severity_trends'].append({
            'date': datetime.now().strftime('%Y-%m-%d'),
            'severities': current_analysis['severities']
        })
        
        return trend_data

    def generate_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Generate specific recommendations based on findings analysis
        """
        recommendations = []
        
        # Critical severity recommendations
        if analysis['severities'].get('critical', 0) > 0:
            recommendations.append({
                'priority': 'Immediate',
                'finding': 'Critical Security Issues',
                'recommendation': 'Immediately address critical security findings. Consider implementing emergency change procedures.',
                'impact': 'Critical findings represent immediate risk to security posture.'
            })
            
        # Service-specific recommendations
        for service, severities in analysis['services'].items():
            if severities.get('high', 0) + severities.get('critical', 0) > 2:
                recommendations.append({
                    'priority': 'High',
                    'finding': f'Multiple High-Risk Issues in {service}',
                    'recommendation': f'Conduct detailed security review of {service} configuration and implement security hardening.',
                    'impact': 'Multiple high-risk findings may indicate systematic security gaps.'
                })
                
        # Compliance recommendations
        if analysis['compliances'].get('fail', 0) > 0:
            recommendations.append({
                'priority': 'High',
                'finding': 'Compliance Failures',
                'recommendation': 'Review and remediate compliance failures. Update compliance monitoring procedures.',
                'impact': 'Non-compliant resources may violate organizational or regulatory requirements.'
            })
            
        return recommendations

    def create_enhanced_report(self, results: Dict[str, Any], output_path: str, company_name: str):
        """
        Create an enhanced PDF report with all analysis components
        """
        # Configure document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Add custom styles
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        ))
        
        # Executive Summary
        elements.extend(self._create_executive_summary(results, styles))
        elements.append(PageBreak())
        
        # Risk Analysis
        elements.extend(self._create_risk_analysis_section(results, styles))
        elements.append(PageBreak())
        
        # Trend Analysis
        if self.historical_data:
            elements.extend(self._create_trend_analysis_section(results, styles))
            elements.append(PageBreak())
        
        # Service Breakdown
        elements.extend(self._create_service_breakdown_section(results, styles))
        elements.append(PageBreak())
        
        # Recommendations
        elements.extend(self._create_recommendations_section(results, styles))
        
        # Build the PDF
        doc.build(elements)

    def _create_executive_summary(self, results: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """
        Create executive summary section
        """
        elements = []
        
        # Title
        elements.append(Paragraph("Executive Summary", styles['CustomTitle']))
        
        # Key metrics summary
        summary_data = [
            ["Metric", "Value"],
            ["Total Findings", str(sum(results['analysis']['severities'].values()))],
            ["Critical Findings", str(results['analysis']['severities'].get('critical', 0))],
            ["High Risk Findings", str(results['analysis']['severities'].get('high', 0))],
            ["Compliance Failures", str(results['analysis']['compliances'].get('fail', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
        
        return elements

    def _create_risk_analysis_section(self, results: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """
        Create detailed risk analysis section with visualizations
        """
        elements = []
        
        elements.append(Paragraph("Risk Analysis", styles['Heading1']))
        
        # Add risk visualization
        risk_viz = self._create_risk_visualization(results['model'])
        elements.append(risk_viz)
        elements.append(Spacer(1, 20))
        
        # Add confidence intervals
        intervals = self.calculate_confidence_intervals(results['model'])
        interval_data = [["Metric", "90% Confidence", "95% Confidence", "99% Confidence"]]
        
        for metric, values in intervals.items():
            row = [metric]
            for conf_level in self.confidence_levels:
                low, high = values[conf_level]
                row.append(f"${low:,.0f} - ${high:,.0f}")
            interval_data.append(row)
            
        interval_table = Table(interval_data, colWidths=[2*inch, 2*inch, 2*inch, 2*inch])
        interval_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(interval_table)
        
        return elements

    def _create_trend_analysis_section(self, results: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """
        Create trend analysis section with visualizations
        """
        elements = []
        
        elements.append(Paragraph("Trend Analysis", styles['Heading1']))
        
        # Create trend visualization
        trend_viz = self._create_trend_visualization(results['trends'])
        elements.append(trend_viz)
        
        return elements

    def _create_service_breakdown_section(self, results: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """
        Create service breakdown section
        """
        elements = []
        
        elements.append(Paragraph("Service Breakdown", styles['Heading1']))
        
        # Create service breakdown table
        service_data = [["Service", "Critical", "High", "Medium", "Low"]]
        
        for service, severities in results['analysis']['services'].items():
            row = [
                service,
                str(severities.get('critical', 0)),
                str(severities.get('high', 0)),
                str(severities.get('medium', 0)),
                str(severities.get('low', 0))
            ]
            service_data.append(row)
            
        service_table = Table(service_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        service_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(service_table)
        
        return elements

    def _create_recommendations_section(self, results: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """
        Create recommendations section
        """
        elements = []
        
        elements.append(Paragraph("Recommendations", styles['Heading1']))
        
        recommendations = self.generate_recommendations(results['analysis'])
        
        for rec in recommendations:
            elements.append(Paragraph(f"Priority: {rec['priority']}", styles['Heading2']))
            elements.append(Paragraph(f"Finding: {rec['finding']}", styles['Normal']))
            elements.append(Paragraph(f"Recommendation: {rec['recommendation']}", styles['Normal']))
            elements.append(Paragraph(f"Impact: {rec['impact']}", styles['Normal']))
            elements.append(Spacer(1, 10))
            
        return elements

    def _create_risk_visualization(self, model: FairModel) -> Image:
        """
        Create risk visualization using matplotlib
        """
        plt.figure(figsize=(10, 6))
        # Create visualization using model data
        # This will need to be customized based on available pyfair methods
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
        buf.seek(0)
        return Image(buf)

    def _create_trend_visualization(self, trend_data: Dict[str, Any]) -> Image:
        """
        Create trend visualization
        """
        plt.figure(figsize=(10, 6))
        # Create trend visualization
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
        buf.seek(0)
        return Image(buf)

def analyze_prowler_risks(ocsf_file_path, pdf_output_path, company_name):
    """
    Main function to analyze Prowler findings and generate enhanced report
    """
    # Initialize analyzer
    analyzer = EnhancedRiskAnalyzer(historical_data_path)
    
    # Load current findings
    with open(ocsf_file_path, 'r') as f:
        findings = json.load(f)
    
    # Analyze findings
    analysis = analyzer.analyze_findings(findings)
    
    # Create FAIR model
    model = prowler_to_fair(findings)
    model.calculate_all()
    
    # Generate trend analysis
    trends = analyzer.generate_trend_analysis(findings)
    
    # Compile results
    results = {
        'model': model,
        'analysis': analysis,
        'trends': trends,
        'recommendations': analyzer.generate_recommendations(analysis)
    }
    
    # Generate PDF report if path is provided
    if pdf_output_path:
        analyzer.create_enhanced_report(results, pdf_output_path, company_name)
    
    return results

def validate_pert_inputs(low, mode, high, param_name=""):
    """
    Validate and adjust inputs to meet PERT distribution requirements:
    - low <= mode <= high
    - all values must be positive
    """
    low = max(0.1, low)
    mode = max(low, mode)
    high = max(mode, high)
    return low, mode, high

def prowler_to_fair(ocsf_file_path):
    """
    Convert Prowler OCSF findings to FAIR model inputs
    """
    # Load OCSF data
    with open(ocsf_file_path, 'r') as f:
        findings = json.load(f)
    
    # Initialize counters
    severity_counts = defaultdict(int)
    compliance_status = defaultdict(int)
    
    # Process findings
    for finding in findings:
        severity = finding.get('severity', 'unknown').lower()
        severity_counts[severity] += 1
        
        status = finding.get('compliance', {}).get('status', 'unknown')
        compliance_status[status] += 1
    
    total_findings = max(1, sum(severity_counts.values()))
    
    # Create FAIR model
    model = FairModel('Cloud Security Risk Assessment')
    
    # Set Contact Frequency
    cf_low, cf_mode, cf_high = validate_pert_inputs(
        total_findings * 0.8,
        total_findings,
        total_findings * 1.2
    )
    model.input_data('Contact Frequency', low=cf_low, mode=cf_mode, high=cf_high)
    
    # Set Probability of Action
    prob_action = (severity_counts.get('critical', 0) + severity_counts.get('high', 0)) / total_findings
    pa_low, pa_mode, pa_high = validate_pert_inputs(
        max(0.1, prob_action - 0.1),
        max(0.1, prob_action),
        min(1.0, prob_action + 0.1)
    )
    model.input_data('Probability of Action', low=pa_low, mode=pa_mode, high=pa_high)
    
    # Set Control Strength
    compliant = compliance_status.get('pass', 0)
    control_strength = max(0.1, compliant / total_findings if total_findings > 0 else 0.5)
    cs_low, cs_mode, cs_high = validate_pert_inputs(
        max(0.1, control_strength - 0.1),
        control_strength,
        min(1.0, control_strength + 0.1)
    )
    model.input_data('Control Strength', low=cs_low, mode=cs_mode, high=cs_high)
    
    # Set Threat Capability
    threat_capability = max(0.1, (
        severity_counts.get('critical', 0) * 0.9 +
        severity_counts.get('high', 0) * 0.7 +
        severity_counts.get('medium', 0) * 0.5 +
        severity_counts.get('low', 0) * 0.3
    ) / total_findings)
    
    tc_low, tc_mode, tc_high = validate_pert_inputs(
        max(0.1, threat_capability - 0.1),
        threat_capability,
        min(1.0, threat_capability + 0.1)
    )
    model.input_data('Threat Capability', low=tc_low, mode=tc_mode, high=tc_high)
    
    # Set Primary Loss
    severity_costs = {
        'critical': 1000000,
        'high': 500000,
        'medium': 100000,
        'low': 10000
    }
    
    primary_loss = max(10000, sum(severity_counts[sev] * severity_costs.get(sev, 0) 
                                 for sev in severity_costs))
    
    pl_low, pl_mode, pl_high = validate_pert_inputs(
        primary_loss * 0.7,
        primary_loss,
        primary_loss * 1.3
    )
    model.input_data('Primary Loss', low=pl_low, mode=pl_mode, high=pl_high)
    
    # Set Secondary Loss parameters
    model.input_data('Secondary Loss Event Frequency', low=0.2, mode=0.3, high=0.4)
    
    slm_low, slm_mode, slm_high = validate_pert_inputs(
        primary_loss * 0.3,
        primary_loss * 0.5,
        primary_loss * 0.7
    )
    model.input_data('Secondary Loss Event Magnitude', low=slm_low, mode=slm_mode, high=slm_high)
    
    return model

def create_simple_report(results, output_path, company_name="Your Company"):
    """
    Create a simple PDF report with the model parameters
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Add custom title style
    styles.add(ParagraphStyle(
        name='CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    ))
    
    # Title
    elements.append(Paragraph(
        f"Cloud Security Risk Assessment Report<br/>{company_name}",
        styles['CustomTitle']
    ))
    
    # Model Parameters
    elements.append(Paragraph("Model Parameters", styles['Heading1']))
    
    # Create table with model parameters
    data = [["Parameter", "Low", "Most Likely", "High"]]
    model = results['model']
    params = model.export_params()
    
    for param_name, param_data in params.items():
        if isinstance(param_data, dict) and 'low' in param_data:
            row = [
                param_name,
                f"{param_data['low']:,.2f}",
                f"{param_data['mode']:,.2f}",
                f"{param_data['high']:,.2f}"
            ]
            data.append(row)
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(table)
    
    # Build the PDF
    doc.build(elements)


if __name__ == "__main__":
    try:
        # File paths
        ocsf_file_path = "dummy.ocsf.json"
        pdf_output_path = "risk_analysis_report.pdf"
        company_name = "Your Company Name"

        # Run the analysis without historical data parameter
        results = analyze_prowler_risks(
            ocsf_file_path=ocsf_file_path,
            pdf_output_path=pdf_output_path,
            company_name=company_name
        )

        print("\nRisk Analysis Complete")
        print(f"PDF report has been generated: {pdf_output_path}")

    except Exception as e:
        print(f"Error analyzing risks: {str(e)}")