'''
HTML Dashboard Generator
Crea dashboard interattivo vulnerabilità
'''

import os
import json
from datetime import datetime
from pathlib import Path


class DashboardGenerator:
    '''Genera dashboard HTML per scan results'''
    
    def __init__(self, output_dir='reports'):
        '''Initialize generator'''
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_dashboard(self, scan_results, plots_dir='reports/plots'):
        '''
        Genera dashboard HTML completo
        
        Args:
            scan_results: dict con results (from parse_with_ml)
            plots_dir: directory con grafici
            
        Returns:
            str: path al file HTML
        '''
        vulnerabilities = scan_results.get('vulnerabilities', [])
        summary = scan_results.get('summary', {})
        
        # Generate HTML
        html = self._generate_html_template(vulnerabilities, summary, plots_dir)
        
        # Save
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'dashboard_{timestamp}.html'
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f'✓ Dashboard salvato: {filepath}')
        return filepath
    
    def _generate_html_template(self, vulnerabilities, summary, plots_dir):
        '''Generate complete HTML'''
        
        # Calculate stats
        total = summary.get('total', len(vulnerabilities))
        by_severity = summary.get('by_severity', {})
        by_priority = summary.get('by_priority', {})
        top_risks = summary.get('top_risks', [])
        
        # Count critical/urgent
        critical_count = by_severity.get('CRITICAL', 0)
        urgent_count = by_priority.get(1, 0)
        
        # Average risk
        ml_vulns = [v for v in vulnerabilities 
                   if v.get('ml_analysis', {}).get('ml_available')]
        avg_risk = 0
        if ml_vulns:
            risks = [v['ml_analysis']['risk_score'] for v in ml_vulns]
            avg_risk = sum(risks) / len(risks)
        
        html = f'''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            background: white;
            padding: 2rem;
            border-radius: 15px;
            margin-bottom: 2rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        h1 {{
            color: #667eea;
            margin-bottom: 0.5rem;
        }}
        
        .subtitle {{
            color: #666;
            font-size: 1.1rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            margin: 0.5rem 0;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9rem;
            text-transform: uppercase;
        }}
        
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        
        .chart-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .chart-card h2 {{
            margin-bottom: 1rem;
            color: #667eea;
        }}
        
        .chart-card img {{
            width: 100%;
            height: auto;
            border-radius: 10px;
        }}
        
        .vulnerability-list {{
            background: white;
            padding: 1.5rem;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .vulnerability-item {{
            padding: 1rem;
            border-left: 4px solid #ddd;
            margin-bottom: 1rem;
            background: #f9f9f9;
            border-radius: 5px;
        }}
        
        .vulnerability-item.critical {{ border-left-color: #d32f2f; }}
        .vulnerability-item.high {{ border-left-color: #f57c00; }}
        .vulnerability-item.medium {{ border-left-color: #fbc02d; }}
        .vulnerability-item.low {{ border-left-color: #388e3c; }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}
        
        .vuln-cve {{
            font-weight: bold;
            font-size: 1.1rem;
        }}
        
        .vuln-score {{
            background: #667eea;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.9rem;
        }}
        
        .recommendation {{
            margin-top: 0.5rem;
            padding: 0.5rem;
            background: #fff3cd;
            border-radius: 5px;
            font-size: 0.9rem;
        }}
        
        footer {{
            text-align: center;
            color: white;
            margin-top: 2rem;
            padding: 1rem;
        }}
        
        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Vulnerability Dashboard</h1>
            <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-value">{total}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Critical Issues</div>
                <div class="stat-value critical">{critical_count}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Urgent Actions</div>
                <div class="stat-value high">{urgent_count}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Average Risk Score</div>
                <div class="stat-value medium">{avg_risk:.2f}</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-card">
                <h2>📊 Severity Distribution</h2>
                <img src="{plots_dir}/severity_dist.png" alt="Severity Distribution">
            </div>
            
            <div class="chart-card">
                <h2>🎯 Priority Distribution</h2>
                <img src="{plots_dir}/priority_dist.png" alt="Priority Distribution">
            </div>
            
            <div class="chart-card">
                <h2>📈 Risk Score Distribution</h2>
                <img src="{plots_dir}/risk_dist.png" alt="Risk Distribution">
            </div>
            
            <div class="chart-card">
                <h2>🔝 Top Vulnerabilities</h2>
                <img src="{plots_dir}/top_vulns.png" alt="Top Vulnerabilities">
            </div>
        </div>
        
        <div class="vulnerability-list">
            <h2>🚨 Top 10 Highest Risk Vulnerabilities</h2>
'''
        
        # Add top 10 vulnerabilities
        ml_vulns = [v for v in vulnerabilities 
                   if v.get('ml_analysis', {}).get('ml_available')]
        top_10 = sorted(ml_vulns, 
                       key=lambda x: x['ml_analysis']['risk_score'],
                       reverse=True)[:10]
        
        for vuln in top_10:
            cve_id = vuln.get('cve_id', 'Unknown')
            severity = vuln.get('severity', 'UNKNOWN').lower()
            cvss = vuln.get('cvss_score', 0)
            ml = vuln.get('ml_analysis', {})
            risk = ml.get('risk_score', 0)
            priority = ml.get('priority', 4)
            recommendation = ml.get('recommendation', '')
            
            html += f'''
            <div class="vulnerability-item {severity}">
                <div class="vuln-header">
                    <span class="vuln-cve">{cve_id}</span>
                    <span class="vuln-score">Risk: {risk:.2f}/10</span>
                </div>
                <div>
                    <strong>CVSS:</strong> {cvss} | 
                    <strong>Severity:</strong> {severity.upper()} | 
                    <strong>Priority:</strong> {priority}
                </div>
                <div class="recommendation">
                    💡 {recommendation}
                </div>
            </div>
'''
        
        html += '''
        </div>
        
        <footer>
            <p>Generated by AI Security Scanner 🤖</p>
            <p>Machine Learning Enhanced | NVD Integrated</p>
        </footer>
    </div>
</body>
</html>
'''
        
        return html


if __name__ == '__main__':
    # Test
    print('='*60)
    print('TEST DASHBOARD GENERATOR')
    print('='*60)
    
    # Mock data
    test_results = {
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2024-0001',
                'cvss_score': 9.8,
                'severity': 'CRITICAL',
                'ml_analysis': {
                    'ml_available': True,
                    'risk_score': 9.5,
                    'priority': 1,
                    'recommendation': '🔴 AZIONE IMMEDIATA!'
                }
            },
            {
                'cve_id': 'CVE-2024-0002',
                'cvss_score': 7.5,
                'severity': 'HIGH',
                'ml_analysis': {
                    'ml_available': True,
                    'risk_score': 7.8,
                    'priority': 2,
                    'recommendation': '🟠 Patch entro 1 settimana'
                }
            },
        ],
        'summary': {
            'total': 2,
            'by_severity': {'CRITICAL': 1, 'HIGH': 1},
            'by_priority': {1: 1, 2: 1},
            'top_risks': []
        }
    }
    
    generator = DashboardGenerator()
    filepath = generator.generate_dashboard(test_results)
    
    print(f'\\n✓ Apri con browser: {filepath}')
    print('='*60)
