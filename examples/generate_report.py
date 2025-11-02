#!/usr/bin/env python3
'''
Complete Report Generator
Scan → Analysis → Visualization → Dashboard
'''

import sys
import os
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser.xml_parser import parse_with_ml
from src.visualization.plotter import VulnerabilityPlotter
from src.visualization.dashboard import DashboardGenerator
from src.security.attack_surface import AttackSurfaceAnalyzer
from src.security.threat_model import ThreatModeler
from src.security.recommendations import SecurityRecommendations

def generate_complete_report(xml_file, use_nvd=False):
    '''Generate complete security report'''
    
    print("="*70)
    print("COMPLETE SECURITY REPORT GENERATOR")
    print("="*70)
    
    # Step 1: Parse and analyze
    print("\n[STEP 1/5] Parsing and ML Analysis...")
    try:
        results = parse_with_ml(xml_file, use_ml=True, use_nvd=use_nvd)
    except Exception as e:
        print(f"✗ Error parsing XML: {e}")
        return None
    
    vulnerabilities = results.get('vulnerabilities', [])
    
    if not vulnerabilities:
        print("⚠ No vulnerabilities found")
        return None
    
    print(f"✓ Found {len(vulnerabilities)} vulnerabilities")
    
    # Step 2: Security Analysis
    print("\n[STEP 2/5] Security Analysis...")
    
    # Initialize results for security analysis
    surface = None
    threat_report = None
    recommendations = None
    
    # Attack Surface
    try:
        print("  • Analyzing attack surface...")
        surface_analyzer = AttackSurfaceAnalyzer()
        surface = surface_analyzer.analyze_surface(vulnerabilities)
        
        # Safe access with .get()
        print(f"    - Attack Surface Score: {surface.get('total_score', 0)}")
        print(f"    - Risk Level: {surface.get('risk_level', 'UNKNOWN')}")
        print(f"    - Entry Points: {len(surface.get('entry_points', []))}")
    except Exception as e:
        print(f"    ⚠ Warning: Attack surface analysis failed: {e}")
        surface = {
            'total_score': 0,
            'entry_points': [],
            'risk_level': 'UNKNOWN',
            'summary': f'Analysis failed: {e}'
        }
    
    # Threat Modeling
    try:
        print("  • Generating threat model (STRIDE)...")
        threat_modeler = ThreatModeler()
        threat_report = threat_modeler.generate_threat_report(vulnerabilities)
        
        print(f"    - Threats identified: {len(threat_report.get('threats', []))}")
        print(f"    - STRIDE categories: {len(threat_report.get('by_category', {}))}")
    except Exception as e:
        print(f"    ⚠ Warning: Threat modeling failed: {e}")
        threat_report = {
            'threats': [],
            'summary': f'Analysis failed: {e}',
            'by_category': {}
        }
    
    # Recommendations
    try:
        print("  • Generating security recommendations...")
        rec_gen = SecurityRecommendations()
        recommendations = rec_gen.generate_recommendations(results)
        
        print(f"    - Recommendations: {len(recommendations.get('recommendations', []))}")
        print(f"    - Immediate actions: {len(recommendations.get('action_items', []))}")
    except Exception as e:
        print(f"    ⚠ Warning: Recommendations generation failed: {e}")
        recommendations = {
            'recommendations': [],
            'action_items': [],
            'summary': f'Generation failed: {e}'
        }
    
    # Add to results
    results['security_analysis'] = {
        'attack_surface': surface,
        'threat_model': threat_report,
        'recommendations': recommendations
    }
    
    print("✓ Security analysis complete")
    
    # Step 3: Generate plots
    print("\n[STEP 3/5] Generating Visualizations...")
    try:
        plotter = VulnerabilityPlotter()
        plots = plotter.create_all_plots(vulnerabilities)
        print("✓ All plots created")
    except Exception as e:
        print(f"⚠ Warning: Plot generation failed: {e}")
        plots = []
    
    # Step 4: Generate dashboard
    print("\n[STEP 4/5] Creating Dashboard...")
    try:
        dashboard_gen = DashboardGenerator()
        dashboard_path = dashboard_gen.generate_dashboard(results)
        print(f"✓ Dashboard: {dashboard_path}")
    except Exception as e:
        print(f"⚠ Warning: Dashboard generation failed: {e}")
        dashboard_path = None
    
    # Step 5: Save JSON report
    print("\n[STEP 5/5] Saving JSON Report...")
    try:
        report_path = xml_file.replace('.xml', '_complete_report.json')
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"✓ JSON Report: {report_path}")
    except Exception as e:
        print(f"⚠ Warning: JSON save failed: {e}")
        report_path = None
    
    # Summary
    print("\n" + "="*70)
    print("REPORT GENERATION COMPLETE!")
    print("="*70)
    
    summary = results.get('summary', {})
    print(f"\n📊 Vulnerability Summary:")
    print(f"  Total Vulnerabilities: {summary.get('total', 0)}")
    print(f"  Critical: {summary.get('by_severity', {}).get('CRITICAL', 0)}")
    print(f"  High: {summary.get('by_severity', {}).get('HIGH', 0)}")
    print(f"  Medium: {summary.get('by_severity', {}).get('MEDIUM', 0)}")
    print(f"  Low: {summary.get('by_severity', {}).get('LOW', 0)}")
    
    if summary.get('by_priority'):
        print(f"\n🎯 Priority Distribution:")
        for priority in sorted(summary['by_priority'].keys()):
            count = summary['by_priority'][priority]
            labels = {1: 'URGENT', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW'}
            print(f"  Priority {priority} ({labels.get(priority, 'N/A'):7s}): {count}")
    
    # Security Analysis Summary
    if surface:
        print(f"\n🔒 Security Analysis Summary:")
        print(f"  Attack Surface Score: {surface.get('total_score', 0)} ({surface.get('risk_level', 'UNKNOWN')})")
        print(f"  Top Entry Points: {len(surface.get('entry_points', []))}")
        
        if threat_report:
            print(f"  Threats Identified: {len(threat_report.get('threats', []))}")
            if threat_report.get('by_category'):
                print(f"  STRIDE Categories: {', '.join(threat_report['by_category'].keys())}")
        
        if recommendations:
            print(f"  Recommendations: {len(recommendations.get('recommendations', []))}")
            print(f"  Immediate Actions: {len(recommendations.get('action_items', []))}")
    
    print(f"\n📁 Generated Files:")
    if plots:
        print(f"  📊 Plots: reports/plots/")
    if dashboard_path:
        print(f"  🖥️  Dashboard: {dashboard_path}")
    if report_path:
        print(f"  📄 JSON: {report_path}")
    
    print("\n💡 Next Steps:")
    if dashboard_path:
        print(f"  1. Open dashboard: xdg-open {dashboard_path}")
    if report_path:
        print(f"  2. Review JSON: cat {report_path} | python3 -m json.tool | less")
        print(f"  3. Check security analysis:")
        print(f"     cat {report_path} | python3 -m json.tool | grep -A 50 'security_analysis'")
    print(f"  4. Share with team!")
    
    print("\n" + "="*70)
    
    return {
        'dashboard': dashboard_path,
        'json': report_path,
        'plots': plots,
        'security_analysis': results.get('security_analysis')
    }


def main():
    if len(sys.argv) < 2:
        print("\nUsage: python3 generate_report.py <nmap_xml_file> [--nvd]")
        print("\nExample:")
        print("  python3 generate_report.py scan.xml")
        print("  python3 generate_report.py scan.xml --nvd")
        return
    
    xml_file = sys.argv[1]
    use_nvd = '--nvd' in sys.argv
    
    if not os.path.exists(xml_file):
        print(f"✗ File not found: {xml_file}")
        return
    
    try:
        result = generate_complete_report(xml_file, use_nvd)
        if result:
            print("\n✅ Success!")
        else:
            print("\n⚠ Report generation completed with warnings")
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main() or 0)
