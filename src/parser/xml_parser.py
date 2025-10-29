
'''
XML Parser for Nmap Output
Parses Nmap XML output into structured Python dictionaries
'''

import xml.etree.ElementTree as ET
import os
from typing import Dict, List, Optional
# New imports for ML integration
from src.ml.analyzer import VulnerabilityAnalyzer
from src.utils.risk_scorer import RiskScorer
from src.nvd.nvd_client import NVDClient

class NmapXMLParser:
    '''Parser for Nmap XML output files'''
    
    def __init__(self, xml_file: str):
        '''
        Initialize parser with XML file
        
        Args:
            xml_file (str): Path to Nmap XML output file
        '''
        self.xml_file = xml_file
        self.tree = None
        self.root = None
        self._parse_file()
    
    def _parse_file(self):
        '''Parse XML file and set tree/root'''
        try:
            self.tree = ET.parse(self.xml_file)
            self.root = self.tree.getroot()
        except ET.ParseError as e:
            raise Exception(f'XML parsing error: {e}')
        except FileNotFoundError:
            raise Exception(f'XML file not found: {self.xml_file}')
    
    def get_scan_info(self) -> Dict:
        '''
        Extract scan metadata
        
        Returns:
            dict: Scan information
        '''
        return {
            'scanner': self.root.get('scanner'),
            'args': self.root.get('args'),
            'start_time': self.root.get('start'),
            'version': self.root.get('version')
        }
    
    def parse_host(self, host_elem) -> Dict:
        '''
        Parse single host element
        
        Args:
            host_elem: XML element for host
        
        Returns:
            dict: Parsed host data
        '''
        host_data = {
            'status': {},
            'addresses': [],
            'hostnames': [],
            'ports': []
        }
        
        # Status
        status = host_elem.find('status')
        if status is not None:
            host_data['status'] = {
                'state': status.get('state'),
                'reason': status.get('reason')
            }
        
        # Addresses
        for addr in host_elem.findall('address'):
            host_data['addresses'].append({
                'addr': addr.get('addr'),
                'addrtype': addr.get('addrtype')
            })
        
        # Hostnames
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            for hostname in hostnames.findall('hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name'),
                    'type': hostname.get('type')
                })
        
        # Ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
        
        return host_data
    
    def _parse_port(self, port_elem) -> Optional[Dict]:
        '''
        Parse single port element
        
        Args:
            port_elem: XML element for port
        
        Returns:
            dict: Parsed port data
        '''
        port_data = {
            'portid': port_elem.get('portid'),
            'protocol': port_elem.get('protocol'),
            'state': {},
            'service': {}
        }
        
        # State
        state = port_elem.find('state')
        if state is not None:
            port_data['state'] = {
                'state': state.get('state'),
                'reason': state.get('reason')
            }
        
        # Service
        service = port_elem.find('service')
        if service is not None:
            port_data['service'] = {
                'name': service.get('name'),
                'product': service.get('product'),
                'version': service.get('version')
            }
        
        return port_data
    
    def parse_all_hosts(self) -> List[Dict]:
        '''
        Parse all hosts in scan
        
        Returns:
            list: List of parsed host dictionaries
        '''
        hosts = []
        for host_elem in self.root.findall('host'):
            host_data = self.parse_host(host_elem)
            hosts.append(host_data)
        return hosts
    
    def parse_complete(self) -> Dict:
        '''
        Parse complete scan output
        
        Returns:
            dict: Complete parsed data
        '''
        return {
            'scan_info': self.get_scan_info(),
            'hosts': self.parse_all_hosts()
        }


# Test code
if __name__ == '__main__':
    import sys
    
    # Need XML file to test
    xml_file = 'test_scan.xml'
    
    if not os.path.exists(xml_file):
        print(f'Error: {xml_file} not found!')
        print('Run nmap_wrapper.py first to create XML file.')
        sys.exit(1)
    
    try:
        parser = NmapXMLParser(xml_file)
        
        print('=== Scan Info ===')
        scan_info = parser.get_scan_info()
        for key, value in scan_info.items():
            print(f'{key}: {value}')
        
        print('\\n=== Hosts ===')
        hosts = parser.parse_all_hosts()
        print(f'Found {len(hosts)} host(s)')
        
        for host in hosts:
            ip = host['addresses'][0]['addr'] if host['addresses'] else 'N/A'
            state = host['status'].get('state', 'unknown')
            print(f'\\nHost: {ip} - {state}')
            print(f'  Ports: {len(host["ports"])} found')
            
            for port in host['ports'][:5]:  # Show first 5
                portid = port['portid']
                port_state = port['state'].get('state')
                service = port['service'].get('name', 'unknown')
                print(f'    {portid}/{port["protocol"]}: {port_state} ({service})')
    
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)
class EnhancedVulnerabilityParser:
    '''Parser with ML and NVD enhancement'''
    
    def __init__(self, use_ml=True, use_risk_scorer=True, use_nvd=False):
        '''Initialize enhanced parser'''
        self.use_ml = use_ml
        self.use_risk_scorer = use_risk_scorer
        self.use_nvd = use_nvd
        
        self.ml_analyzer = None
        self.risk_scorer = None
        self.nvd_client = None
        
        if self.use_ml:
            try:
                self.ml_analyzer = VulnerabilityAnalyzer()
                print("✓ ML Analyzer inizializzato")
            except Exception as e:
                print(f"⚠ ML Analyzer non disponibile: {e}")
                self.use_ml = False
        
        if self.use_risk_scorer:
            self.risk_scorer = RiskScorer()
            print("✓ Risk Scorer inizializzato")
        
        if self.use_nvd:
            try:
                self.nvd_client = NVDClient()
                print("✓ NVD Client inizializzato")
            except Exception as e:
                print(f"⚠ NVD Client non disponibile: {e}")
                self.use_nvd = False
    
    def parse_and_enhance(self, xml_file):
        '''Parse XML and apply enhancements'''
        print(f"\n[1/4] Parsing XML: {xml_file}")
        vulnerabilities = parse_nmap_xml(xml_file)
        print(f"  → {len(vulnerabilities)} vulnerabilità trovate")
        
        if not vulnerabilities:
            return {'vulnerabilities': [], 'summary': {}}
        
        # NVD Enhancement
        if self.use_nvd and self.nvd_client:
            print(f"\n[2/4] Arricchimento NVD...")
            vulnerabilities = self._apply_nvd_enrichment(vulnerabilities)
        else:
            print(f"\n[2/4] NVD Enhancement disabilitato")
        
        # ML Analysis
        if self.use_ml and self.ml_analyzer:
            print(f"\n[3/4] Analisi ML...")
            vulnerabilities = self._apply_ml_analysis(vulnerabilities)
        else:
            print(f"\n[3/4] ML Analysis disabilitato")
        
        # Summary
        print(f"\n[4/4] Generazione summary...")
        summary = self._generate_summary(vulnerabilities)
        
        return {
            'vulnerabilities': vulnerabilities,
            'summary': summary,
            'ml_enabled': self.use_ml,
            'nvd_enabled': self.use_nvd,
            'risk_scoring_enabled': self.use_risk_scorer
        }
    
    def _apply_nvd_enrichment(self, vulnerabilities):
        '''Enrich with NVD data'''
        enriched = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  Enriching {i}/{len(vulnerabilities)}...", end='\r')
            
            try:
                enriched_vuln = self.nvd_client.enrich_vulnerability(vuln)
                enriched.append(enriched_vuln)
            except Exception as e:
                print(f"\n⚠ Errore NVD per {vuln.get('cve_id')}: {e}")
                enriched.append(vuln)
        
        print(f"  ✓ NVD enrichment complete")
        return enriched
    
    def _apply_ml_analysis(self, vulnerabilities):
        '''Apply ML analysis'''
        enhanced = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  Analyzing {i}/{len(vulnerabilities)}...", end='\r')
            
            try:
                ml_result = self.ml_analyzer.analyze(vuln)
                
                if self.use_risk_scorer and self.risk_scorer:
                    risk_score = self.risk_scorer.calculate_risk_score(vuln, ml_result)
                    priority = self.risk_scorer.get_priority(risk_score)
                    
                    ml_result['risk_score'] = float(risk_score)
                    ml_result['priority'] = int(priority)
                    ml_result['priority_label'] = self.risk_scorer.get_priority_label(priority)
                    ml_result['timeframe'] = self.risk_scorer.get_timeframe(priority)
                
                vuln['ml_analysis'] = ml_result
                
            except Exception as e:
                print(f"\n⚠ Errore ML: {e}")
                vuln['ml_analysis'] = {'ml_available': False, 'error': str(e)}
            
            enhanced.append(vuln)
        
        print(f"  ✓ ML analysis complete")
        return enhanced
    
    def _generate_summary(self, vulnerabilities):
        '''Generate summary statistics'''
        summary = {
            'total': len(vulnerabilities),
            'by_severity': {},
            'by_priority': {},
            'top_risks': [],
            'nvd_enriched_count': 0
        }
        
        for vuln in vulnerabilities:
            # Count NVD enrichment
            if vuln.get('nvd_enriched'):
                summary['nvd_enriched_count'] += 1
            
            # Severity
            sev = vuln.get('severity', 'UNKNOWN')
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1
            
            # Priority
            if 'ml_analysis' in vuln:
                ml = vuln['ml_analysis']
                if ml.get('ml_available'):
                    priority = ml.get('priority', 4)
                    summary['by_priority'][priority] = summary['by_priority'].get(priority, 0) + 1
        
        # Top risks
        ml_vulns = [v for v in vulnerabilities if 'ml_analysis' in v and v['ml_analysis'].get('ml_available')]
        sorted_vulns = sorted(ml_vulns, key=lambda x: x['ml_analysis'].get('risk_score', 0), reverse=True)
        
        summary['top_risks'] = [
            {
                'cve_id': v.get('cve_id', 'unknown'),
                'cvss': v.get('cvss_score', 0),
                'risk_score': v['ml_analysis']['risk_score'],
                'priority': v['ml_analysis']['priority']
            }
            for v in sorted_vulns[:5]
        ]
        
        return summary


def parse_with_ml(xml_file, use_ml=True, use_risk_scorer=True, use_nvd=False):
    '''Helper function for parsing with ML'''
    parser = EnhancedVulnerabilityParser(
        use_ml=use_ml,
        use_risk_scorer=use_risk_scorer,
        use_nvd=use_nvd
    )
    return parser.parse_and_enhance(xml_file)
