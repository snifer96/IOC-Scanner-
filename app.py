import os
import requests
import hashlib
import json
import csv
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file, make_response
from flask_cors import CORS
from dotenv import load_dotenv
from pathlib import Path
import ipaddress
from io import StringIO, BytesIO
import zipfile

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
CORS(app)

# VirusTotal API Configuration
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VT_BASE_URL = 'https://www.virustotal.com/api/v3'

headers = {
    'x-apikey': VT_API_KEY,
    'Accept': 'application/json'
}

# Create directories
Path('reports').mkdir(exist_ok=True)
Path('uploads').mkdir(exist_ok=True)

class IOCScanner:
    def __init__(self):
        self.scan_history = []
        self.cache = {}
        self.cache_duration = timedelta(hours=1)
    
    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_domain(self, domain):
        """Basic domain validation"""
        if len(domain) < 3 or len(domain) > 253:
            return False
        if '.' not in domain:
            return False
        # Remove protocol if present
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        return True
    
    def calculate_file_hash(self, file_path, hash_type='sha256'):
        """Calculate hash of a file"""
        try:
            hash_func = getattr(hashlib, hash_type)()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            return None
    
    def check_cache(self, ioc_type, value):
        """Check if result is cached"""
        cache_key = f"{ioc_type}_{value}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if datetime.now() - timestamp < self.cache_duration:
                return cached_data
        return None
    
    def update_cache(self, ioc_type, value, data):
        """Update cache with new result"""
        cache_key = f"{ioc_type}_{value}"
        self.cache[cache_key] = (data, datetime.now())
    
    def scan_ip(self, ip_address):
        """Scan IP address using VirusTotal"""
        try:
            # Check cache first
            cached = self.check_cache('ip', ip_address)
            if cached:
                return cached
            
            url = f'{VT_BASE_URL}/ip_addresses/{ip_address}'
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                processed = {
                    'status': 'success',
                    'data': self.process_ip_result(result)
                }
                self.update_cache('ip', ip_address, processed)
                return processed
            elif response.status_code == 404:
                return {'status': 'error', 'message': 'IP not found in VirusTotal database'}
            else:
                return {'status': 'error', 'message': f'API error: {response.status_code}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def scan_domain(self, domain):
        """Scan domain using VirusTotal"""
        try:
            # Check cache first
            cached = self.check_cache('domain', domain)
            if cached:
                return cached
            
            url = f'{VT_BASE_URL}/domains/{domain}'
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                processed = {
                    'status': 'success',
                    'data': self.process_domain_result(result)
                }
                self.update_cache('domain', domain, processed)
                return processed
            elif response.status_code == 404:
                return {'status': 'error', 'message': 'Domain not found in VirusTotal database'}
            else:
                return {'status': 'error', 'message': f'API error: {response.status_code}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def scan_hash(self, file_hash):
        """Scan file hash using VirusTotal"""
        try:
            # Check cache first
            cached = self.check_cache('hash', file_hash)
            if cached:
                return cached
            
            url = f'{VT_BASE_URL}/files/{file_hash}'
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                processed = {
                    'status': 'success',
                    'data': self.process_hash_result(result)
                }
                self.update_cache('hash', file_hash, processed)
                return processed
            elif response.status_code == 404:
                return {'status': 'error', 'message': 'Hash not found in VirusTotal database'}
            else:
                return {'status': 'error', 'message': f'API error: {response.status_code}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def scan_url(self, url_to_scan):
        """Scan URL using VirusTotal"""
        try:
            # Check cache first
            cached = self.check_cache('url', url_to_scan)
            if cached:
                return cached
            
            url_id = hashlib.sha256(url_to_scan.encode()).hexdigest()
            analysis_url = f'{VT_BASE_URL}/urls/{url_id}'
            response = requests.get(analysis_url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                processed = {
                    'status': 'success',
                    'data': self.process_url_result(result, url_to_scan)  # Pass original URL
                }
                self.update_cache('url', url_to_scan, processed)
                return processed
            else:
                # Submit for analysis
                submit_url = f'{VT_BASE_URL}/urls'
                post_response = requests.post(
                    submit_url,
                    headers=headers,
                    data={'url': url_to_scan}
                )
                
                if post_response.status_code == 200:
                    # For pending scans, still return the original URL
                    pending_result = {
                        'type': 'URL',
                        'value': url_to_scan,  # Original URL
                        'url_id': url_id,
                        'harmless': 0,
                        'malicious': 0,
                        'suspicious': 0,
                        'undetected': 0,
                        'title': 'Pending Analysis',
                        'reputation': 0,
                        'last_analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'total_engines': 0,
                        'raw_data': {'status': 'pending'}
                    }
                    
                    return {
                        'status': 'pending',
                        'message': 'Analysis submitted. Please check back later.',
                        'data': pending_result
                    }
                else:
                    return {'status': 'error', 'message': f'Failed to submit URL: {post_response.status_code}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def process_ip_result(self, result):
        """Process and format IP scan results"""
        data = result.get('data', {})
        attributes = data.get('attributes', {})
        analysis_stats = attributes.get('last_analysis_stats', {})
        
        return {
            'type': 'IP Address',
            'value': data.get('id'),
            'harmless': analysis_stats.get('harmless', 0),
            'malicious': analysis_stats.get('malicious', 0),
            'suspicious': analysis_stats.get('suspicious', 0),
            'undetected': analysis_stats.get('undetected', 0),
            'asn': attributes.get('asn', 'N/A'),
            'country': attributes.get('country', 'N/A'),
            'network': attributes.get('network', 'N/A'),
            'reputation': attributes.get('reputation', 0),
            'last_analysis_date': self.format_timestamp(attributes.get('last_analysis_date')),
            'total_engines': sum(analysis_stats.values()),
            'tags': attributes.get('tags', []),
            'raw_data': attributes
        }
    
    def process_domain_result(self, result):
        """Process and format domain scan results"""
        data = result.get('data', {})
        attributes = data.get('attributes', {})
        analysis_stats = attributes.get('last_analysis_stats', {})
        
        return {
            'type': 'Domain',
            'value': data.get('id'),
            'harmless': analysis_stats.get('harmless', 0),
            'malicious': analysis_stats.get('malicious', 0),
            'suspicious': analysis_stats.get('suspicious', 0),
            'undetected': analysis_stats.get('undetected', 0),
            'creation_date': self.format_timestamp(attributes.get('creation_date')),
            'last_update_date': self.format_timestamp(attributes.get('last_update_date')),
            'registrar': attributes.get('registrar', 'N/A'),
            'reputation': attributes.get('reputation', 0),
            'last_analysis_date': self.format_timestamp(attributes.get('last_analysis_date')),
            'total_engines': sum(analysis_stats.values()),
            'categories': attributes.get('categories', {}),
            'raw_data': attributes
        }
    
    def process_hash_result(self, result):
        """Process and format hash scan results"""
        data = result.get('data', {})
        attributes = data.get('attributes', {})
        analysis_stats = attributes.get('last_analysis_stats', {})
        
        return {
            'type': 'File Hash',
            'value': data.get('id'),
            'hash_type': self.detect_hash_type(data.get('id')),
            'harmless': analysis_stats.get('harmless', 0),
            'malicious': analysis_stats.get('malicious', 0),
            'suspicious': analysis_stats.get('suspicious', 0),
            'undetected': analysis_stats.get('undetected', 0),
            'size': attributes.get('size', 'N/A'),
            'type_tag': attributes.get('type_tag', 'N/A'),
            'names': attributes.get('names', []),
            'reputation': attributes.get('reputation', 0),
            'last_analysis_date': self.format_timestamp(attributes.get('last_analysis_date')),
            'total_engines': sum(analysis_stats.values()),
            'magic': attributes.get('magic', 'N/A'),
            'raw_data': attributes
        }
    
    def process_url_result(self, result, original_url=None):
        """Process and format URL scan results"""
        data = result.get('data', {})
        attributes = data.get('attributes', {})
        analysis_stats = attributes.get('last_analysis_stats', {})
        
        # Use the original URL passed in or get from result
        url_value = original_url or attributes.get('url') or data.get('id')
        
        return {
            'type': 'URL',
            'value': url_value,  # Use the original URL here
            'url_id': data.get('id'),  # Store the hash ID separately
            'harmless': analysis_stats.get('harmless', 0),
            'malicious': analysis_stats.get('malicious', 0),
            'suspicious': analysis_stats.get('suspicious', 0),
            'undetected': analysis_stats.get('undetected', 0),
            'title': attributes.get('title', 'N/A'),
            'reputation': attributes.get('reputation', 0),
            'last_analysis_date': self.format_timestamp(attributes.get('last_analysis_date')),
            'total_engines': sum(analysis_stats.values()),
            'categories': attributes.get('categories', {}),
            'raw_data': attributes
        }
    
    def detect_hash_type(self, hash_value):
        """Detect the type of hash based on length"""
        if len(hash_value) == 32:
            return 'MD5'
        elif len(hash_value) == 40:
            return 'SHA-1'
        elif len(hash_value) == 64:
            return 'SHA-256'
        else:
            return 'Unknown'
    
    def format_timestamp(self, timestamp):
        """Format timestamp to readable date"""
        if timestamp:
            try:
                return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            except:
                return str(timestamp)
        return 'N/A'
    
    def get_threat_level(self, result):
        """Determine threat level based on scan results"""
        if result.get('malicious', 0) > 0:
            return 'High'
        elif result.get('suspicious', 0) > 0:
            return 'Medium'
        elif result.get('harmless', 0) > 0:
            return 'Low'
        else:
            return 'Unknown'
    
    def export_to_csv(self, results, filename=None):
        """Export results to CSV format"""
        if not filename:
            filename = f"ioc_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = f"reports/{filename}"
        
        # Prepare data for CSV
        fieldnames = [
            'Type', 'Value', 'Threat Level', 'Malicious', 'Suspicious', 
            'Harmless', 'Undetected', 'Total Engines', 'Reputation', 
            'Last Analysis', 'Scan Date'
        ]
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                if result.get('status') == 'success':
                    data = result.get('data', {})
                    writer.writerow({
                        'Type': data.get('type', ''),
                        'Value': data.get('value', ''),
                        'Threat Level': self.get_threat_level(data),
                        'Malicious': data.get('malicious', 0),
                        'Suspicious': data.get('suspicious', 0),
                        'Harmless': data.get('harmless', 0),
                        'Undetected': data.get('undetected', 0),
                        'Total Engines': data.get('total_engines', 0),
                        'Reputation': data.get('reputation', 0),
                        'Last Analysis': data.get('last_analysis_date', ''),
                        'Scan Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
        
        return filepath if os.path.exists(filepath) else None
    
    def export_to_json(self, results, filename=None):
        """Export results to JSON format"""
        if not filename:
            filename = f"ioc_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = f"reports/{filename}"
        
        export_data = {
            'scan_date': datetime.now().isoformat(),
            'total_scanned': len(results),
            'threat_summary': {
                'high': sum(1 for r in results if r.get('status') == 'success' and r.get('data', {}).get('malicious', 0) > 0),
                'medium': sum(1 for r in results if r.get('status') == 'success' and r.get('data', {}).get('suspicious', 0) > 0),
                'low': sum(1 for r in results if r.get('status') == 'success' and r.get('data', {}).get('harmless', 0) > 0),
                'unknown': sum(1 for r in results if r.get('status') == 'success' and r.get('data', {}).get('undetected', 0) > 0)
            },
            'results': results
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return filepath
    
    def export_to_html(self, results, filename=None):
        """Export results to HTML format"""
        if not filename:
            filename = f"ioc_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        filepath = f"reports/{filename}"
        
        # Count threats
        threat_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
        for result in results:
            if result.get('status') == 'success':
                threat_level = self.get_threat_level(result.get('data', {}))
                threat_counts[threat_level] += 1
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>IOC Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .result {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .threat-high {{ border-left: 5px solid #e74c3c; }}
        .threat-medium {{ border-left: 5px solid #f39c12; }}
        .threat-low {{ border-left: 5px solid #27ae60; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }}
        .stat-box {{ background: white; padding: 10px; border-radius: 5px; text-align: center; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f2f2f2; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>IOC Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Scanned: {len(results)}</p>
    </div>
    
    <div class="summary">
        <h2>Threat Summary</h2>
        <div class="stats">
            <div class="stat-box" style="background: #e74c3c; color: white;">
                <h3>{threat_counts['High']}</h3>
                <p>High Threat</p>
            </div>
            <div class="stat-box" style="background: #f39c12; color: white;">
                <h3>{threat_counts['Medium']}</h3>
                <p>Medium Threat</p>
            </div>
            <div class="stat-box" style="background: #27ae60; color: white;">
                <h3>{threat_counts['Low']}</h3>
                <p>Low Threat</p>
            </div>
            <div class="stat-box" style="background: #95a5a6; color: white;">
                <h3>{threat_counts['Unknown']}</h3>
                <p>Unknown</p>
            </div>
        </div>
    </div>
    
    <h2>Detailed Results</h2>
"""
        
        for i, result in enumerate(results, 1):
            if result.get('status') == 'success':
                data = result.get('data', {})
                threat_level = self.get_threat_level(data)
                threat_class = f'threat-{threat_level.lower()}'
                
                html += f"""
    <div class="result {threat_class}">
        <h3>Result #{i}: {data.get('type')}</h3>
        <p><strong>Value:</strong> <code>{data.get('value')}</code></p>
        <p><strong>Threat Level:</strong> <span style="color: {'#e74c3c' if threat_level == 'High' else '#f39c12' if threat_level == 'Medium' else '#27ae60'}">{threat_level}</span></p>
        
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Malicious Detections</td>
                <td>{data.get('malicious', 0)}</td>
            </tr>
            <tr>
                <td>Suspicious Detections</td>
                <td>{data.get('suspicious', 0)}</td>
            </tr>
            <tr>
                <td>Harmless Detections</td>
                <td>{data.get('harmless', 0)}</td>
            </tr>
            <tr>
                <td>Undetected</td>
                <td>{data.get('undetected', 0)}</td>
            </tr>
            <tr>
                <td>Total Engines</td>
                <td>{data.get('total_engines', 0)}</td>
            </tr>
            <tr>
                <td>Reputation</td>
                <td>{data.get('reputation', 0)}</td>
            </tr>
            <tr>
                <td>Last Analysis</td>
                <td>{data.get('last_analysis_date', 'N/A')}</td>
            </tr>
        </table>
    </div>
"""
            else:
                html += f"""
    <div class="result">
        <h3>Result #{i}: Error</h3>
        <p><strong>Error:</strong> {result.get('message', 'Unknown error')}</p>
    </div>
"""
        
        html += """
    <div class="footer">
        <p>Report generated by IOC Scanner v2.0</p>
        <p>Disclaimer: This report is for informational purposes only.</p>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filepath
    
    def export_all_formats(self, results):
        """Export results in all formats and create zip"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Export to all formats
        csv_file = self.export_to_csv(results, f"ioc_scan_{timestamp}.csv")
        json_file = self.export_to_json(results, f"ioc_scan_{timestamp}.json")
        html_file = self.export_to_html(results, f"ioc_scan_{timestamp}.html")
        
        # Create zip file
        zip_filename = f"reports/ioc_scan_full_report_{timestamp}.zip"
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            for file in [csv_file, json_file, html_file]:
                if file and os.path.exists(file):
                    zipf.write(file, os.path.basename(file))
        
        return zip_filename

# Initialize scanner
scanner = IOCScanner()

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle scan requests"""
    try:
        data = request.get_json()
        scan_type = data.get('type')
        value = data.get('value', '').strip()
        
        if not value:
            return jsonify({'status': 'error', 'message': 'No value provided'})
        
        # Validate based on type
        if scan_type == 'ip':
            if not scanner.validate_ip(value):
                return jsonify({'status': 'error', 'message': 'Invalid IP address format'})
            result = scanner.scan_ip(value)
            
        elif scan_type == 'domain':
            if not scanner.validate_domain(value):
                return jsonify({'status': 'warning', 'message': 'Domain format may be invalid'})
            result = scanner.scan_domain(value)
            
        elif scan_type == 'hash':
            result = scanner.scan_hash(value)
            
        elif scan_type == 'url':
            result = scanner.scan_url(value)
            
        else:
            return jsonify({'status': 'error', 'message': 'Invalid scan type'})
        
        # Add to history
        if result.get('status') == 'success':
            scanner.scan_history.append({
                'timestamp': datetime.now().isoformat(),
                'type': scan_type,
                'value': value,
                'result': result
            })
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/batch_scan', methods=['POST'])
def batch_scan():
    """Handle batch scanning of multiple IOCs"""
    try:
        data = request.get_json()
        iocs = data.get('iocs', [])
        
        if not iocs:
            return jsonify({'status': 'error', 'message': 'No IOCs provided'})
        
        results = []
        for ioc in iocs:
            ioc_type = ioc.get('type')
            ioc_value = ioc.get('value', '').strip()
            
            if ioc_type == 'ip':
                results.append(scanner.scan_ip(ioc_value))
            elif ioc_type == 'domain':
                results.append(scanner.scan_domain(ioc_value))
            elif ioc_type == 'hash':
                results.append(scanner.scan_hash(ioc_value))
            elif ioc_type == 'url':
                results.append(scanner.scan_url(ioc_value))
        
        return jsonify({
            'status': 'success',
            'total': len(results),
            'results': results
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/calculate_hash', methods=['POST'])
def calculate_hash_route():
    """Calculate hash of uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'})
        
        # Save file temporarily
        temp_path = f'uploads/temp_{int(time.time())}_{file.filename}'
        file.save(temp_path)
        
        # Calculate hashes
        hashes = {
            'md5': scanner.calculate_file_hash(temp_path, 'md5'),
            'sha1': scanner.calculate_file_hash(temp_path, 'sha1'),
            'sha256': scanner.calculate_file_hash(temp_path, 'sha256')
        }
        
        # Clean up
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return jsonify({
            'status': 'success',
            'filename': file.filename,
            'size': request.content_length,
            'hashes': hashes
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/export', methods=['POST'])
def export_results():
    """Export scan results in specified format"""
    try:
        data = request.get_json()
        results = data.get('results', [])
        export_format = data.get('format', 'all')
        
        if not results:
            return jsonify({'status': 'error', 'message': 'No results to export'})
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if export_format == 'csv':
            filename = scanner.export_to_csv(results, f"ioc_scan_{timestamp}.csv")
            if filename:
                return send_file(filename, as_attachment=True)
            
        elif export_format == 'json':
            filename = scanner.export_to_json(results, f"ioc_scan_{timestamp}.json")
            if filename:
                return send_file(filename, as_attachment=True)
            
        elif export_format == 'html':
            filename = scanner.export_to_html(results, f"ioc_scan_{timestamp}.html")
            if filename:
                return send_file(filename, as_attachment=True)
            
        elif export_format == 'all':
            zip_filename = scanner.export_all_formats(results)
            if zip_filename:
                return send_file(zip_filename, as_attachment=True)
        
        return jsonify({'status': 'error', 'message': 'Export failed'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/export_csv_direct', methods=['GET'])
def export_csv_direct():
    """Export current results to CSV directly"""
    try:
        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Type', 'Value', 'Threat Level', 'Malicious', 'Suspicious', 
            'Harmless', 'Undetected', 'Total Engines', 'Reputation', 
            'Last Analysis', 'Scan Date'
        ])
        
        # Write data from scanner history
        for item in scanner.scan_history:
            if item['result'].get('status') == 'success':
                data = item['result'].get('data', {})
                writer.writerow([
                    data.get('type', ''),
                    data.get('value', ''),
                    scanner.get_threat_level(data),
                    data.get('malicious', 0),
                    data.get('suspicious', 0),
                    data.get('harmless', 0),
                    data.get('undetected', 0),
                    data.get('total_engines', 0),
                    data.get('reputation', 0),
                    data.get('last_analysis_date', ''),
                    item['timestamp']
                ])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = f'attachment; filename=ioc_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        response.headers['Content-type'] = 'text/csv'
        
        return response
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/history', methods=['GET'])
def get_history():
    """Get scan history"""
    return jsonify({
        'status': 'success',
        'history': scanner.scan_history[-50:]  # Last 50 scans
    })

@app.route('/clear_cache', methods=['POST'])
def clear_cache():
    """Clear scanner cache"""
    scanner.cache.clear()
    return jsonify({'status': 'success', 'message': 'Cache cleared'})

@app.route('/report')
def report_page():
    """Render report page"""
    return render_template('report.html')

@app.route('/api_status', methods=['GET'])
def api_status():
    """Check API status"""
    try:
        # Make a simple request to VirusTotal
        response = requests.get(f'{VT_BASE_URL}/ip_addresses/8.8.8.8', headers=headers)
        
        if response.status_code == 200:
            return jsonify({
                'status': 'success',
                'api_connected': True,
                'message': 'VirusTotal API is working'
            })
        else:
            return jsonify({
                'status': 'success',
                'api_connected': False,
                'message': f'VirusTotal API returned status: {response.status_code}'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'api_connected': False,
            'message': str(e)
        })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=9648, debug=True)