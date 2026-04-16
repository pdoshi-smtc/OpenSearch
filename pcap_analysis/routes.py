"""
PCAP Analysis Routes Module
Handles all Flask routes and logic for PCAP file analysis and visualization
"""

from flask import Blueprint, render_template, jsonify, request
import os
import json
from datetime import datetime
from .analyzer import (
    extract_pcap_data,
    detect_lost_service_with_tshark,
    get_sop
)
from .call_flow_diagram_html_generation import process_pcap

# Create blueprint
pcap_analysis_bp = Blueprint(
    'pcap_analysis', 
    __name__, 
    template_folder='templates',
    static_folder='static'
)

# Configuration
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@pcap_analysis_bp.route('/')
def pcap_home():
    """Main page for PCAP analysis interface"""
    return render_template('pcap_analyzer.html')

@pcap_analysis_bp.route('/upload', methods=['POST'])
def upload_pcap():
    """Handle PCAP file upload and analysis"""
    try:
        # Validate file upload
        if 'pcap_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['pcap_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        # Save the uploaded file
        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        print(f"{filename} saved successfully at {filepath}")
        
        # Process PCAP file
        try:
            # Generate mermaid diagram for call trace
            mermaid_div = process_pcap(filepath)
            
            # Extract packet data and analysis
            pcap_data = extract_pcap_data(filepath, mermaid_div)
            
            # Clean up the uploaded file
            os.remove(filepath)
            
            return jsonify({
                'success': True,
                'data': pcap_data
            })
            
        except Exception as e:
            print(f"Analysis exception: {e}")
            # Clean up file on error
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({
                'error': f'Error analyzing PCAP file: {str(e)}'
            }), 500
            
    except Exception as e:
        print(f"Upload exception: {e}")
        return jsonify({'error': str(e)}), 500

@pcap_analysis_bp.route('/api/sop/<rp_name>')
def get_sop_by_rp(rp_name):
    """API endpoint to get SOP (Standard Operating Procedure) by RP name"""
    try:
        sop_content = get_sop(rp_name)
        return jsonify({
            'success': True,
            'rp': rp_name,
            'sop': sop_content
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@pcap_analysis_bp.route('/api/analyze', methods=['POST'])
def analyze_pcap_data():
    """API endpoint for PCAP analysis without file upload (for already uploaded files)"""
    try:
        data = request.get_json()
        filepath = data.get('filepath')
        
        if not filepath or not os.path.exists(filepath):
            return jsonify({'error': 'Invalid file path'}), 400
        
        # Generate analysis
        mermaid_div = process_pcap(filepath)
        pcap_data = extract_pcap_data(filepath, mermaid_div)
        
        return jsonify({
            'success': True,
            'data': pcap_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@pcap_analysis_bp.route('/api/lost-service', methods=['POST'])
def check_lost_service():
    """API endpoint to check for lost service in PCAP file"""
    try:
        data = request.get_json()
        filepath = data.get('filepath')
        max_delta = data.get('max_delta', 1.0)
        
        if not filepath or not os.path.exists(filepath):
            return jsonify({'error': 'Invalid file path'}), 400
        
        # Detect lost service
        lost_service_data = detect_lost_service_with_tshark(filepath, max_delta)
        
        return jsonify({
            'success': True,
            'lost_service': lost_service_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500