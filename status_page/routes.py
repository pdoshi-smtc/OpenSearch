"""
Status Page Routes Module
Handles all Flask routes and display logic for the status page
"""

from flask import Blueprint, render_template, jsonify
from datetime import datetime
from .scraper import get_status_data, scrape_sierra_status

# Create blueprint
status_bp = Blueprint('status', __name__, template_folder='templates')

@status_bp.route('/')
def status_home():
    """Main page showing status information"""
    status_data = get_status_data()
    
    # Format last updated time
    if status_data['last_updated']:
        last_updated = datetime.fromisoformat(status_data['last_updated']).strftime('%Y-%m-%d %H:%M:%S')
    else:
        last_updated = 'Never'
    
    return render_template('status_page.html', 
                         last_updated=last_updated,
                         overall_status=status_data.get('overall_status', 'Unknown'),
                         scheduled_maintenance=status_data['scheduled_maintenance'],
                         past_incidents=status_data['past_incidents'],
                         non_operational_devices=status_data['non_operational_devices'],
                         service_groups=status_data.get('service_groups', []),
                         services=status_data.get('services', []))

@status_bp.route('/api/status')
def api_status():
    """API endpoint to get status data as JSON"""
    return jsonify(get_status_data())

@status_bp.route('/api/refresh')
def api_refresh():
    """API endpoint to trigger a refresh of the data"""
    scrape_sierra_status()
    return jsonify({"status": "success", "message": "Data refreshed"})