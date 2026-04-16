from flask import Blueprint, render_template, jsonify, request
from datetime import datetime, timezone
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create blueprint
alerts_bp = Blueprint('alerts', __name__, 
                     template_folder='templates',
                     static_folder='static')

class AlertsManager:
    def __init__(self, alerts_file='data/alerts.json'):
        self.alerts_file = alerts_file
        self.alerts_data = self.load_alerts()
    
    def load_alerts(self):
        """Load alerts from JSON file"""
        try:
            if os.path.exists(self.alerts_file):
                with open(self.alerts_file, 'r') as f:
                    return json.load(f)
            else:
                print(f"Warning: {self.alerts_file} not found")
                return {'alerts': [], 'metadata': {}}
        except Exception as e:
            print(f"Error loading alerts: {e}")
            return {'alerts': [], 'metadata': {}}
    
    def reload_alerts(self):
        """Reload alerts from file"""
        self.alerts_data = self.load_alerts()
    
    def get_filtered_alerts(self, start_date, end_date):
        """Get alerts filtered by date range"""
        try:
            # Parse dates as UTC
            start_dt = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
            end_dt = datetime.fromisoformat(end_date).replace(tzinfo=timezone.utc)
            
            # Convert to milliseconds
            start_timestamp = int(start_dt.timestamp() * 1000)
            end_timestamp = int(end_dt.timestamp() * 1000)
            
            # Filter alerts
            filtered_alerts = []
            current_time = datetime.now(timezone.utc)
            
            for alert in self.alerts_data.get('alerts', []):
                created_at = alert.get('createdAt', 0)
                if start_timestamp <= created_at <= end_timestamp:
                    # Calculate duration since creation
                    created_dt = datetime.fromtimestamp(created_at / 1000, tz=timezone.utc)
                    duration = current_time - created_dt
                    
                    # Format duration
                    total_seconds = int(duration.total_seconds())
                    days = total_seconds // 86400
                    hours = (total_seconds % 86400) // 3600
                    minutes = (total_seconds % 3600) // 60
                    
                    if days > 0:
                        alert['duration_formatted'] = f"{days}d {hours}h {minutes}m"
                    else:
                        alert['duration_formatted'] = f"{hours}h {minutes}m"
                    
                    # Format acknowledged by
                    owner = alert.get('owner', '')
                    if owner:
                        alert['acknowledged_by'] = owner
                    else:
                        alert['acknowledged_by'] = "Not acknowledged"
                    
                    # Add formatted dates
                    alert['created_date_formatted'] = created_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                    
                    # Calculate age in days
                    alert['age_days'] = (current_time - created_dt).days
                    
                    filtered_alerts.append(alert)
            
            # Sort by createdAt descending
            filtered_alerts.sort(key=lambda x: x.get('createdAt', 0), reverse=True)
            
            # Calculate statistics
            return self.calculate_statistics(filtered_alerts, start_dt, end_dt)
            
        except Exception as e:
            raise ValueError(f"Error filtering alerts: {str(e)}")
    
    def calculate_statistics(self, alerts, start_dt, end_dt):
        """Calculate statistics for filtered alerts"""
        priority_stats = {'P1': 0, 'P2': 0, 'P3': 0, 'P4': 0, 'P5': 0}
        status_stats = {'open': 0, 'closed': 0}
        source_stats = {}
        acknowledged_stats = {'acknowledged': 0, 'not_acknowledged': 0}
        
        for alert in alerts:
            # Priority stats
            priority = alert.get('priority', 'Unknown')
            if priority in priority_stats:
                priority_stats[priority] += 1
            
            # Status stats
            status = alert.get('status', 'unknown').lower()
            if status in status_stats:
                status_stats[status] += 1
            
            # Source stats
            source = alert.get('source', 'Unknown')
            source_stats[source] = source_stats.get(source, 0) + 1
            
            # Acknowledged stats
            if alert.get('acknowledged', False):
                acknowledged_stats['acknowledged'] += 1
            else:
                acknowledged_stats['not_acknowledged'] += 1
        
        # Sort source stats by count
        top_sources = sorted(source_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'alerts': alerts,
            'stats': {
                'total': len(alerts),
                'totalInFile': len(self.alerts_data.get('alerts', [])),
                'priorities': priority_stats,
                'statuses': status_stats,
                'sources': dict(top_sources),
                'acknowledged': acknowledged_stats
            },
            'dateRange': {
                'start': start_dt.strftime('%Y-%m-%d %H:%M UTC'),
                'end': end_dt.strftime('%Y-%m-%d %H:%M UTC')
            }
        }
    
    def get_alert_trends(self, days=7):
        """Get alert trends for the last N days"""
        current_time = datetime.now(timezone.utc)
        trends = []
        
        for i in range(days):
            date = current_time - timedelta(days=i)
            date_start = date.replace(hour=0, minute=0, second=0, microsecond=0)
            date_end = date.replace(hour=23, minute=59, second=59, microsecond=999999)
            
            # Count alerts for this day
            count = 0
            for alert in self.alerts_data.get('alerts', []):
                created_at = alert.get('createdAt', 0)
                if date_start.timestamp() * 1000 <= created_at <= date_end.timestamp() * 1000:
                    count += 1
            
            trends.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        trends.reverse()  # Show oldest to newest
        return trends

# Initialize alerts manager
alerts_manager = None

def initialize_alerts_manager():
    """Initialize the alerts manager on startup"""
    global alerts_manager
    try:
        print("Initializing Alerts Manager...")
        alerts_file = os.path.join('data', 'alerts.json')
        alerts_manager = AlertsManager(alerts_file)
        print("✅ Alerts Manager initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing Alerts Manager: {e}")
        raise

# Initialize when blueprint is registered
initialize_alerts_manager()

@alerts_bp.route('/')
def alerts_home():
    """Main alerts page"""
    return render_template('alerts.html')

@alerts_bp.route('/api/alerts')
def get_alerts():
    """API endpoint to get filtered alerts"""
    try:
        # Get query parameters
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        
        if not start_date or not end_date:
            return jsonify({'error': 'Start and end dates are required'}), 400
        
        # Reload alerts data (in case it was updated)
        alerts_manager.reload_alerts()
        
        # Get filtered alerts
        result = alerts_manager.get_filtered_alerts(start_date, end_date)
        
        return jsonify(result)
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@alerts_bp.route('/api/alerts/stats')
def get_alert_stats():
    """Get overall alert statistics"""
    try:
        alerts_manager.reload_alerts()
        
        all_alerts = alerts_manager.alerts_data.get('alerts', [])
        
        # Basic stats
        total_alerts = len(all_alerts)
        
        # Priority distribution
        priority_counts = {}
        status_counts = {}
        
        for alert in all_alerts:
            priority = alert.get('priority', 'Unknown')
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
            
            status = alert.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return jsonify({
            'total_alerts': total_alerts,
            'priority_distribution': priority_counts,
            'status_distribution': status_counts,
            'last_updated': alerts_manager.alerts_data.get('metadata', {}).get('fetched_at', 'Unknown')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/api/alerts/trends')
def get_alert_trends():
    """Get alert trends for the last 7 days"""
    try:
        days = int(request.args.get('days', 7))
        trends = alerts_manager.get_alert_trends(days)
        return jsonify({'trends': trends})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/api/alerts/refresh')
def refresh_alerts():
    """Refresh alerts data from file"""
    try:
        alerts_manager.reload_alerts()
        return jsonify({
            'success': True,
            'message': 'Alerts data refreshed successfully',
            'total_alerts': len(alerts_manager.alerts_data.get('alerts', []))
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500