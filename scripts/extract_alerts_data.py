#!/usr/bin/env python3
"""
Daily script to extract alerts data from Jira Service Management
This script should be scheduled to run daily using cron or task scheduler
"""

import requests
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import logging

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/alerts_extraction.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AlertsDataExtractor:
    def __init__(self):
        # Configuration from environment
        self.email = os.getenv('JIRA_USER_EMAIL')
        self.api_token = os.getenv('JIRA_API_TOKEN')
        self.jira_domain = os.getenv('JIRA_BASE_URL', 'https://sierrawireless.atlassian.net')
        self.alerts_endpoint = '/gateway/api/jsm/ops/web/3a7467b6-6c2f-4bfc-a2d9-21020a74bee4/v1/alerts'
        
        # Query parameters
        self.limit = 50
        self.sort = 'insertedAt'
        self.apply_visibility_filter = 'false'
        self.max_alerts = int(os.getenv('MAX_ALERTS_TO_FETCH', 1000))
        
        # Output file
        self.output_file = os.path.join('data', 'alerts.json')
        
        # Validate credentials
        if not self.email or not self.api_token:
            logger.error("JIRA credentials not found in environment variables")
            raise ValueError("Please set JIRA_USER_EMAIL and JIRA_API_TOKEN in .env file")
    
    def fetch_alerts_batch(self, offset=0, limit=50):
        """Fetch a batch of alerts from Jira Service Management"""
        url = f"{self.jira_domain}{self.alerts_endpoint}"
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        params = {
            "sort": self.sort,
            "limit": limit,
            "offset": offset,
            "applyVisibilityFilter": self.apply_visibility_filter
        }
        
        try:
            response = requests.get(
                url, 
                headers=headers, 
                params=params, 
                auth=HTTPBasicAuth(self.email, self.api_token)
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Error fetching alerts: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
    
    def fetch_all_alerts(self):
        """Fetch all alerts with pagination support"""
        all_alerts = []
        offset = 0
        
        logger.info(f"Starting to fetch alerts (maximum: {self.max_alerts})")
        
        while len(all_alerts) < self.max_alerts:
            # Adjust limit for last request if needed
            remaining = self.max_alerts - len(all_alerts)
            current_limit = min(self.limit, remaining)
            
            logger.info(f"Fetching alerts: offset={offset}, limit={current_limit} (retrieved: {len(all_alerts)}/{self.max_alerts})")
            
            data = self.fetch_alerts_batch(offset=offset, limit=current_limit)
            
            if not data:
                logger.error("Failed to fetch alerts")
                break
                
            alerts = data.get('values', [])
            
            if not alerts:
                logger.info("No more alerts available")
                break
                
            # Add alerts up to max_alerts
            alerts_to_add = alerts[:remaining]
            all_alerts.extend(alerts_to_add)
            
            logger.info(f"Added {len(alerts_to_add)} alerts. Total: {len(all_alerts)}")
            
            # Check if we've reached the maximum
            if len(all_alerts) >= self.max_alerts:
                logger.info(f"Reached maximum limit of {self.max_alerts} alerts")
                break
                
            # Check if there are more alerts to fetch
            total_count = data.get('count', 0)
            if offset + current_limit >= total_count:
                logger.info(f"Retrieved all available alerts (total in system: {total_count})")
                break
                
            offset += self.limit
        
        return all_alerts
    
    def convert_timestamp(self, timestamp_ms):
        """Convert Unix timestamp in milliseconds to readable datetime string"""
        if timestamp_ms:
            # Convert milliseconds to seconds
            timestamp_sec = timestamp_ms / 1000
            # Convert to datetime object
            dt = datetime.fromtimestamp(timestamp_sec, tz=timezone.utc)
            # Return in readable format
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        return None
    
    def process_alerts(self, alerts):
        """Process and enhance alert data"""
        processed_alerts = []
        current_time = datetime.now(timezone.utc)
        
        # Statistics
        priority_counts = {}
        status_counts = {}
        source_counts = {}
        
        for alert in alerts:
            # Convert timestamps to readable format
            if 'createdAt' in alert:
                alert['createdAt_readable'] = self.convert_timestamp(alert['createdAt'])
                
            if 'updatedAt' in alert:
                alert['updatedAt_readable'] = self.convert_timestamp(alert['updatedAt'])
                
            if 'lastOccuredAt' in alert:
                alert['lastOccuredAt_readable'] = self.convert_timestamp(alert['lastOccuredAt'])
                
            if 'snoozedUntil' in alert and alert['snoozedUntil'] > 0:
                alert['snoozedUntil_readable'] = self.convert_timestamp(alert['snoozedUntil'])
            
            # Add processing timestamp
            alert['processed_at'] = current_time.isoformat()
            
            # Calculate alert age
            if 'createdAt' in alert:
                created_time = datetime.fromtimestamp(alert['createdAt'] / 1000, tz=timezone.utc)
                age = current_time - created_time
                alert['age_hours'] = round(age.total_seconds() / 3600, 2)
                alert['age_days'] = round(age.days, 2)
            
            # Update statistics
            priority = alert.get('priority', 'Unknown')
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
            
            status = alert.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
            
            source = alert.get('source', 'Unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
            
            processed_alerts.append(alert)
        
        return processed_alerts, {
            'priority_distribution': priority_counts,
            'status_distribution': status_counts,
            'source_distribution': source_counts,
            'total_alerts': len(processed_alerts)
        }
    
    def save_alerts_to_json(self, alerts, statistics):
        """Save alerts to a JSON file with metadata"""
        try:
            output_data = {
                'alerts': alerts,
                'metadata': {
                    'total_count': len(alerts),
                    'fetched_at': datetime.now(timezone.utc).isoformat(),
                    'source': self.jira_domain + self.alerts_endpoint,
                    'statistics': statistics
                }
            }
            
            # Ensure data directory exists
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Successfully saved {len(alerts)} alerts to {self.output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving alerts to file: {e}")
            return False
    
    def extract_and_save(self):
        """Main extraction process"""
        logger.info("Starting alerts data extraction...")
        
        # Fetch all alerts
        alerts = self.fetch_all_alerts()
        
        if not alerts:
            logger.warning("No alerts were retrieved")
            return False
        
        logger.info(f"Successfully retrieved {len(alerts)} alerts")
        
        # Process alerts
        processed_alerts, statistics = self.process_alerts(alerts)
        
        # Save to JSON file
        success = self.save_alerts_to_json(processed_alerts, statistics)
        
        if success:
            logger.info("Alert extraction completed successfully")
            
            # Print summary
            print("\n" + "="*50)
            print("EXTRACTION SUMMARY")
            print("="*50)
            print(f"Total alerts extracted: {len(processed_alerts)}")
            print(f"Extraction time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("\nPriority Distribution:")
            for priority, count in statistics['priority_distribution'].items():
                print(f"  {priority}: {count}")
            print("\nStatus Distribution:")
            for status, count in statistics['status_distribution'].items():
                print(f"  {status}: {count}")
            print("\nTop 5 Sources:")
            sorted_sources = sorted(statistics['source_distribution'].items(), 
                                  key=lambda x: x[1], reverse=True)[:5]
            for source, count in sorted_sources:
                print(f"  {source}: {count}")
            print("="*50)
        else:
            logger.error("Alert extraction failed")
            
        return success

def main():
    """Main function"""
    try:
        # Create necessary directories
        os.makedirs('data', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        # Run extraction
        extractor = AlertsDataExtractor()
        success = extractor.extract_and_save()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()