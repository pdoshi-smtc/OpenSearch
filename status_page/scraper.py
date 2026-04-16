"""
Status Page Scraper Module
Handles all data extraction logic for the Sierra Wireless status page
"""

import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
import os
from threading import Thread, Lock
import time

# Thread-safe data storage
_data_lock = Lock()
_status_data = {
    "last_updated": None,
    "overall_status": "Unknown",
    "scheduled_maintenance": [],
    "past_incidents": [],
    "services": [],
    "service_groups": [],
    "non_operational_devices": []
}

def get_status_data():
    """Get the current status data in a thread-safe manner"""
    with _data_lock:
        return _status_data.copy()

def scrape_sierra_status():
    """Scrape the Semtech status page"""
    global _status_data
    
    try:
        # Fetch the main page
        response = requests.get('https://status.sierrawireless.com/', timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Initialize data structure
        data = {
            "last_updated": datetime.now().isoformat(),
            "overall_status": "Unknown",
            "scheduled_maintenance": [],
            "past_incidents": [],
            "services": [],
            "service_groups": [],
            "non_operational_devices": []
        }
        
        # Extract overall status
        status_container = soup.find('div', class_='page-status')
        if status_container:
            status_text = status_container.find('h2', class_='status')
            if status_text:
                data["overall_status"] = status_text.text.strip()
        
        # Extract all component groups and their services
        component_groups = soup.find_all('div', class_='component-container is-group')
        
        for group in component_groups:
            group_header = group.find('div', class_='component-inner-container')
            if group_header:
                group_name_elem = group_header.find('span', text=True, recursive=False)
                if group_name_elem:
                    group_name = group_name_elem.text.strip()
                    
                    # Get group status
                    group_status_elem = group_header.find('span', class_='component-status')
                    group_status = group_status_elem.text.strip() if group_status_elem else "Unknown"
                    
                    # Get description if available
                    tooltip_elem = group_header.find('span', class_='tooltip-base')
                    group_description = tooltip_elem.get('data-original-title', '') if tooltip_elem else ''
                    
                    group_info = {
                        "name": group_name,
                        "status": group_status,
                        "description": group_description,
                        "operational": group_status.lower() == "operational",
                        "services": []
                    }
                    
                    # Extract child components
                    child_container = group.find('div', class_='child-components-container')
                    if child_container:
                        child_components = child_container.find_all('div', class_='component-inner-container')
                        
                        for child in child_components:
                            service_name_elem = child.find('span', class_='name')
                            if service_name_elem:
                                service_name = service_name_elem.text.strip()
                                
                                # Get service status
                                service_status_elem = child.find_all('span', class_='component-status')
                                service_status = service_status_elem[-1].text.strip() if service_status_elem else "Unknown"
                                
                                # Get description
                                service_tooltip = child.find('span', class_='tooltip-base')
                                service_description = service_tooltip.get('data-original-title', '') if service_tooltip else ''
                                
                                service_info = {
                                    "name": service_name,
                                    "status": service_status,
                                    "description": service_description,
                                    "operational": service_status.lower() == "operational",
                                    "group": group_name
                                }
                                
                                group_info["services"].append(service_info)
                                data["services"].append(service_info)
                                
                                # Add to non-operational list if not operational
                                if not service_info["operational"]:
                                    data["non_operational_devices"].append(service_info)
                    
                    data["service_groups"].append(group_info)
        
        # Extract scheduled maintenance
        maintenance_container = soup.find('div', class_='scheduled-maintenances-container')
        if maintenance_container:
            maintenance_items = maintenance_container.find_all('div', class_='scheduled-maintenance')
            
            for item in maintenance_items:
                title_elem = item.find('h3', class_='incident-title')
                if title_elem:
                    title_link = title_elem.find('a')
                    if title_link:
                        title_text = title_link.find('span', class_='whitespace-pre-wrap')
                        title = title_text.text.strip() if title_text else title_link.text.strip()
                        url = title_link.get('href', '')
                        
                        # Extract time
                        time_elem = title_elem.find('small', class_='pull-right')
                        time_text = time_elem.text.strip() if time_elem else "N/A"
                        
                        # Extract description
                        update_container = item.find('div', class_='updates-container')
                        description = ""
                        if update_container:
                            update_elem = update_container.find('span', class_='whitespace-pre-wrap')
                            if update_elem:
                                description = update_elem.text.strip()
                        
                        maintenance_info = {
                            "title": title,
                            "url": f"https://status.sierrawireless.com{url}" if url.startswith('/') else url,
                            "time": time_text,
                            "description": description
                        }
                        data["scheduled_maintenance"].append(maintenance_info)
        
        # Extract past incidents
        incidents_list = soup.find('div', class_='incidents-list')
        if incidents_list:
            status_days = incidents_list.find_all('div', class_='status-day')
            
            for day in status_days[:7]:  # Get last 7 days
                date_elem = day.find('div', class_='date')
                if date_elem:
                    incident_date = date_elem.text.strip()
                    
                    incident_containers = day.find_all('div', class_='incident-container')
                    for container in incident_containers:
                        title_elem = container.find('div', class_='incident-title')
                        if title_elem:
                            title_link = title_elem.find('a')
                            if title_link:
                                incident_title = title_link.text.strip()
                                incident_url = title_link.get('href', '')
                                
                                # Get impact level
                                impact_classes = title_elem.get('class', [])
                                impact = "none"
                                for cls in impact_classes:
                                    if cls.startswith('impact-'):
                                        impact = cls.replace('impact-', '')
                                        break
                                
                                # Get latest update
                                updates_container = container.find('div', class_='updates-container')
                                latest_update = ""
                                if updates_container:
                                    update_divs = updates_container.find_all('div', class_='update')
                                    if update_divs:
                                        latest_update_elem = update_divs[0].find('span', class_='whitespace-pre-wrap')
                                        if latest_update_elem:
                                            latest_update = latest_update_elem.text.strip()
                                
                                incident_info = {
                                    "date": incident_date,
                                    "title": incident_title,
                                    "url": f"https://status.sierrawireless.com{incident_url}" if incident_url.startswith('/') else incident_url,
                                    "impact": impact,
                                    "latest_update": latest_update
                                }
                                data["past_incidents"].append(incident_info)
        
        # Update global status data thread-safely
        with _data_lock:
            _status_data = data
        
        # Save to JSON file
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
            
        json_path = os.path.join(data_dir, 'sierra_status.json')
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
            
        return data
        
    except Exception as e:
        print(f"Error scraping Sierra Wireless status: {e}")
        return get_status_data()

def periodic_scraper():
    """Background thread to periodically scrape the status page"""
    while True:
        scrape_sierra_status()
        time.sleep(300)  # Refresh every 5 minutes

def start_background_scraper():
    """Start the background scraper thread"""
    # Initial scrape
    print("Performing initial status page scrape...")
    scrape_sierra_status()
    
    # Start background scraper thread
    scraper_thread = Thread(target=periodic_scraper, daemon=True)
    scraper_thread.start()
    print("Status page background scraper started")