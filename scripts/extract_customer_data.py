#!/usr/bin/env python3
"""
Daily script to extract customer data from Confluence
This script should be scheduled to run daily using cron or task scheduler
"""

import requests
import os
import sys
import json
from bs4 import BeautifulSoup
from datetime import datetime
import logging
from dotenv import load_dotenv
import urllib3

# Disable SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/customer_extraction.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CustomerDataExtractor:
    def __init__(self):
        # Configuration from environment
        self.pat = os.getenv('CONFLUENCE_PASSWORD')
        self.base_url = os.getenv('CONFLUENCE_BASE_URL', 'https://confluence.sierrawireless.com')
        self.page_id = os.getenv('CONFLUENCE_PAGE_ID', '466383617')
        
        # Output file
        self.output_file = os.path.join('data', 'customer_data.json')
        
        # Headers for authentication
        self.headers = {
            "Authorization": f"Bearer {self.pat}",
            "Content-Type": "application/json"
        }
        
        # Validate credentials
        if not self.pat:
            logger.error("Confluence PAT/Password not found in environment variables")
            raise ValueError("Please set CONFLUENCE_PAT or CONFLUENCE_PASSWORD in .env file")
    
    def fetch_confluence_page(self):
        """Fetch the Confluence page content"""
        url = f"{self.base_url}/rest/api/content/{self.page_id}?expand=body.storage"
        
        try:
            logger.info(f"Fetching Confluence page: {self.page_id}")
            
            response = requests.get(
                url, 
                headers=self.headers, 
                verify=False  # Set to True in production with proper SSL certificates
            )
            
            if response.status_code == 200:
                logger.info("Successfully fetched Confluence page")
                return response.json()
            else:
                logger.error(f"Failed to retrieve page. Status: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
    
    def extract_tables_from_html(self, html_content):
        """Extract tables from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        tables = []
        
        # Find all tables in the content
        html_tables = soup.find_all('table')
        logger.info(f"Found {len(html_tables)} tables in the page")
        
        for table_idx, table in enumerate(html_tables):
            # Extract headers
            headers = []
            header_rows = table.find_all('th')
            
            if header_rows:
                headers = [th.get_text(strip=True) for th in header_rows]
            else:
                # Sometimes headers are in the first row with td tags
                first_row = table.find('tr')
                if first_row:
                    headers = [td.get_text(strip=True) for td in first_row.find_all('td')]
            
            logger.info(f"Table {table_idx + 1} headers: {headers}")
            
            # Extract rows
            rows = []
            all_rows = table.find_all('tr')
            
            # Skip header row if headers were found
            start_idx = 1 if headers else 0
            
            for tr in all_rows[start_idx:]:
                cells = tr.find_all(['td', 'th'])
                
                if cells:
                    row_data = {}
                    for i, cell in enumerate(cells):
                        # Clean cell text
                        cell_text = cell.get_text(strip=True)
                        cell_text = ' '.join(cell_text.split())  # Normalize whitespace
                        
                        # Use header as key if available
                        if i < len(headers):
                            row_data[headers[i]] = cell_text
                        else:
                            row_data[f"Column_{i+1}"] = cell_text
                    
                    # Only add non-empty rows
                    if any(row_data.values()):
                        rows.append(row_data)
            
            if rows:
                tables.append(rows)
                logger.info(f"Extracted {len(rows)} rows from table {table_idx + 1}")
        
        return tables
    
    def process_customer_data(self, tables):
        """Process and clean customer data"""
        processed_data = []
        all_customers = set()
        
        for table_idx, table in enumerate(tables):
            logger.info(f"Processing table {table_idx + 1} with {len(table)} rows")
            
            for row in table:
                # Clean and standardize the data
                cleaned_row = {}
                
                for key, value in row.items():
                    # Clean key
                    clean_key = key.strip()
                    
                    # Clean value
                    clean_value = str(value).strip() if value else ""
                    
                    # Skip empty values
                    if clean_value and clean_value.lower() not in ['none', 'null', 'n/a', '-']:
                        cleaned_row[clean_key] = clean_value
                
                # Check if this row has customer information
                customer_name = cleaned_row.get("Customer Name", "")
                
                if customer_name:
                    all_customers.add(customer_name)
                    processed_data.append(cleaned_row)
        
        logger.info(f"Processed {len(processed_data)} customer records")
        logger.info(f"Found {len(all_customers)} unique customers")
        
        return processed_data
    
    def save_customer_data(self, tables, processed_data):
        """Save customer data to JSON file"""
        try:
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            
            # Prepare metadata
            metadata = {
                'extraction_date': datetime.now().isoformat(),
                'source_page_id': self.page_id,
                'source_url': f"{self.base_url}/pages/viewpage.action?pageId={self.page_id}",
                'total_tables': len(tables),
                'total_records': sum(len(table) for table in tables),
                'unique_customers': len(set(row.get("Customer Name", "") for table in tables for row in table if row.get("Customer Name")))
            }
            
            # Save the original table structure
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(tables, f, indent=4, ensure_ascii=False)
            
            # Save metadata separately
            metadata_file = os.path.join('data', 'customer_metadata.json')
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=4)
            
            logger.info(f"Successfully saved customer data to {self.output_file}")
            logger.info(f"Metadata saved to {metadata_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving customer data: {e}")
            return False
    
    def extract_and_save(self):
        """Main extraction process"""
        logger.info("Starting customer data extraction from Confluence...")
        
        # Fetch Confluence page
        page_data = self.fetch_confluence_page()
        
        if not page_data:
            logger.error("Failed to fetch Confluence page")
            return False
        
        # Extract HTML content
        html_content = page_data.get('body', {}).get('storage', {}).get('value', '')
        
        if not html_content:
            logger.error("No HTML content found in the page")
            return False
        
        # Extract tables
        tables = self.extract_tables_from_html(html_content)
        
        if not tables:
            logger.warning("No tables found in the page")
            return False
        
        # Process customer data
        processed_data = self.process_customer_data(tables)
        
        # Save to JSON file
        success = self.save_customer_data(tables, processed_data)
        
        if success:
            logger.info("Customer data extraction completed successfully")
            
            # Print summary
            print("\n" + "="*60)
            print("CUSTOMER DATA EXTRACTION SUMMARY")
            print("="*60)
            print(f"Extraction time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Source: Confluence Page ID {self.page_id}")
            print(f"Tables extracted: {len(tables)}")
            print(f"Total records: {sum(len(table) for table in tables)}")
            
            # Count unique customers
            all_customers = set()
            for table in tables:
                for row in table:
                    customer_name = row.get("Customer Name", "")
                    if customer_name:
                        all_customers.add(customer_name)
            
            print(f"Unique customers: {len(all_customers)}")
            
            # Show sample fields
            if tables and tables[0]:
                print(f"\nSample fields found:")
                sample_row = tables[0][0]
                for field in list(sample_row.keys())[:10]:
                    print(f"  - {field}")
                if len(sample_row) > 10:
                    print(f"  ... and {len(sample_row) - 10} more fields")
            
            print("="*60)
        else:
            logger.error("Customer data extraction failed")
        
        return success

def main():
    """Main function"""
    try:
        # Create necessary directories
        os.makedirs('data', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        # Run extraction
        extractor = CustomerDataExtractor()
        success = extractor.extract_and_save()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()