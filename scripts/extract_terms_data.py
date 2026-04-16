#!/usr/bin/env python3
"""
Daily script to extract terminology data from Confluence
This script should be scheduled to run daily using cron or task scheduler
"""

import requests
import os
import sys
import json
from datetime import datetime
from bs4 import BeautifulSoup
import urllib3
import logging
from dotenv import load_dotenv

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
        logging.FileHandler('logs/terms_extraction.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TerminologyDataExtractor:
    def __init__(self):
        # Configuration from environment
        self.pat = os.getenv('CONFLUENCE_PASSWORD')
        self.base_url = os.getenv('CONFLUENCE_BASE_URL', 'https://confluence.sierrawireless.com')
        self.page_id = os.getenv('CONFLUENCE_TERMS_PAGE_ID', '407798724')
        
        # Output file
        self.output_file = os.path.join('data', 'handbook.json')
        
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
        soup = BeautifulSoup(html_content, "html.parser")
        tables = soup.find_all("table")
        all_data = []
        
        logger.info(f"Found {len(tables)} tables in the page")
        
        for table_idx, table in enumerate(tables):
            headers = []
            rows_data = []
            
            # Process each row in the table
            for i, row in enumerate(table.find_all("tr")):
                cols = row.find_all(["th", "td"])
                cols_text = [col.get_text(strip=True) for col in cols]
                
                if i == 0:
                    # First row is headers
                    headers = cols_text
                    logger.info(f"Table {table_idx + 1} headers: {headers}")
                else:
                    # Create dictionary for each row
                    if headers and len(cols_text) == len(headers):
                        row_dict = {headers[j]: cols_text[j] for j in range(len(cols_text))}
                        rows_data.append(row_dict)
                    elif cols_text:  # Handle rows without headers
                        row_dict = {f"Column_{j+1}": cols_text[j] for j in range(len(cols_text))}
                        rows_data.append(row_dict)
            
            if rows_data:
                all_data.append(rows_data)
                logger.info(f"Extracted {len(rows_data)} rows from table {table_idx + 1}")
        
        return all_data
    
    def process_terminology_data(self, tables):
        """Process and clean terminology data"""
        processed_tables = []
        all_terms = set()
        term_count = 0
        
        for table_idx, table in enumerate(tables):
            processed_rows = []
            
            for row in table:
                # Clean each field in the row
                cleaned_row = {}
                has_content = False
                
                for key, value in row.items():
                    # Clean key and value
                    clean_key = key.strip() if key else f"Field_{len(cleaned_row)+1}"
                    clean_value = str(value).strip() if value else ""
                    
                    # Skip completely empty values
                    if clean_value and clean_value.lower() not in ['', 'none', 'null', 'n/a']:
                        cleaned_row[clean_key] = clean_value
                        has_content = True
                
                if has_content:
                    processed_rows.append(cleaned_row)
                    
                    # Track unique terms (first column value)
                    if cleaned_row:
                        first_val = list(cleaned_row.values())[0]
                        if first_val:
                            all_terms.add(first_val)
                            term_count += 1
            
            if processed_rows:
                processed_tables.append(processed_rows)
        
        logger.info(f"Processed {term_count} terminology entries")
        logger.info(f"Found {len(all_terms)} unique terms")
        
        return processed_tables, all_terms
    
    def save_terminology_data(self, tables, unique_terms):
        """Save terminology data to JSON file"""
        try:
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            
            # Save the table data
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(tables, f, indent=2, ensure_ascii=False)
            
            # Prepare and save metadata
            metadata = {
                'extraction_date': datetime.now().isoformat(),
                'source_page_id': self.page_id,
                'source_url': f"{self.base_url}/pages/viewpage.action?pageId={self.page_id}",
                'total_tables': len(tables),
                'total_entries': sum(len(table) for table in tables),
                'unique_terms': len(unique_terms),
                'categories': self.categorize_terms(unique_terms)
            }
            
            metadata_file = os.path.join('data', 'handbook_metadata.json')
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Successfully saved terminology data to {self.output_file}")
            logger.info(f"Metadata saved to {metadata_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving terminology data: {e}")
            return False
    
    def categorize_terms(self, terms):
        """Categorize terms by first letter"""
        categories = {}
        
        for term in terms:
            if term:
                first_char = term[0].upper()
                if not first_char.isalpha():
                    first_char = '#'
                
                if first_char not in categories:
                    categories[first_char] = 0
                categories[first_char] += 1
        
        return dict(sorted(categories.items()))
    
    def extract_and_save(self):
        """Main extraction process"""
        logger.info("Starting terminology data extraction from Confluence...")
        
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
        
        # Process terminology data
        processed_tables, unique_terms = self.process_terminology_data(tables)
        
        # Save to JSON file
        success = self.save_terminology_data(processed_tables, unique_terms)
        
        if success:
            logger.info("Terminology data extraction completed successfully")
            
            # Print summary
            print("\n" + "="*60)
            print("TERMINOLOGY DATA EXTRACTION SUMMARY")
            print("="*60)
            print(f"Extraction time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Source: Confluence Page ID {self.page_id}")
            print(f"Tables extracted: {len(processed_tables)}")
            print(f"Total entries: {sum(len(table) for table in processed_tables)}")
            print(f"Unique terms: {len(unique_terms)}")
            
            # Show category distribution
            categories = self.categorize_terms(unique_terms)
            print(f"\nTerms by first letter:")
            for letter, count in sorted(categories.items()):
                print(f"  {letter}: {count}")
            
            # Show sample terms
            sample_terms = list(unique_terms)[:10]
            print(f"\nSample terms:")
            for term in sample_terms:
                print(f"  - {term}")
            if len(unique_terms) > 10:
                print(f"  ... and {len(unique_terms) - 10} more")
            
            print("="*60)
        else:
            logger.error("Terminology data extraction failed")
        
        return success

def main():
    """Main function"""
    try:
        # Create necessary directories
        os.makedirs('data', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        # Run extraction
        extractor = TerminologyDataExtractor()
        success = extractor.extract_and_save()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()