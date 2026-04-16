#!/usr/bin/env python3
"""
Daily script to extract JIRA data for Similarity Search application
This script should be scheduled to run daily using cron or task scheduler
"""

import os
import sys
import pandas as pd
from datetime import datetime, timedelta
import requests
from requests.auth import HTTPBasicAuth
import json
import logging
from dotenv import load_dotenv

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/jira_extraction.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class JiraDataExtractor:
    def __init__(self):
        self.jira_url = os.getenv('JIRA_BASE_URL')
        self.api_token = os.getenv('JIRA_API_TOKEN')
        self.user_email = os.getenv('JIRA_USER_EMAIL')
        self.output_file = os.path.join('data', 'jira_export.csv')
        
        
        if not self.api_token or not self.user_email:
            logger.error("JIRA credentials not found in environment variables")
            raise ValueError("Please set JIRA_API_TOKEN and JIRA_USER_EMAIL in .env file")
    
    def get_jira_issues(self, jql_query, max_results=1000):
        """Fetch issues from JIRA using JQL"""
        auth = HTTPBasicAuth(self.user_email, self.api_token)
        headers = {"Accept": "application/json"}
        
        all_issues = []
        start_at = 0
        
        while True:
            url = f"{self.jira_url}/rest/api/3/search/jql"
            params = {
                'jql': jql_query,
                'startAt': start_at,
                'maxResults': max_results,  # JIRA API limit
                'fields': 'summary,description,status,priority,created,assignee,issuetype,updated,labels,components'
            }
            
            try:
                response = requests.get(url, headers=headers, params=params, auth=auth)
                response.raise_for_status()
                data = response.json()
                
                issues = data.get('issues', [])
                all_issues.extend(issues)
                
                if len(all_issues) >= max_results or len(issues) < 50:
                    break
                
                start_at += 50
                logger.info(f"Fetched {len(all_issues)} issues so far...")
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching JIRA issues: {e}")
                break
        
        return all_issues
    
    def process_issues(self, issues):
        """Process JIRA issues into a DataFrame"""
        processed_data = []
        
        for issue in issues:
            fields = issue.get('fields', {})
            
            # Extract relevant fields
            issue_data = {
                'Issue key': issue.get('key', ''),
                'Summary': fields.get('summary', ''),
                'Description': self.clean_description(fields.get('description', '')),
                'Status': fields.get('status', {}).get('name', 'Unknown'),
                'Priority': fields.get('priority', {}).get('name', 'Unknown') if fields.get('priority') else 'Unknown',
                'Issue Type': fields.get('issuetype', {}).get('name', 'Unknown'),
                'Created': fields.get('created', ''),
                'Updated': fields.get('updated', ''),
                'Assignee': fields.get('assignee', {}).get('displayName', 'Unassigned') if fields.get('assignee') else 'Unassigned',
                'Labels': ', '.join(fields.get('labels', [])),
                'Components': ', '.join([c.get('name', '') for c in fields.get('components', [])])
            }
            
            processed_data.append(issue_data)
        
        return pd.DataFrame(processed_data)

    
    def clean_description(self, description):
        """Clean JIRA description text"""
        import re

        # Handle None or empty description
        if not description:
            return ''

        # ✅ If description is a dict (Atlassian Document Format), extract plain text
        if isinstance(description, dict):
            text_parts = []

            def extract_text(content):
                for item in content:
                    if item.get('type') == 'text':
                        text_parts.append(item.get('text', ''))
                    elif 'content' in item:
                        extract_text(item['content'])

            extract_text(description.get('content', []))
            description = ' '.join(text_parts)

        # ✅ Now ensure it's a string
        if not isinstance(description, str):
            description = str(description)

        # Remove {code} blocks
        description = re.sub(r'\{code.*?\}.*?\{code\}', '', description, flags=re.DOTALL)

        # Remove other JIRA markup
        description = re.sub(r'\{.*?\}', '', description)
        description = re.sub(r'\[.*?\|.*?\]', '', description)
        description = re.sub(r'h\d\.', '', description)
        description = re.sub(r'\*+', '', description)
        description = re.sub(r'_+', '', description)
        description = re.sub(r'-+', '', description)

        # Clean whitespace
        description = ' '.join(description.split())

        return description[:2000]  # Limit description length

    # def clean_description(self, description):
    #     """Clean JIRA description text"""
    #     if not description:
    #         return ''
        
    #     # Remove JIRA formatting
    #     import re
        
    #     # Remove {code} blocks
    #     description = re.sub(r'\{code.*?\}.*?\{code\}', '', description, flags=re.DOTALL)
        
    #     # Remove other JIRA markup
    #     description = re.sub(r'\{.*?\}', '', description)
    #     description = re.sub(r'\[.*?\|.*?\]', '', description)
    #     description = re.sub(r'h\d\.', '', description)
    #     description = re.sub(r'\*+', '', description)
    #     description = re.sub(r'_+', '', description)
    #     description = re.sub(r'-+', '', description)
        
    #     # Clean whitespace
    #     description = ' '.join(description.split())
        
    #     return description[:2000]  # Limit description length
    
    def extract_and_save(self):
        """Main extraction process"""
        logger.info("Starting JIRA data extraction...")
        
        # Define JQL query - modify based on your needs
        # This example gets all issues updated in the last 30 days
        project=os.getenv('PROJECT')
        days_back = 30
        jql_queries = [
            f"project = {project} AND updated >= -{days_back}d ORDER BY updated DESC"
            # Add more queries as needed
        ]
        
        all_issues = []
        for jql in jql_queries:
            logger.info(f"Executing JQL: {jql}")
            issues = self.get_jira_issues(jql)
            all_issues.extend(issues)
            logger.info(f"Fetched {len(issues)} issues for this query")
        
        if not all_issues:
            logger.warning("No issues found")
            return
        
        # Process issues
        df = self.process_issues(all_issues)
        
        # Remove duplicates based on Issue key
        df = df.drop_duplicates(subset=['Issue key'])
        
        # Save to CSV
        df.to_csv(self.output_file, index=False)
        logger.info(f"Saved {len(df)} issues to {self.output_file}")
        
        # Save metadata
        metadata = {
            'extraction_date': datetime.now().isoformat(),
            'total_issues': len(df),
            'status_distribution': df['Status'].value_counts().to_dict(),
            'priority_distribution': df['Priority'].value_counts().to_dict()
        }
        
        with open(os.path.join('data', 'jira_metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("Extraction completed successfully")
        
        return df

def main():
    """Main function"""
    try:
        # Create data directory if it doesn't exist
        os.makedirs('data', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        # Run extraction
        extractor = JiraDataExtractor()
        df = extractor.extract_and_save()
        
        # Print summary
        if df is not None:
            print(f"\nExtraction Summary:")
            print(f"Total issues: {len(df)}")
            print(f"Date range: {df['Created'].min()} to {df['Created'].max()}")
            print(f"\nStatus distribution:")
            print(df['Status'].value_counts())
            
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()