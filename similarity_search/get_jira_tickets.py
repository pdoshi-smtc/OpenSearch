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
        self.output_file = os.path.join('data', 'raw/jira_tickets.json')  
        
        if not self.api_token or not self.user_email:
            logger.error("JIRA credentials not found in environment variables")
            raise ValueError("Please set JIRA_API_TOKEN and JIRA_USER_EMAIL in .env file")
    
    def get_jira_issues(self, jql_query, max_tickets=500):
        """Fetch issues from JIRA using JQL with proper pagination"""
        auth = HTTPBasicAuth(self.user_email, self.api_token)
        headers = {"Accept": "application/json"}
        
        all_issues = []
        fetched_ids = set()  # Track unique issue IDs to avoid duplicates
        next_page_token = None
        batch_size = 100  # JIRA API allows up to 100 per request
        page_count = 0
        
        while len(all_issues) < max_tickets:
            # Calculate how many to fetch in this batch
            remaining = max_tickets - len(all_issues)
            current_batch_size = min(batch_size, remaining)
            
            url = f"{self.jira_url}/rest/api/3/search/jql"
            
            # Build params - use nextPageToken if available
            params = {
                'jql': jql_query,
                'maxResults': current_batch_size,
                'fields': 'summary,description,status,priority,created,assignee,reporter,issuetype,updated,labels,components,comment',
                'expand': 'renderedFields'
            }
            
            # Use nextPageToken for pagination if available, otherwise use startAt
            if next_page_token:
                params['nextPageToken'] = next_page_token
                logger.info(f"Requesting batch with nextPageToken, maxResults={current_batch_size}")
            else:
                params['startAt'] = len(all_issues)
                logger.info(f"Requesting batch: startAt={params['startAt']}, maxResults={current_batch_size}")
            
            try:
                response = requests.get(url, headers=headers, params=params, auth=auth)
                response.raise_for_status()
                data = response.json()
                
                # Debug: Log what we got from API
                total_in_response = data.get('total', 'not provided')
                issues = data.get('issues', [])
                logger.info(f"API Response: total={total_in_response}, issues_in_batch={len(issues)}, page={page_count + 1}")
                
                # Check for nextPageToken in response
                next_page_token = data.get('nextPageToken')
                
                # If no issues returned, we've reached the end
                if not issues or len(issues) == 0:
                    logger.info("No more issues to fetch - empty batch returned")
                    break
                
                # Add only unique issues
                new_issues_count = 0
                for issue in issues:
                    issue_id = issue.get('id')
                    if issue_id and issue_id not in fetched_ids:
                        all_issues.append(issue)
                        fetched_ids.add(issue_id)
                        new_issues_count += 1
                
                logger.info(f"Added {new_issues_count} new unique issues. Total unique issues: {len(all_issues)}")
                
                # If no new unique issues were added, we might be in a loop
                if new_issues_count == 0:
                    logger.warning("No new unique issues in this batch - may have reached the end of unique results")
                    break
                
                # Check if we've reached the maximum we want to fetch
                if len(all_issues) >= max_tickets:
                    logger.info(f"Reached max_tickets limit of {max_tickets}")
                    all_issues = all_issues[:max_tickets]  # Trim to exact max_tickets
                    break
                
                # Check if this is the last page
                is_last = data.get('isLast', False)
                if is_last:
                    logger.info("Reached last page according to API")
                    break
                
                # If we got fewer issues than requested and no nextPageToken, we've reached the end
                if len(issues) < current_batch_size and not next_page_token:
                    logger.info(f"Fetched all available issues (got {len(issues)} in last batch, requested {current_batch_size})")
                    break
                
                page_count += 1
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching JIRA issues: {e}")
                logger.error(f"Response content: {response.text if 'response' in locals() else 'No response'}")
                break
        
        logger.info(f"Total unique issues fetched: {len(all_issues)}")
        return all_issues
    
    def process_issues(self, issues):
        """Process JIRA issues into the required format"""
        processed_data = []
        
        for issue in issues:
            fields = issue.get('fields', {})
            
            # Generate document ID
            doc_id = f"jira_{issue.get('id', '')}"
            
            # Extract summary and description
            summary = fields.get('summary', '')
            
            # Handle description - it might be in ADF format or plain text
            description = self.clean_description(fields.get('description', ''))
            
            # Create searchable text
            searchable_text = f"{summary} {description}".strip()
            
            # Extract comments
            comments = []
            comment_data = fields.get('comment', {})
            if comment_data and 'comments' in comment_data:
                for comment in comment_data.get('comments', []):
                    comment_body = comment.get('body', '')
                    # Handle ADF format in comments
                    if isinstance(comment_body, dict):
                        comment_text = self.extract_text_from_adf(comment_body)
                    else:
                        comment_text = str(comment_body)
                    
                    comments.append({
                        'author': comment.get('author', {}).get('displayName', 'Unknown'),
                        'created': comment.get('created', ''),
                        'updated': comment.get('updated', ''),
                        'body': comment_text
                    })
            
            # Build the issue data in the exact format requested
            issue_data = {
                'id': doc_id,
                'key': issue.get('key', ''),
                'issue_id': issue.get('id', ''),
                'type': fields.get('issuetype', {}).get('name', 'Unknown') if fields.get('issuetype') else 'Unknown',
                'summary': summary,
                'description': description,
                'searchable_text': searchable_text,
                'assignee': fields.get('assignee', {}).get('displayName', 'Unassigned') if fields.get('assignee') else 'Unassigned',
                'reporter': fields.get('reporter', {}).get('displayName', '') if fields.get('reporter') else '',
                'priority': fields.get('priority', {}).get('name', 'Unknown') if fields.get('priority') else 'Unknown',
                'status': fields.get('status', {}).get('name', 'Unknown') if fields.get('status') else 'Unknown',
                'created': fields.get('created', ''),
                'updated': fields.get('updated', ''),
                'labels': fields.get('labels', []),
                'components': [c.get('name', '') for c in fields.get('components', [])] if fields.get('components') else [],
                'comments': comments,
                'metadata': {
                    'url': f"{self.jira_url}/browse/{issue.get('key', '')}",
                    'last_indexed': datetime.now().isoformat()
                }
            }
            
            processed_data.append(issue_data)
        
        return processed_data
    
    def extract_text_from_adf(self, adf_content):
        """Extract plain text from ADF content"""
        if not isinstance(adf_content, dict):
            return str(adf_content)
        
        text_parts = []
        
        def extract_from_node(node):
            if isinstance(node, dict):
                # Extract text from text nodes
                if node.get('type') == 'text':
                    text_parts.append(node.get('text', ''))
                # Recursively process content
                if 'content' in node:
                    for item in node.get('content', []):
                        extract_from_node(item)
            elif isinstance(node, list):
                for item in node:
                    extract_from_node(item)
        
        # Start extraction from the root content
        if 'content' in adf_content:
            extract_from_node(adf_content.get('content', []))
        else:
            extract_from_node(adf_content)
        
        return ' '.join(text_parts)

    
    def clean_description(self, description):
        """Clean JIRA description text"""
        import re

        # Handle None or empty description
        if not description:
            return ''

        # If description is a dict (Atlassian Document Format), extract plain text
        if isinstance(description, dict):
            text_parts = []

            def extract_text(node):
                if isinstance(node, dict):
                    # Extract text from text nodes
                    if node.get('type') == 'text':
                        text_parts.append(node.get('text', ''))
                    # Recursively process content
                    if 'content' in node:
                        for item in node.get('content', []):
                            extract_text(item)
                elif isinstance(node, list):
                    for item in node:
                        extract_text(item)

            # Start extraction from the root content
            if 'content' in description:
                extract_text(description.get('content', []))
            else:
                extract_text(description)
                
            description = ' '.join(text_parts)

        # Now ensure it's a string
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
    
    def extract_and_save(self):
        """Main extraction process"""
        logger.info("Starting JIRA data extraction...")
        
        # Define JQL query - modify based on your needs
        # This example gets all issues updated in the last 30 days
        project=os.getenv('PROJECT')
        days_back = 30
        max_tickets = 500  # Set maximum tickets to fetch
        
        jql_queries = [
            f"project = {project} AND updated >= -{days_back}d ORDER BY updated DESC"
            # Add more queries as needed
        ]
        
        all_issues = []
        for jql in jql_queries:
            logger.info(f"Executing JQL: {jql}")
            logger.info(f"Max tickets to fetch: {max_tickets}")
            issues = self.get_jira_issues(jql, max_tickets=max_tickets)
            all_issues.extend(issues)
            logger.info(f"Fetched {len(issues)} issues for this query")
        
        if not all_issues:
            logger.warning("No issues found")
            return
        
        # Process issues
        logger.info(f"Processing {len(all_issues)} issues...")
        processed_issues = self.process_issues(all_issues)
        
        # Remove duplicates based on issue_id
        unique_issues = []
        seen_ids = set()
        for issue in processed_issues:
            if issue['issue_id'] not in seen_ids:
                unique_issues.append(issue)
                seen_ids.add(issue['issue_id'])
        
        if len(processed_issues) != len(unique_issues):
            logger.info(f"Removed {len(processed_issues) - len(unique_issues)} duplicate issues")
        
        # Save to JSON
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(unique_issues, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved {len(unique_issues)} issues to {self.output_file}")
        
        # Create status and priority distributions for metadata
        status_dist = {}
        priority_dist = {}
        for issue in unique_issues:
            status = issue.get('status', 'Unknown')
            priority = issue.get('priority', 'Unknown')
            status_dist[status] = status_dist.get(status, 0) + 1
            priority_dist[priority] = priority_dist.get(priority, 0) + 1
        
        # Save metadata
        metadata = {
            'extraction_date': datetime.now().isoformat(),
            'total_issues': len(unique_issues),
            'status_distribution': status_dist,
            'priority_distribution': priority_dist
        }
        
        with open(os.path.join('data', 'raw/jira_metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("Extraction completed successfully")
        
        return unique_issues

def main():
    """Main function"""
    try:
        # Create data directory if it doesn't exist
        os.makedirs('data', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        # Run extraction
        extractor = JiraDataExtractor()
        issues = extractor.extract_and_save()
        
        # Print summary
        if issues:
            print(f"\nExtraction Summary:")
            print(f"Total issues: {len(issues)}")
            
            # Get date range
            dates = [issue['created'] for issue in issues if issue.get('created')]
            if dates:
                print(f"Date range: {min(dates)} to {max(dates)}")
            
            # Status distribution
            status_counts = {}
            for issue in issues:
                status = issue.get('status', 'Unknown')
                status_counts[status] = status_counts.get(status, 0) + 1
            
            print(f"\nStatus distribution:")
            for status, count in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {status}: {count}")
            
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()