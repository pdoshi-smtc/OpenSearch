from flask import Blueprint, render_template, request, jsonify
import json
import os
from rapidfuzz import process, fuzz
from datetime import datetime
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Create blueprint
kyc_bp = Blueprint('kyc', __name__, 
                   template_folder='templates',
                   static_folder='static')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CustomerDataManager:
    def __init__(self, data_file='data/customer_data.json'):
        self.data_file = data_file
        self.tables = []
        self.all_rows = []
        self.customer_names = []
        self.customer_lookup = {}
        self.load_customer_data()
    
    def load_customer_data(self):
        """Load customer data from JSON file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    self.tables = json.load(f)
                
                # Flatten all tables into one list
                self.all_rows = [row for table in self.tables for row in table]
                
                # Extract customer names for search
                self.customer_names = []
                self.customer_lookup = {}
                
                for row in self.all_rows:
                    customer_name = row.get("Customer Name", "").strip()
                    if customer_name:
                        self.customer_names.append(customer_name)
                        # Create lookup dictionary for faster access
                        self.customer_lookup[customer_name.lower()] = row
                
                # Remove duplicates while preserving order
                seen = set()
                unique_names = []
                for name in self.customer_names:
                    if name.lower() not in seen:
                        seen.add(name.lower())
                        unique_names.append(name)
                self.customer_names = unique_names
                
                logger.info(f"Loaded {len(self.all_rows)} customer records")
                logger.info(f"Found {len(self.customer_names)} unique customers")
            else:
                logger.warning(f"Customer data file not found: {self.data_file}")
                
        except Exception as e:
            logger.error(f"Error loading customer data: {e}")
    
    def reload_data(self):
        """Reload customer data from file"""
        self.load_customer_data()
    
    def search_customer(self, query):
        """Search for a customer by name"""
        query = query.strip()
        
        # Try exact match first (case-insensitive)
        result = self.customer_lookup.get(query.lower())
        if result:
            return result, []
        
        # If no exact match, find suggestions
        suggestions = self.get_suggestions(query, limit=10)
        return None, suggestions
    
    def get_suggestions(self, query, limit=5):
        """Get customer name suggestions using fuzzy matching"""
        if not query:
            return []
        
        # Use fuzzy matching to find similar names
        matches = process.extract(
            query,
            self.customer_names,
            scorer=fuzz.WRatio,
            limit=limit
        )
        
        # Filter matches with score > 50
        suggestions = [match[0] for match in matches if match[1] > 50]
        return suggestions
    
    def get_autocomplete_suggestions(self, query, limit=10):
        """Get autocomplete suggestions for partial input"""
        if not query:
            return []
        
        query_lower = query.lower()
        
        # First, get names that start with the query
        starts_with = [name for name in self.customer_names 
                      if name.lower().startswith(query_lower)]
        
        # Then, get names that contain the query but don't start with it
        contains = [name for name in self.customer_names 
                   if query_lower in name.lower() and not name.lower().startswith(query_lower)]
        
        # Combine results, prioritizing starts_with
        results = starts_with[:limit]
        remaining = limit - len(results)
        if remaining > 0:
            results.extend(contains[:remaining])
        
        return results
    
    def get_customer_details(self, customer_name):
        """Get detailed information for a specific customer"""
        return self.customer_lookup.get(customer_name.lower())
    
    def get_statistics(self):
        """Get customer database statistics"""
        stats = {
            'total_customers': len(self.customer_names),
            'total_records': len(self.all_rows),
            'tables_count': len(self.tables),
            'fields': set()
        }
        
        # Collect all unique fields
        for row in self.all_rows:
            stats['fields'].update(row.keys())
        
        stats['fields'] = list(stats['fields'])
        stats['fields'].sort()
        
        # Get customer distribution by first letter
        letter_distribution = {}
        for name in self.customer_names:
            if name:
                first_letter = name[0].upper()
                letter_distribution[first_letter] = letter_distribution.get(first_letter, 0) + 1
        
        stats['letter_distribution'] = dict(sorted(letter_distribution.items()))
        
        return stats
    
    def search_by_field(self, field_name, value):
        """Search customers by any field"""
        results = []
        value_lower = value.lower()
        
        for row in self.all_rows:
            field_value = str(row.get(field_name, "")).lower()
            if value_lower in field_value:
                results.append(row)
        
        return results
    
    def get_all_customers(self, page=1, per_page=50):
        """Get paginated list of all customers"""
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        # Get unique customers
        unique_customers = []
        seen = set()
        
        for row in self.all_rows:
            customer_name = row.get("Customer Name", "")
            if customer_name and customer_name.lower() not in seen:
                seen.add(customer_name.lower())
                unique_customers.append(row)
        
        total_pages = (len(unique_customers) + per_page - 1) // per_page
        
        return {
            'customers': unique_customers[start_idx:end_idx],
            'total': len(unique_customers),
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        }

# Initialize customer data manager
customer_manager = None

def initialize_customer_manager():
    """Initialize the customer data manager on startup"""
    global customer_manager
    try:
        logger.info("Initializing Customer Data Manager...")
        data_file = os.path.join('data', 'customer_data.json')
        customer_manager = CustomerDataManager(data_file)
        logger.info("✅ Customer Data Manager initialized successfully")
    except Exception as e:
        logger.error(f"❌ Error initializing Customer Data Manager: {e}")
        raise

# Initialize when blueprint is registered
initialize_customer_manager()

@kyc_bp.route('/')
def kyc_home():
    """Main customer search page"""
    stats = customer_manager.get_statistics() if customer_manager else {}
    return render_template('kyc.html', stats=stats)

@kyc_bp.route('/search', methods=['POST'])
def search_customer():
    """Search for a customer"""
    search_query = request.form.get('customer_name', '').strip()
    
    if not search_query:
        return render_template('kyc.html', 
                             stats=customer_manager.get_statistics(),
                             error="Please enter a customer name")
    
    result, suggestions = customer_manager.search_customer(search_query)
    
    return render_template('kyc.html',
                         result=result,
                         search_query=search_query,
                         suggestions=suggestions,
                         stats=customer_manager.get_statistics())

@kyc_bp.route('/api/search', methods=['GET', 'POST'])
def api_search():
    """API endpoint for customer search"""
    if request.method == 'POST':
        data = request.get_json()
        query = data.get('query', '')
    else:
        query = request.args.get('q', '')
    
    if not query:
        return jsonify({'error': 'Query parameter required'}), 400
    
    result, suggestions = customer_manager.search_customer(query)
    
    return jsonify({
        'success': True,
        'query': query,
        'result': result,
        'suggestions': suggestions,
        'timestamp': datetime.now().isoformat()
    })

@kyc_bp.route('/api/suggest', methods=['GET'])
def suggest():
    """API endpoint for autocomplete suggestions"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return jsonify([])
    
    suggestions = customer_manager.get_autocomplete_suggestions(query, limit=10)
    return jsonify(suggestions)

@kyc_bp.route('/api/customer/<customer_name>')
def get_customer_details(customer_name):
    """Get detailed information for a specific customer"""
    customer = customer_manager.get_customer_details(customer_name)
    
    if customer:
        return jsonify({
            'success': True,
            'customer': customer
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Customer not found'
        }), 404

@kyc_bp.route('/api/stats')
def get_statistics():
    """Get customer database statistics"""
    try:
        stats = customer_manager.get_statistics()
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@kyc_bp.route('/api/customers')
def list_customers():
    """Get paginated list of all customers"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    result = customer_manager.get_all_customers(page, per_page)
    return jsonify(result)

@kyc_bp.route('/api/refresh')
def refresh_data():
    """Refresh customer data from file"""
    try:
        customer_manager.reload_data()
        stats = customer_manager.get_statistics()
        return jsonify({
            'success': True,
            'message': 'Customer data refreshed successfully',
            'stats': stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@kyc_bp.route('/api/search/field', methods=['POST'])
def search_by_field():
    """Search customers by any field"""
    data = request.get_json()
    field_name = data.get('field')
    value = data.get('value', '')
    
    if not field_name or not value:
        return jsonify({'error': 'Field name and value required'}), 400
    
    results = customer_manager.search_by_field(field_name, value)
    
    return jsonify({
        'success': True,
        'field': field_name,
        'value': value,
        'results': results,
        'count': len(results)
    })