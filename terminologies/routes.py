from flask import Blueprint, render_template, request, jsonify
import json
import os
from rapidfuzz import process, fuzz
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Create blueprint
terms_bp = Blueprint('terms', __name__, 
                    template_folder='templates',
                    static_folder='static')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TerminologyManager:
    def __init__(self, data_file='data/handbook.json'):
        self.data_file = data_file
        self.tables = []
        self.all_rows = []
        self.terms_index = {}
        self.categories = defaultdict(list)
        self.load_terminology_data()
    
    def load_terminology_data(self):
        """Load terminology data from JSON file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    self.tables = json.load(f)
                
                # Flatten all tables and build index
                self.all_rows = []
                self.terms_index = {}
                
                for table in self.tables:
                    for row in table:
                        if row:
                            self.all_rows.append(row)
                            
                            # Get the first column value as the main term
                            first_val = list(row.values())[0] if row else ""
                            if first_val:
                                # Create searchable index
                                term_lower = first_val.lower()
                                self.terms_index[term_lower] = row
                                
                                # Categorize by first letter
                                first_letter = first_val[0].upper() if first_val else '#'
                                if not first_letter.isalpha():
                                    first_letter = '#'
                                self.categories[first_letter].append(first_val)
                
                # Sort categories
                for letter in self.categories:
                    self.categories[letter].sort()
                
                logger.info(f"Loaded {len(self.all_rows)} terminology entries")
                logger.info(f"Created index with {len(self.terms_index)} terms")
                
            else:
                logger.warning(f"Terminology data file not found: {self.data_file}")
                
        except Exception as e:
            logger.error(f"Error loading terminology data: {e}")
    
    def reload_data(self):
        """Reload terminology data from file"""
        self.load_terminology_data()
    
    def search_term(self, query):
        """Search for a term by exact or fuzzy match"""
        query = query.strip()
        
        # Try exact match first (case-insensitive)
        result = self.terms_index.get(query.lower())
        if result:
            return result, []
        
        # If no exact match, find suggestions
        suggestions = self.get_suggestions(query, limit=10)
        return None, suggestions
    
    def get_suggestions(self, query, limit=5):
        """Get term suggestions using fuzzy matching"""
        if not query:
            return []
        
        # Get all terms for fuzzy matching
        all_terms = list(self.terms_index.keys())
        
        # Use fuzzy matching
        matches = process.extract(
            query.lower(),
            all_terms,
            scorer=fuzz.WRatio,
            limit=limit
        )
        
        # Get the actual term names (not lowercase)
        suggestions = []
        for match in matches:
            if match[1] > 40:  # Threshold for similarity
                # Find the original term
                for row in self.all_rows:
                    first_val = list(row.values())[0] if row else ""
                    if first_val.lower() == match[0]:
                        suggestions.append(first_val)
                        break
        
        return suggestions
    
    def get_autocomplete_suggestions(self, query, limit=10):
        """Get autocomplete suggestions for partial input"""
        if not query:
            return []
        
        query_lower = query.lower()
        matches = []
        
        # First, get terms that start with the query
        for row in self.all_rows:
            if row:
                first_val = list(row.values())[0]
                if first_val and first_val.lower().startswith(query_lower):
                    matches.append(first_val)
                    if len(matches) >= limit:
                        break
        
        # If not enough matches, also include terms that contain the query
        if len(matches) < limit:
            for row in self.all_rows:
                if row:
                    first_val = list(row.values())[0]
                    if first_val and query_lower in first_val.lower() and first_val not in matches:
                        matches.append(first_val)
                        if len(matches) >= limit:
                            break
        
        return matches[:limit]
    
    def get_term_details(self, term):
        """Get detailed information for a specific term"""
        return self.terms_index.get(term.lower())
    
    def get_statistics(self):
        """Get terminology database statistics"""
        stats = {
            'total_terms': len(self.terms_index),
            'total_entries': len(self.all_rows),
            'tables_count': len(self.tables),
            'categories': {},
            'fields': set()
        }
        
        # Count terms by category
        for letter, terms in self.categories.items():
            stats['categories'][letter] = len(terms)
        
        # Collect all unique fields
        for row in self.all_rows:
            if row:
                stats['fields'].update(row.keys())
        
        stats['fields'] = sorted(list(stats['fields']))
        
        return stats
    
    def get_terms_by_letter(self, letter):
        """Get all terms starting with a specific letter"""
        if letter == 'ALL':
            all_terms = []
            for row in self.all_rows:
                if row:
                    first_val = list(row.values())[0]
                    if first_val:
                        all_terms.append(first_val)
            return sorted(set(all_terms))
        
        return self.categories.get(letter, [])
    
    def search_by_field(self, field_name, value):
        """Search terms by any field"""
        results = []
        value_lower = value.lower()
        
        for row in self.all_rows:
            if row and field_name in row:
                field_value = str(row.get(field_name, "")).lower()
                if value_lower in field_value:
                    results.append(row)
        
        return results
    
    def get_all_terms(self, page=1, per_page=50):
        """Get paginated list of all terms"""
        all_terms = []
        for row in self.all_rows:
            if row:
                first_val = list(row.values())[0]
                if first_val:
                    all_terms.append({
                        'term': first_val,
                        'data': row
                    })
        
        # Sort by term
        all_terms.sort(key=lambda x: x['term'].lower())
        
        # Paginate
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        total_pages = (len(all_terms) + per_page - 1) // per_page
        
        return {
            'terms': all_terms[start_idx:end_idx],
            'total': len(all_terms),
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        }
    
    def get_recent_searches(self, limit=10):
        """Get recently searched terms (would require search history tracking)"""
        # This is a placeholder - in production, you'd track search history
        return []
    
    def export_terms(self, format='json'):
        """Export all terms in specified format"""
        if format == 'json':
            return self.all_rows
        elif format == 'csv':
            # Convert to CSV format
            if not self.all_rows:
                return ""
            
            import csv
            import io
            
            output = io.StringIO()
            if self.all_rows:
                fieldnames = list(self.all_rows[0].keys())
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.all_rows)
            
            return output.getvalue()
        
        return None

# Initialize terminology manager
terms_manager = None

def initialize_terms_manager():
    """Initialize the terminology manager on startup"""
    global terms_manager
    try:
        logger.info("Initializing Terminology Manager...")
        data_file = os.path.join('data', 'handbook.json')
        terms_manager = TerminologyManager(data_file)
        logger.info("✅ Terminology Manager initialized successfully")
    except Exception as e:
        logger.error(f"❌ Error initializing Terminology Manager: {e}")
        raise

# Initialize when blueprint is registered
initialize_terms_manager()

@terms_bp.route('/')
def terms_home():
    """Main terminology search page"""
    stats = terms_manager.get_statistics() if terms_manager else {}
    return render_template('terminologies.html', stats=stats)

@terms_bp.route('/search', methods=['POST'])
def search_term():
    """Search for a term"""
    query = request.form.get('term', '').strip()
    
    if not query:
        return render_template('terminologies.html', 
                             stats=terms_manager.get_statistics(),
                             error="Please enter a term to search")
    
    result, suggestions = terms_manager.search_term(query)
    
    return render_template('terminologies.html',
                         query=query,
                         result=result,
                         suggestions=suggestions,
                         stats=terms_manager.get_statistics())

@terms_bp.route('/api/search', methods=['GET', 'POST'])
def api_search():
    """API endpoint for term search"""
    if request.method == 'POST':
        data = request.get_json()
        query = data.get('query', '')
    else:
        query = request.args.get('q', '')
    
    if not query:
        return jsonify({'error': 'Query parameter required'}), 400
    
    result, suggestions = terms_manager.search_term(query)
    
    return jsonify({
        'success': True,
        'query': query,
        'result': result,
        'suggestions': suggestions,
        'timestamp': datetime.now().isoformat()
    })

@terms_bp.route('/api/suggest', methods=['GET'])
def suggest():
    """API endpoint for autocomplete suggestions"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return jsonify([])
    
    suggestions = terms_manager.get_autocomplete_suggestions(query, limit=10)
    return jsonify(suggestions)

@terms_bp.route('/api/term/<term_name>')
def get_term_details(term_name):
    """Get detailed information for a specific term"""
    term = terms_manager.get_term_details(term_name)
    
    if term:
        return jsonify({
            'success': True,
            'term': term
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Term not found'
        }), 404

@terms_bp.route('/api/stats')
def get_statistics():
    """Get terminology database statistics"""
    try:
        stats = terms_manager.get_statistics()
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@terms_bp.route('/api/terms')
def list_terms():
    """Get paginated list of all terms"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    letter = request.args.get('letter', '')
    
    if letter:
        terms = terms_manager.get_terms_by_letter(letter)
        return jsonify({
            'success': True,
            'letter': letter,
            'terms': terms,
            'count': len(terms)
        })
    else:
        result = terms_manager.get_all_terms(page, per_page)
        return jsonify(result)

@terms_bp.route('/api/refresh')
def refresh_data():
    """Refresh terminology data from file"""
    try:
        terms_manager.reload_data()
        stats = terms_manager.get_statistics()
        return jsonify({
            'success': True,
            'message': 'Terminology data refreshed successfully',
            'stats': stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@terms_bp.route('/api/export')
def export_terms():
    """Export all terms"""
    format = request.args.get('format', 'json')
    
    if format == 'csv':
        csv_data = terms_manager.export_terms('csv')
        return csv_data, 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=terminologies_{datetime.now().strftime("%Y%m%d")}.csv'
        }
    else:
        return jsonify(terms_manager.export_terms('json'))

@terms_bp.route('/api/categories')
def get_categories():
    """Get all term categories (alphabetical)"""
    stats = terms_manager.get_statistics()
    categories = stats.get('categories', {})
    
    return jsonify({
        'success': True,
        'categories': categories,
        'total': sum(categories.values())
    })