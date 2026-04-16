import os
import json
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set
import warnings
import logging
import re
from collections import Counter

# Suppress warnings
warnings.filterwarnings('ignore', category=FutureWarning, module='transformers')
logging.getLogger('chromadb').setLevel(logging.ERROR)
os.environ['ANONYMIZED_TELEMETRY'] = 'False'

import chromadb
from sentence_transformers import SentenceTransformer
from flask import Blueprint, render_template, request, jsonify
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create blueprint
similarity_bp = Blueprint('similarity', __name__, 
                         template_folder='templates',
                         static_folder='static')


class EnhancedJiraRAG:
    def __init__(self, model_name="BAAI/bge-base-en-v1.5"):
        """Initialize the RAG system with BGE embeddings and ChromaDB."""
        print("="*60)
        print("Initializing EnhancedJiraRAG...")
        print("="*60)
        
        # Initialize the embedding model
        print(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        print(f"✅ Model loaded successfully! Embedding dimension: {self.model.get_sentence_embedding_dimension()}")
        
        # Initialize ChromaDB
        self.setup_chromadb()
        
        # State tracking file
        self.state_file = "data/raw/indexing_state.json"
        self.load_indexing_state()
    
    def setup_chromadb(self):
        """Setup ChromaDB with proper configuration"""
        print("\nSetting up ChromaDB...")
        
        # Create persistent client with a fixed path
        self.client = chromadb.PersistentClient(path="./chroma_db")
        
        # List all collections
        collections = self.client.list_collections()
        print(f"Existing collections: {[c.name for c in collections]}")
    
        # Try to get the specific collection
        collection_found = False
        for collection in collections:
            if collection.name == "jira_tickets_enhanced":
                self.collection = collection
                doc_count = self.collection.count()
                print(f"✅ Found existing collection 'jira_tickets_enhanced' with {doc_count} documents")
                collection_found = True
                break

        if not collection_found:
            # Create new collection if doesn't exist
            self.collection = self.client.create_collection(
                name="jira_tickets_enhanced",
                metadata={"hnsw:space": "cosine"}
            )
            print("✅ Created new collection 'jira_tickets_enhanced'")
    
    def get_existing_keys_from_chromadb(self) -> Set[str]:
        """Get all existing document keys from ChromaDB"""
        try:
            if self.collection.count() == 0:
                return set()
            
            # Get all documents to extract keys
            results = self.collection.get()
            existing_keys = set(results['ids'])
            print(f"📊 Found {len(existing_keys)} existing documents in ChromaDB")
            return existing_keys
        except Exception as e:
            print(f"⚠️ Error getting existing keys from ChromaDB: {e}")
            return set()
    
    def load_indexing_state(self):
        """Load the state of previous indexing operations"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    self.state = json.load(f)
                print(f"📊 Loaded state: Last key: {self.state.get('last_ticket_key')}, Total indexed: {self.state.get('total_indexed', 0)}")
            except Exception as e:
                print(f"⚠️ Error loading state file: {e}")
                self.state = self.get_default_state()
        else:
            self.state = self.get_default_state()
            print("📊 No previous state found, starting fresh")
    
    def get_default_state(self):
        """Get default state structure"""
        return {
            'last_ticket_key': None,
            'last_ticket_numeric': 0,
            'last_indexed_timestamp': None,
            'total_indexed': 0,
            'key_pattern': None,
            'skipped_duplicates': []
        }
    
    def save_indexing_state(self):
        """Save the current state of indexing"""
        try:
            if len(self.state.get('skipped_duplicates', [])) > 100:
                self.state['skipped_duplicates'] = self.state['skipped_duplicates'][-100:]
            
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
            print(f"💾 State saved: Last key: {self.state.get('last_ticket_key')}, Total indexed: {self.state.get('total_indexed', 0)}")
        except Exception as e:
            print(f"⚠️ Error saving state: {e}")
    
    def clear_collection(self):
        """Clear all documents from collection and reset state"""
        try:
            self.client.delete_collection(name="jira_tickets_enhanced")
            self.collection = self.client.create_collection(
                name="jira_tickets_enhanced",
                metadata={"hnsw:space": "cosine"}
            )
            
            # Reset state
            self.state = self.get_default_state()
            self.save_indexing_state()
            
            print("✅ Cleared collection and reset state for fresh indexing")
        except Exception as e:
            print(f"Error clearing collection: {e}")
    
    def extract_key_parts(self, ticket_key):
        """Extract pattern and numeric part from ticket key"""
        if not ticket_key:
            return None, None
        
        patterns = [
            r'^([A-Z]+)-(\d+)$',
            r'^([A-Z]+)(\d+)$',
            r'^([A-Za-z]+)-(\d+)$',
            r'^(\w+)-(\d+)$',
        ]
        
        for pattern in patterns:
            match = re.match(pattern, ticket_key)
            if match:
                prefix = match.group(1)
                number = int(match.group(2))
                return prefix, number
        
        match = re.search(r'(\d+)', ticket_key)
        if match:
            return ticket_key.replace(match.group(1), '').replace('-', ''), int(match.group(1))
        
        return None, None
    
    def is_key_newer(self, key1, key2):
        """Compare two keys to determine if key1 is newer than key2"""
        if not key2:
            return True
        
        prefix1, num1 = self.extract_key_parts(key1)
        prefix2, num2 = self.extract_key_parts(key2)
        
        if prefix1 == prefix2 and num1 is not None and num2 is not None:
            return num1 > num2
        
        return key1 > key2
    
    def load_and_index_tickets_incremental(self, json_file_path: str, force_full_reindex: bool = False) -> Dict:
        """Load and index tickets from the new JSON format incrementally"""
        print("\n" + "="*60)
        print("STARTING INCREMENTAL INDEXING")
        print("="*60)
        
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                tickets = json.load(f)
            print(f"✅ Loaded {len(tickets)} tickets from {json_file_path}")
        except Exception as e:
            print(f"❌ Error loading JSON file: {e}")
            return {'status': 'error', 'message': str(e)}
        
        if force_full_reindex:
            print("⚠️ Force full reindex requested - clearing existing data")
            self.clear_collection()
        
        existing_keys = self.get_existing_keys_from_chromadb()
        tickets.sort(key=lambda x: x.get('key', ''))
        
        new_tickets = []
        skipped_duplicates = []
        failed_keys = []
        
        for ticket in tickets:
            key = ticket.get('key')
            if not key:
                continue
            
            if key in existing_keys:
                skipped_duplicates.append(key)
                continue
            
            if self.state.get('last_ticket_key'):
                if not self.is_key_newer(key, self.state['last_ticket_key']):
                    skipped_duplicates.append(key)
                    continue
            
            new_tickets.append(ticket)
        
        print(f"\n📊 Processing Summary:")
        print(f"   Total tickets in file: {len(tickets)}")
        print(f"   Already indexed: {len(skipped_duplicates)}")
        print(f"   New tickets to index: {len(new_tickets)}")
        
        if not new_tickets:
            print("✅ No new tickets to index")
            return {
                'status': 'success',
                'new_indexed': 0,
                'skipped_duplicates': len(skipped_duplicates),
                'total_in_db': self.collection.count()
            }
        
        indexed_count = 0
        batch_size = 50
        
        for i in range(0, len(new_tickets), batch_size):
            batch = new_tickets[i:i + batch_size]
            batch_ids = []
            batch_documents = []
            batch_embeddings = []
            batch_metadatas = []
            
            for ticket in batch:
                try:
                    doc_id = ticket.get('key')
                    if not doc_id:
                        continue
                    
                    searchable_text = ticket.get('searchable_text', '')
                    if not searchable_text:
                        searchable_text = f"{ticket.get('summary', '')} {ticket.get('description', '')}"
                    
                    embedding = self.model.encode([searchable_text])[0]
                    
                    comments_text = ""
                    if ticket.get('comments'):
                        comments_text = " ".join([c.get('body', '') for c in ticket['comments']])
                    
                    metadata = {
                        'key': ticket.get('key'),
                        'issue_id': ticket.get('issue_id'),
                        'type': ticket.get('type'),
                        'summary': ticket.get('summary', ''),
                        'description': ticket.get('description', '')[:1000],
                        'assignee': ticket.get('assignee', 'Unassigned'),
                        'reporter': ticket.get('reporter', ''),
                        'status': ticket.get('status', 'Unknown'),
                        'priority': ticket.get('priority', 'Unknown'),
                        'created': ticket.get('created', ''),
                        'updated': ticket.get('updated', ''),
                        'labels': json.dumps(ticket.get('labels', [])),
                        'components': json.dumps(ticket.get('components', [])),
                        'comments_count': len(ticket.get('comments', [])),
                        'url': ticket.get('metadata', {}).get('url', ''),
                        'last_indexed': ticket.get('metadata', {}).get('last_indexed', '')
                    }
                    
                    if ticket.get('created'):
                        try:
                            created_dt = datetime.fromisoformat(ticket['created'].replace('+0000', '+00:00'))
                            metadata['created_timestamp'] = created_dt.timestamp()
                        except:
                            metadata['created_timestamp'] = 0
                    
                    batch_ids.append(doc_id)
                    batch_documents.append(searchable_text)
                    batch_embeddings.append(embedding.tolist())
                    batch_metadatas.append(metadata)
                    
                except Exception as e:
                    print(f"⚠️ Error processing ticket {ticket.get('key', 'unknown')}: {e}")
                    failed_keys.append(ticket.get('key', 'unknown'))
                    continue
            
            if batch_ids:
                try:
                    self.collection.add(
                        ids=batch_ids,
                        documents=batch_documents,
                        embeddings=batch_embeddings,
                        metadatas=batch_metadatas
                    )
                    indexed_count += len(batch_ids)
                    print(f"   ✅ Indexed batch: {len(batch_ids)} tickets (Total: {indexed_count}/{len(new_tickets)})")
                    
                    if batch_ids:
                        last_key = batch_ids[-1]
                        self.state['last_ticket_key'] = last_key
                        prefix, num = self.extract_key_parts(last_key)
                        if num is not None:
                            self.state['last_ticket_numeric'] = num
                        if prefix:
                            self.state['key_pattern'] = prefix
                    
                except Exception as e:
                    print(f"❌ Error adding batch to ChromaDB: {e}")
                    failed_keys.extend(batch_ids)
        
        self.state['total_indexed'] = self.state.get('total_indexed', 0) + indexed_count
        self.state['last_indexed_timestamp'] = datetime.now().isoformat()
        if len(skipped_duplicates) > 0:
            self.state['skipped_duplicates'] = skipped_duplicates[-100:]
        self.save_indexing_state()
        
        print("\n" + "="*60)
        print("INDEXING COMPLETE")
        print("="*60)
        print(f"✅ Successfully indexed: {indexed_count} new tickets")
        print(f"📊 Total documents in ChromaDB: {self.collection.count()}")
        
        return {
            'status': 'success',
            'new_indexed': indexed_count,
            'skipped_duplicates': len(skipped_duplicates),
            'failed': len(failed_keys),
            'failed_keys': failed_keys,
            'total_in_db': self.collection.count(),
            'last_key': self.state.get('last_ticket_key')
        }
    
    def get_available_statuses(self) -> List[str]:
        """Get all unique statuses from the database"""
        try:
            if self.collection.count() == 0:
                return []
            
            results = self.collection.get()
            statuses = set()
            for metadata in results['metadatas']:
                if metadata.get('status'):
                    statuses.add(metadata['status'])
            
            return sorted(list(statuses))
        except Exception as e:
            print(f"Error getting statuses: {e}")
            return []
    
    def extract_keywords(self, text: str, top_n: int = 5) -> List[str]:
        """Extract key terms from text using simple frequency analysis"""
        # Simple stopwords list
        stopwords = {
            'the', 'is', 'at', 'which', 'on', 'a', 'an', 'as', 'are', 'was', 
            'were', 'been', 'be', 'have', 'has', 'had', 'do', 'does', 'did', 
            'will', 'would', 'should', 'may', 'might', 'must', 'can', 'could',
            'to', 'of', 'in', 'for', 'with', 'by', 'from', 'up', 'about', 'into',
            'through', 'during', 'before', 'after', 'above', 'below', 'between',
            'under', 'again', 'further', 'then', 'once', 'that', 'this', 'these',
            'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
            'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'and',
            'or', 'not', 'no', 'nor', 'but', 'if', 'then', 'else', 'when',
            'where', 'why', 'how', 'all', 'many', 'some', 'much', 'few', 'most',
            'other', 'such', 'only', 'own', 'same', 'so', 'than', 'too', 'very'
        }
        
        # Tokenize and filter
        words = re.findall(r'\b[a-z]+\b', text.lower())
        words = [w for w in words if len(w) > 2 and w not in stopwords]
        
        # Count frequencies
        word_freq = Counter(words)
        
        # Get top N words
        top_words = [word for word, _ in word_freq.most_common(top_n)]
        
        return top_words
    
    def keyword_search(self, query: str, top_k: int = 10, status_filter: List[str] = None) -> List[Dict]:
        """Perform keyword-based search"""
        try:
            query_lower = query.lower()
            query_words = set(query_lower.split())
            
            # Get all documents
            all_results = self.collection.get()
            
            if not all_results['ids']:
                return []
            
            keyword_matches = []
            
            for i, doc_id in enumerate(all_results['ids']):
                metadata = all_results['metadatas'][i]
                document = all_results['documents'][i] if 'documents' in all_results else ""
                
                # Apply status filter if provided
                if status_filter and metadata.get('status') not in status_filter:
                    continue
                
                # Calculate keyword match score
                text_to_search = f"{metadata.get('summary', '')} {metadata.get('description', '')} {document}".lower()
                text_words = set(text_to_search.split())
                
                matching_words = query_words.intersection(text_words)
                if matching_words:
                    match_score = len(matching_words) / len(query_words)
                    
                    keyword_matches.append({
                        'key': metadata.get('key'),
                        'metadata': metadata,
                        'keyword_matches': len(matching_words),
                        'match_score': match_score,
                        'matching_terms': list(matching_words)
                    })
            
            # Sort by match score
            keyword_matches.sort(key=lambda x: x['match_score'], reverse=True)
            
            return keyword_matches[:top_k]
            
        except Exception as e:
            print(f"Error in keyword search: {e}")
            return []
    
    def search_similar_tickets_advanced(self, 
                                       query: str, 
                                       top_k: int = 10,
                                       search_type: str = "semantic",
                                       status_filter: List[str] = None,
                                       date_weight: float = 0.3,
                                       similarity_weight: float = 0.7,
                                       max_days_back: int = 365) -> Dict:
        """Advanced search with multiple modes and scoring options"""
        
        results = {
            'query': query,
            'search_type': search_type,
            'results': [],
            'scoring_parameters': {
                'date_weight': date_weight,
                'similarity_weight': similarity_weight,
                'max_days_back': max_days_back
            }
        }
        
        if search_type == "semantic":
            # Semantic similarity search
            results['results'] = self._semantic_search(
                query, top_k, status_filter, date_weight, similarity_weight, max_days_back
            )
        
        elif search_type == "keyword":
            # Keyword matching search
            keyword_results = self.keyword_search(query, top_k, status_filter)
            
            # Format keyword results
            for kr in keyword_results:
                result = {
                    'issue_key': kr['key'],
                    'summary': kr['metadata'].get('summary', ''),
                    'description': kr['metadata'].get('description', ''),
                    'status': kr['metadata'].get('status', ''),
                    'priority': kr['metadata'].get('priority', ''),
                    'assignee': kr['metadata'].get('assignee', ''),
                    'keyword_matches': kr['keyword_matches'],
                    'match_score': f"{kr['match_score']:.2f}",
                    'key_terms': ', '.join(kr.get('matching_terms', []))
                }
                
                # Calculate days ago
                if kr['metadata'].get('created'):
                    try:
                        created_dt = datetime.fromisoformat(kr['metadata']['created'].replace('+0000', '+00:00'))
                        days_ago = (datetime.now() - created_dt).days
                        result['days_ago'] = days_ago
                    except:
                        result['days_ago'] = None
                
                results['results'].append(result)
        
        elif search_type == "hybrid":
            # Hybrid search - both semantic and keyword
            semantic_results = self._semantic_search(
                query, top_k, status_filter, date_weight, similarity_weight, max_days_back
            )
            
            keyword_results = self.keyword_search(query, top_k, status_filter)
            
            # Format keyword results for hybrid
            formatted_keyword_results = []
            for kr in keyword_results:
                result = {
                    'issue_key': kr['key'],
                    'summary': kr['metadata'].get('summary', ''),
                    'description': kr['metadata'].get('description', ''),
                    'status': kr['metadata'].get('status', ''),
                    'priority': kr['metadata'].get('priority', ''),
                    'assignee': kr['metadata'].get('assignee', ''),
                    'keyword_matches': kr['keyword_matches'],
                    'match_score': f"{kr['match_score']:.2f}",
                    'key_terms': ', '.join(kr.get('matching_terms', []))
                }
                
                if kr['metadata'].get('created'):
                    try:
                        created_dt = datetime.fromisoformat(kr['metadata']['created'].replace('+0000', '+00:00'))
                        days_ago = (datetime.now() - created_dt).days
                        result['days_ago'] = days_ago
                    except:
                        result['days_ago'] = None
                
                formatted_keyword_results.append(result)
            
            results['results'] = {
                'semantic': semantic_results,
                'keyword': formatted_keyword_results
            }
        
        return results
    
    def _semantic_search(self, query: str, top_k: int, status_filter: List[str],
                        date_weight: float, similarity_weight: float, max_days_back: int) -> List[Dict]:
        """Internal method for semantic search"""
        print(f"\n🔍 Performing semantic search for: '{query}'")
        
        # Generate embedding for the query
        query_embedding = self.model.encode([query])[0]
        
        # Build filter conditions
        where_conditions = {}
        if status_filter:
            where_conditions = {"$or": [{"status": s} for s in status_filter]}
        
        # Search in ChromaDB
        search_results = self.collection.query(
            query_embeddings=[query_embedding.tolist()],
            n_results=min(top_k * 3, 50),  # Get more results for filtering
            where=where_conditions if where_conditions else None
        )
        
        if not search_results['ids'][0]:
            print("   ❌ No results found")
            return []
        
        # Process and score results
        scored_results = []
        current_time = datetime.now()
        
        for i, doc_id in enumerate(search_results['ids'][0]):
            metadata = search_results['metadatas'][0][i]
            distance = search_results['distances'][0][i] if 'distances' in search_results else 0
            
            # Calculate similarity score (normalize distance to 0-1 range)
            raw_similarity = 1 / (1 + distance)
            
            # Calculate date score
            days_ago = None
            raw_date_score = 0.5  # Default if no date
            
            if metadata.get('created'):
                try:
                    created_dt = datetime.fromisoformat(metadata['created'].replace('+0000', '+00:00'))
                    days_ago = (current_time - created_dt).days
                    
                    # Skip if too old
                    if days_ago > max_days_back:
                        continue
                    
                    # Calculate date score (more recent = higher score)
                    raw_date_score = max(0, 1 - (days_ago / max_days_back))
                except:
                    pass
            
            # Calculate combined score
            combined_score = (raw_similarity * similarity_weight) + (raw_date_score * date_weight)
            
            # Extract key terms from the query and document
            doc_text = f"{metadata.get('summary', '')} {metadata.get('description', '')}"
            key_terms = self.extract_keywords(doc_text, top_n=5)
            
            scored_results.append({
                'issue_key': metadata.get('key'),
                'summary': metadata.get('summary', ''),
                'description': metadata.get('description', ''),
                'status': metadata.get('status', ''),
                'priority': metadata.get('priority', ''),
                'assignee': metadata.get('assignee', ''),
                'created': metadata.get('created', ''),
                'days_ago': days_ago,
                'similarity_score': f"{raw_similarity:.3f}",
                'date_score': f"{raw_date_score:.3f}",
                'combined_score': f"{combined_score:.3f}",
                'key_terms': ', '.join(key_terms),
                'scoring_info': {
                    'raw_similarity': f"{raw_similarity:.3f}",
                    'raw_date_score': f"{raw_date_score:.3f}",
                    'similarity_weight': similarity_weight,
                    'date_weight': date_weight
                }
            })
        
        # Sort by combined score
        scored_results.sort(key=lambda x: float(x['combined_score']), reverse=True)
        
        return scored_results[:top_k]
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics about the indexed data"""
        try:
            total_count = self.collection.count()
            
            if total_count == 0:
                return {
                    'total_tickets': 0,
                    'status_counts': {},
                    'priority_counts': {},
                    'type_counts': {},
                    'vector_dimensions': [0, 0],
                    'date_range': {'oldest': None, 'newest': None}
                }
            
            # Get sample of documents for statistics
            sample_size = min(1000, total_count)
            results = self.collection.get(limit=sample_size)
            
            # Count statistics
            status_counts = Counter()
            priority_counts = Counter()
            type_counts = Counter()
            dates = []
            
            for metadata in results['metadatas']:
                if metadata.get('status'):
                    status_counts[metadata['status']] += 1
                if metadata.get('priority'):
                    priority_counts[metadata['priority']] += 1
                if metadata.get('type'):
                    type_counts[metadata['type']] += 1
                if metadata.get('created'):
                    dates.append(metadata['created'])
            
            # Get vector dimensions
            if results.get('embeddings') and len(results['embeddings']) > 0:
                vector_dims = [len(results['embeddings']), len(results['embeddings'][0])]
            else:
                vector_dims = [total_count, self.model.get_sentence_embedding_dimension()]
            
            # Get date range
            date_range = {'oldest': None, 'newest': None}
            if dates:
                sorted_dates = sorted(dates)
                date_range = {
                    'oldest': sorted_dates[0],
                    'newest': sorted_dates[-1]
                }
            
            return {
                'total_tickets': total_count,
                'status_counts': dict(status_counts.most_common()),
                'priority_counts': dict(priority_counts.most_common()),
                'type_counts': dict(type_counts.most_common()),
                'vector_dimensions': vector_dims,
                'date_range': date_range,
                'sample_size': sample_size,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {
                'error': str(e),
                'total_tickets': 0,
                'status_counts': {},
                'vector_dimensions': [0, 0]
            }


# Initialize RAG engine (global variable)
rag_engine = None

def initialize_rag_engine():
    """Initialize the Enhanced Jira RAG engine on startup"""
    global rag_engine
    try:
        print("Initializing Enhanced Similarity Search Engine...")
        rag_engine = EnhancedJiraRAG()
        
        # Check if we need to index
        stats = rag_engine.get_statistics()
        if stats['total_tickets'] == 0:
            print("\nNo tickets found in database. Indexing from JSON file...")
            json_path = os.path.join('data', 'raw', 'jira_tickets.json')
            if os.path.exists(json_path):
                result = rag_engine.load_and_index_tickets_incremental(
                    json_path,
                    force_full_reindex=False
                )
                print(f"Indexing result: {result}")
            else:
                print(f"⚠️ JSON file not found at {json_path}")
        else:
            print(f"\n✅ Database already contains {stats['total_tickets']} tickets")
            if stats.get('status_counts'):
                print(f"   Status distribution: {list(stats['status_counts'].keys())[:5]}")
        
        print("✅ Enhanced Similarity Search Engine initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing Enhanced Similarity Search Engine: {e}")
        raise

# Initialize the RAG engine when the blueprint is imported
initialize_rag_engine()


# Blueprint Routes
@similarity_bp.route('/')
def similarity_home():
    """Main page with search interface"""
    return render_template('similarity_search.html')


@similarity_bp.route('/search', methods=['POST'])
def search_similar_tickets():
    """API endpoint for similar ticket search"""
    try:
        data = request.get_json()
        
        # Extract parameters
        query = data.get('query', '').strip()
        top_k = int(data.get('top_k', 10))
        search_type = data.get('search_type', 'semantic')
        status_filter = data.get('status_filter', [])
        date_weight = float(data.get('date_weight', 0.7))
        similarity_weight = float(data.get('similarity_weight', 0.3))
        max_days_back = int(data.get('max_days_back', 365))
        
        if not query:
            return jsonify({'error': 'Please provide a search query'}), 400
        
        if not rag_engine:
            return jsonify({'error': 'Search engine not initialized'}), 500
        
        if status_filter and not isinstance(status_filter, list):
            return jsonify({'error': 'status_filter must be a list'}), 400
        
        # Normalize weights
        if abs(similarity_weight + date_weight - 1.0) > 0.001:
            total_weight = similarity_weight + date_weight
            if total_weight > 0:
                similarity_weight = similarity_weight / total_weight
                date_weight = date_weight / total_weight
            else:
                similarity_weight, date_weight = 0.3, 0.7
        
        # Perform search
        results = rag_engine.search_similar_tickets_advanced(
            query=query,
            top_k=top_k,
            search_type=search_type,
            status_filter=status_filter if status_filter else None,
            date_weight=date_weight,
            similarity_weight=similarity_weight,
            max_days_back=max_days_back
        )
        
        return jsonify({
            'success': True,
            **results,
            'total_results': len(results['results']) if isinstance(results['results'], list) else 
                           len(results['results'].get('semantic', [])) + len(results['results'].get('keyword', [])),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@similarity_bp.route('/statuses', methods=['GET'])
def get_available_statuses():
    """Get available statuses for filtering"""
    if not rag_engine:
        return jsonify({'error': 'Search engine not initialized'}), 500
    
    try:
        statuses = rag_engine.get_available_statuses()
        return jsonify({
            'success': True,
            'statuses': statuses,
            'total_count': len(statuses),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@similarity_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    if not rag_engine:
        return jsonify({'error': 'Search engine not initialized'}), 500
    
    try:
        stats = rag_engine.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@similarity_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'engine_status': 'initialized' if rag_engine else 'not_initialized',
        'timestamp': datetime.now().isoformat()
    })


@similarity_bp.route('/index', methods=['POST'])
def index_tickets():
    """Trigger indexing of tickets"""
    if not rag_engine:
        return jsonify({'error': 'Search engine not initialized'}), 500
    
    try:
        data = request.get_json() if request.is_json else {}
        json_file = data.get('file_path', os.path.join('data', 'raw', 'jira_tickets.json'))
        force_reindex = data.get('force_reindex', False)
        
        result = rag_engine.load_and_index_tickets_incremental(
            json_file,
            force_full_reindex=force_reindex
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500