import json
import logging
import requests
import traceback
import re
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from tenacity import retry, stop_after_attempt, wait_exponential
from azure.ai.inference.models import ChatCompletionsToolDefinition, FunctionDefinition, SystemMessage, UserMessage
import os
from typing import List, Dict, Any, Optional, Union

# Configure logging
logger = logging.getLogger("triton.search")

class SearchTools:
    """Provider for search-related AI tools"""
    
    @staticmethod
    def get_search_tool_definition():
        """Get the search tool definition for AI models"""
        return ChatCompletionsToolDefinition(
            function=FunctionDefinition(
                name="search_internet",
                description="REQUIRED: Search the internet for current, factual information on a topic. You MUST use this for any factual claims or recent information.",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The specific search query string to find precise information",
                        },
                        "engine": {
                            "type": "string",
                            "enum": ["google", "duckduckgo"],
                            "description": "The search engine to use",
                        },
                    },
                    "required": ["query"],
                },
            )
        )


class QueryOptimizer:
    """Handles query analysis and optimization for more effective searching"""
    
    @staticmethod
    def analyze_query(query: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a search query to extract key concepts and intent
        
        Args:
            query (str): The original search query
            context (str, optional): Additional context to consider
            
        Returns:
            Dict: Analysis results containing key terms, entities, etc.
        """
        # Remove common filler words and normalize
        normalized_query = query.lower()
        filler_words = ['the', 'a', 'an', 'and', 'or', 'but', 'is', 'are', 'was', 'were', 
                       'in', 'on', 'at', 'to', 'for', 'with', 'about', 'like', 'by']
        
        # Extract potential key terms (capitalize proper nouns, technical terms)
        key_terms = []
        potential_entities = re.findall(r'\b[A-Z][a-z]+\b', query)
        technical_terms = re.findall(r'\b[a-z]+[A-Z][a-z]+\b', query)  # camelCase terms
        quoted_terms = re.findall(r'"([^"]*)"', query)  # Terms in quotes
        
        key_terms.extend(potential_entities)
        key_terms.extend(technical_terms)
        key_terms.extend(quoted_terms)
        
        # Extract year references which are often important for temporal queries
        years = re.findall(r'\b(19|20)\d{2}\b', query)
        
        # Look for question words to determine query type
        question_words = ['what', 'when', 'where', 'who', 'why', 'how']
        query_type = next((word for word in question_words if normalized_query.startswith(word)), 'statement')
        
        return {
            "original_query": query,
            "normalized_query": normalized_query,
            "key_terms": key_terms,
            "years": years,
            "query_type": query_type,
            "contains_technical_terms": len(technical_terms) > 0,
        }
    
    @staticmethod
    def generate_search_queries(query_analysis: Dict[str, Any], max_queries: int = 3) -> List[str]:
        """
        Generate optimized search queries based on query analysis
        
        Args:
            query_analysis (Dict): Output from analyze_query
            max_queries (int): Maximum number of queries to generate
            
        Returns:
            List[str]: List of optimized search queries
        """
        queries = []
        original = query_analysis["original_query"]
        
        # Always include the original query
        queries.append(original)
        
        # If we have key terms, create a more focused query
        if query_analysis["key_terms"]:
            key_term_query = " ".join(query_analysis["key_terms"])
            if key_term_query != original and len(key_term_query) > 5:
                # Add quotes around multi-word terms for exact matching
                if len(query_analysis["key_terms"]) > 1:
                    key_term_query = f'"{key_term_query}"'
                queries.append(key_term_query)
        
        # For factual questions, rephrase to a more direct form
        if query_analysis["query_type"] in ["what", "when", "where", "who"]:
            # Remove the question word and question mark for more direct searching
            direct_query = re.sub(r'^(what|when|where|who)\s+(is|are|was|were)\s+', '', 
                                 query_analysis["normalized_query"])
            direct_query = direct_query.rstrip('?').strip()
            
            # Add back any key terms that might have been removed
            for term in query_analysis["key_terms"]:
                if term.lower() not in direct_query.lower():
                    direct_query += f" {term}"
            
            # Only add if it's substantially different from the original
            if direct_query != original.lower() and len(direct_query) > len(original) * 0.6:
                queries.append(direct_query)
        
        # For technical queries, add 'how to' version if not already a how-to
        if query_analysis["contains_technical_terms"] and not original.lower().startswith('how to'):
            # Extract the main technical terms
            tech_query = " ".join([term for term in query_analysis["key_terms"] 
                                 if re.search(r'[a-z]+[A-Z][a-z]+', term)])
            if tech_query:
                how_to_query = f"how to {tech_query}"
                queries.append(how_to_query)
        
        # If years were mentioned, create a time-specific query
        if query_analysis["years"]:
            year = query_analysis["years"][0]  # Take the first year mentioned
            year_query = f"{' '.join(query_analysis['key_terms'])} {year}"
            queries.append(year_query)
        
        # Return unique queries, limited to max_queries
        unique_queries = []
        for q in queries:
            if q not in unique_queries and len(q) > 3:
                unique_queries.append(q)
                if len(unique_queries) >= max_queries:
                    break
        
        return unique_queries


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def call_search_function(args):
    """Execute a web search and return results
    
    Args:
        args (dict): Arguments containing query and engine
            - query (str): The search query
            - engine (str, optional): Search engine to use ("google" or "duckduckgo")
    
    Returns:
        str: JSON string of search results
    """
    query = args.get("query", "")
    engine = args.get("engine", "google")
    
    if not query:
        return json.dumps([])
    
    try:
        logger.info(f"Analyzing search query: {query}")
        
        # Analyze and optimize the query
        query_analysis = QueryOptimizer.analyze_query(query)
        search_queries = QueryOptimizer.generate_search_queries(query_analysis)
        
        logger.info(f"Generated search queries: {search_queries}")
        
        # Use the first query by default (fallback to original)
        primary_query = search_queries[0]
        
        # Perform search with the primary query
        logger.info(f"Performing {engine} search for primary query: {primary_query}")
        
        # Choose search API based on engine
        if engine.lower() == "duckduckgo":
            primary_results = json.loads(perform_duckduckgo_search(primary_query))
        else:
            # Default to Google
            primary_results = json.loads(perform_google_search(primary_query))
        
        all_results = primary_results
        
        # If primary query didn't yield enough results, try alternative queries
        if len(primary_results) < 3 and len(search_queries) > 1:
            for alt_query in search_queries[1:]:
                logger.info(f"Trying alternative query: {alt_query}")
                
                if engine.lower() == "duckduckgo":
                    alt_results = json.loads(perform_duckduckgo_search(alt_query))
                else:
                    alt_results = json.loads(perform_google_search(alt_query))
                
                # Add unique results that weren't in the primary results
                primary_urls = [r.get("link", "") for r in primary_results]
                for result in alt_results:
                    if result.get("link") not in primary_urls:
                        all_results.append(result)
                
                # If we now have enough results, stop trying more queries
                if len(all_results) >= 5:
                    break
        
        # Add the query that produced each result
        for i, result in enumerate(all_results):
            # For primary results, use primary query
            if i < len(primary_results):
                result["query_used"] = primary_query
            # For additional results, find which query produced it
            else:
                for alt_query in search_queries[1:]:
                    if engine.lower() == "duckduckgo":
                        alt_results = json.loads(perform_duckduckgo_search(alt_query))
                    else:
                        alt_results = json.loads(perform_google_search(alt_query))
                    
                    for alt_result in alt_results:
                        if alt_result.get("link") == result.get("link"):
                            result["query_used"] = alt_query
                            break
        
        logger.info(f"Search complete. Found {len(all_results)} results.")
        return json.dumps(all_results)
        
    except Exception as e:
        logger.error(f"Search error: {str(e)}\n{traceback.format_exc()}")
        return json.dumps([{"error": str(e)}])


def perform_google_search(query):
    """Perform a Google search and return results
    
    Args:
        query (str): The search query string
        
    Returns:
        str: JSON string of search results
    """
    # This is a simplified version - in production, use Google Custom Search API
    google_api_key = os.getenv("GOOGLE_API_KEY")
    search_engine_id = os.getenv("GOOGLE_SEARCH_ENGINE_ID")
    
    # If no API key is available, return a mock response
    if not google_api_key or not search_engine_id:
        logger.warning("Google search API keys not configured, returning mock results")
        return json.dumps([
            {
                "title": "Mock Search Result for: " + query,
                "link": "https://example.com/result1",
                "snippet": "This is a mock search result. Configure Google API keys for real results."
            }
        ])
        
    # In a real implementation, you would call the Google Custom Search API
    url = f"https://www.googleapis.com/customsearch/v1"
    params = {
        "key": google_api_key,
        "cx": search_engine_id,
        "q": query,
        "num": 5
    }
    
    response = requests.get(url, params=params)
    data = response.json()
    
    results = []
    if "items" in data:
        for item in data["items"]:
            results.append({
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", "")
            })
    
    return json.dumps(results)


def perform_duckduckgo_search(query):
    """Perform a DuckDuckGo search and return results
    
    Args:
        query (str): The search query string
        
    Returns:
        str: JSON string of search results
    """
    # This uses the DuckDuckGo HTML response since they don't have an official API
    # In production, consider using a proper search API
    
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")
        
        results = []
        for result in soup.select(".result"):
            title_elem = result.select_one(".result__a")
            snippet_elem = result.select_one(".result__snippet")
            
            if title_elem and snippet_elem:
                title = title_elem.get_text(strip=True)
                link = title_elem.get("href", "")
                if link.startswith("/"):
                    # Extract actual URL from DuckDuckGo redirect URL
                    link_parts = link.split("uddg=")
                    if len(link_parts) > 1:
                        link = link_parts[1].split("&")[0]
                        link = requests.utils.unquote(link)
                
                snippet = snippet_elem.get_text(strip=True)
                
                results.append({
                    "title": title,
                    "link": link,
                    "snippet": snippet
                })
                
                # Limit to 5 results
                if len(results) >= 5:
                    break
        
        return json.dumps(results)
    
    except Exception as e:
        logger.error(f"DuckDuckGo search error: {str(e)}")
        return json.dumps([{"error": str(e)}])
