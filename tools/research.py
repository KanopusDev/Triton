import json
import logging
import requests
import traceback
import time
import re
import html
from bs4 import BeautifulSoup, Comment
from urllib.parse import urlparse
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential
from azure.ai.inference.models import ChatCompletionsToolDefinition, FunctionDefinition
from typing import List, Dict, Any, Optional, Union
import asyncio
import aiohttp

# Import from search module
from tools.search import call_search_function, QueryOptimizer

# Configure logging
logger = logging.getLogger("triton.research")

class WebTools:
    """Provider for web content extraction tools"""
    
    @staticmethod
    def get_web_extraction_tool_definition():
        """Get the web extraction tool definition for AI models"""
        return ChatCompletionsToolDefinition(
            function=FunctionDefinition(
                name="extract_web_content",
                description="REQUIRED: Extract and analyze detailed content from a specific webpage. You MUST use this to get in-depth information after finding relevant URLs via search.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The full URL of the web page to extract content from",
                        },
                        "element_selector": {
                            "type": "string",
                            "description": "Optional CSS selector to target specific elements (e.g., 'article', '.content', '#main')",
                        }
                    },
                    "required": ["url"],
                },
            )
        )


class ResearchManager:
    """Coordinates search and content extraction for comprehensive research"""
    
    def __init__(self):
        """Initialize the research manager"""
        # Track rate limits across instances
        self.rate_limit_tracker = {}
    
    async def research_topic(self, topic: str, max_sources: int = 3) -> Dict[str, Any]:
        """
        Perform comprehensive research on a topic
        
        Args:
            topic (str): The research topic or question
            max_sources (int): Maximum number of sources to extract content from
            
        Returns:
            Dict: Research results with search results and extracted content
        """
        try:
            # Analyze the query to understand the topic better
            query_analysis = QueryOptimizer.analyze_query(topic)
            search_queries = QueryOptimizer.generate_search_queries(query_analysis)
            
            # Perform search with the generated queries
            search_args = {"query": search_queries[0], "engine": "google"}
            search_results_json = call_search_function(search_args)
            search_results = json.loads(search_results_json)
            
            # Filter out error results
            valid_results = [r for r in search_results if "error" not in r]
            
            if not valid_results:
                return {
                    "topic": topic,
                    "success": False,
                    "error": "No valid search results found",
                    "search_results": [],
                    "extracted_content": []
                }
            
            # Extract content from the top results (asynchronously)
            urls_to_extract = [r["link"] for r in valid_results[:max_sources] if "link" in r]
            extracted_contents = await self._extract_multiple_contents(urls_to_extract)
            
            return {
                "topic": topic,
                "success": True,
                "search_results": valid_results,
                "extracted_content": extracted_contents
            }
            
        except Exception as e:
            logger.error(f"Research error for topic '{topic}': {str(e)}\n{traceback.format_exc()}")
            return {
                "topic": topic,
                "success": False,
                "error": str(e),
                "search_results": [],
                "extracted_content": []
            }
    
    async def _extract_multiple_contents(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Extract content from multiple URLs asynchronously
        
        Args:
            urls (List[str]): List of URLs to extract content from
            
        Returns:
            List[Dict]: List of extracted content results
        """
        tasks = []
        for url in urls:
            tasks.append(self._extract_content_safe(url))
        
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
    
    async def _extract_content_safe(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Safely extract content from a URL with error handling
        
        Args:
            url (str): URL to extract content from
            
        Returns:
            Optional[Dict]: Extracted content or None if extraction failed
        """
        try:
            # Call the extract_web_content function with proper arguments
            args = {"url": url}
            result_json = extract_web_content(args)
            result = json.loads(result_json)
            
            # Check if there was an error
            if "error" in result:
                logger.warning(f"Error extracting content from {url}: {result['error']}")
                return None
                
            return result
        except Exception as e:
            logger.error(f"Error extracting content from {url}: {str(e)}")
            return None


@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=3))
def extract_web_content(args):
    """Extract content from a web page URL with security and rate limiting
    
    Args:
        args (dict): Arguments containing URL and optional selector
            - url (str): The webpage URL to extract content from
            - element_selector (str, optional): CSS selector to target specific elements
    
    Returns:
        str: JSON string of extracted content
    """
    url = args.get("url", "")
    element_selector = args.get("element_selector", "")
    
    if not url:
        return json.dumps({"error": "No URL provided"})
    
    # Security check - validate URL
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return json.dumps({"error": "Invalid URL format"})
        
        # Block potentially dangerous protocols
        if parsed_url.scheme not in ['http', 'https']:
            return json.dumps({"error": "Only HTTP and HTTPS protocols are supported"})
        
        # Block access to local or private networks
        if parsed_url.netloc in ['localhost', '127.0.0.1'] or parsed_url.netloc.startswith('192.168.') or parsed_url.netloc.startswith('10.'):
            return json.dumps({"error": "Access to local networks is not allowed"})
    except Exception as e:
        return json.dumps({"error": f"URL validation error: {str(e)}"})
    
    # Track website access to implement rate limiting
    website_domain = parsed_url.netloc
    
    # Use global dictionary to track rate limiting (normally would use Redis in production)
    if not hasattr(extract_web_content, 'rate_limit_tracker'):
        extract_web_content.rate_limit_tracker = {}
    
    current_time = time.time()
    
    # Basic rate limiting: max 3 requests per domain per minute
    if website_domain in extract_web_content.rate_limit_tracker:
        last_access_times = extract_web_content.rate_limit_tracker[website_domain]
        # Remove timestamps older than 60 seconds
        last_access_times = [t for t in last_access_times if current_time - t < 60]
        
        if len(last_access_times) >= 3:
            return json.dumps({
                "error": f"Rate limit exceeded for {website_domain}. Try again later or use a different source."
            })
        
        extract_web_content.rate_limit_tracker[website_domain] = last_access_times + [current_time]
    else:
        extract_web_content.rate_limit_tracker[website_domain] = [current_time]
    
    # Fetch and parse the web page
    try:
        logger.info(f"Extracting content from URL: {url}")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.google.com/",
            "Connection": "keep-alive"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise exception for 4XX/5XX responses
        
        # Check if content is HTML
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type and 'application/xhtml+xml' not in content_type:
            return json.dumps({
                "url": url,
                "content_type": content_type,
                "error": "Non-HTML content type. Cannot extract web content.",
                "raw_text": response.text[:1000] if len(response.text) > 1000 else response.text  # Limit raw text
            })
        
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script, style elements and comments
        for element in soup(['script', 'style', 'iframe', 'noscript']):
            element.decompose()
            
        # Remove comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
        
        # Get page title
        title = soup.title.string if soup.title else "No title"
        
        # Extract main content
        if element_selector:
            # Extract content from specific selector if provided
            content_elements = soup.select(element_selector)
            if not content_elements:
                # If selector doesn't match anything, fall back to body
                main_content = soup.get_text(separator='\n', strip=True)
            else:
                main_content = '\n'.join([elem.get_text(separator='\n', strip=True) for elem in content_elements])
        else:
            # Try to intelligently extract main content
            # First check for main article elements
            main_content_elem = soup.find('article') or soup.find(id=re.compile('^(main|content|article)')) or \
                                soup.find(class_=re.compile('^(main|content|article)')) or \
                                soup.find('main') or soup.body
            
            if main_content_elem:
                main_content = main_content_elem.get_text(separator='\n', strip=True)
            else:
                main_content = soup.get_text(separator='\n', strip=True)
        
        # Clean up content - remove excessive whitespace and normalize
        main_content = re.sub(r'\n\s*\n', '\n\n', main_content)
        main_content = re.sub(r'[ \t]+', ' ', main_content)
        
        # Limit content length to prevent token issues (about 10k chars)
        if len(main_content) > 10000:
            main_content = main_content[:10000] + "...[content truncated]"
        
        # Extract meta description if available
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        description = meta_desc['content'] if meta_desc and 'content' in meta_desc.attrs else ""
        
        # Extract publication date if available
        pub_date = None
        date_meta = soup.find('meta', attrs={'property': 'article:published_time'})
        if date_meta and 'content' in date_meta.attrs:
            pub_date = date_meta['content']
        
        # Check if content is meaningful
        if len(main_content.strip()) < 50:
            return json.dumps({
                "url": url,
                "title": title,
                "error": "Extracted content too short or empty. The page may use JavaScript to load content or might be protected."
            })
        
        # Analyze content for overall quality
        content_quality = {
            "length": len(main_content),
            "has_paragraphs": main_content.count('\n\n') > 2,
            "average_sentence_length": len(main_content) / (main_content.count('.') + 1)
        }
        
        # Return the extracted data with enhanced metadata
        return json.dumps({
            "url": url,
            "title": html.unescape(title),
            "description": html.unescape(description),
            "content": html.unescape(main_content),
            "content_type": content_type,
            "extraction_time": datetime.utcnow().isoformat(),
            "publication_date": pub_date,
            "domain": parsed_url.netloc,
            "content_quality": content_quality
        })
        
    except requests.exceptions.RequestException as e:
        error_message = str(e)
        logger.error(f"Web extraction error for {url}: {error_message}")
        
        if hasattr(e, 'response') and e.response is not None:
            status_code = e.response.status_code
            return json.dumps({
                "url": url,
                "error": f"Failed to fetch URL (HTTP {status_code}): {error_message}"
            })
        else:
            return json.dumps({
                "url": url,
                "error": f"Failed to fetch URL: {error_message}"
            })
    
    except Exception as e:
        logger.error(f"Web extraction error for {url}: {str(e)}\n{traceback.format_exc()}")
        return json.dumps({
            "url": url,
            "error": f"Error extracting content: {str(e)}"
        })
