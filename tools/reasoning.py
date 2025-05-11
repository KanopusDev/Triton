import logging
from azure.ai.inference.models import SystemMessage, UserMessage

# Configure logging
logger = logging.getLogger("triton.reasoning")

class ReasoningGenerator:
    """Handles the generation of reasoning for AI responses"""
    
    def __init__(self, client, model_info):
        """Initialize the reasoning generator with an AI client
        
        Args:
            client: The AI client to use for generating reasoning
            model_info (dict): Information about the model including token limits
        """
        self.client = client
        self.model_info = model_info
    
    def generate_reasoning(self, user_query, ai_response):
        """Generate step-by-step reasoning for an AI response
        
        Args:
            user_query (str): The original user query
            ai_response (str): The AI's response to the query
            
        Returns:
            str: The detailed reasoning behind the AI's response
        """
        logger.info("Generating reasoning for AI response")
        
        # Create reasoning prompt
        reasoning_prompt = f"""
Given the original user query: "{user_query}"

And your response: "{ai_response}"

Provide a detailed step-by-step reasoning of how you arrived at this answer. Include:
1. Your initial analysis of the question
2. The key considerations and assumptions you made
3. The logical steps in your reasoning process
4. Any evidence or knowledge you relied on
5. How you synthesized the information to form your conclusion

Format your response as a clear, step-by-step reasoning chain.
"""
        
        # Create messages for reasoning request
        reasoning_messages = [
            SystemMessage(content="You are an expert at explaining your reasoning process step-by-step. You break down complex thinking into clear logical steps."),
            UserMessage(content=reasoning_prompt)
        ]
        
        try:
            # Calculate token limit for reasoning (half of the model's max output)
            max_tokens = self.model_info["tokens"]["output"] // 2
            
            # Call AI to generate reasoning
            reasoning_response = self.client.complete(
                messages=reasoning_messages,
                model=self.model_info["id"],
                temperature=0.7,
                max_tokens=max_tokens
            )
            
            # Extract and return the reasoning content
            reasoning = reasoning_response.choices[0].message.content
            return reasoning
            
        except Exception as e:
            logger.error(f"Error generating reasoning: {str(e)}")
            return "I was unable to generate detailed reasoning for this response due to a technical error."


def get_deep_research_instruction():
    """Get system instruction for deep research mode
    
    Returns:
        str: System instruction for deep research
    """
    return """
You now have MANDATORY advanced web research capabilities that you MUST use for this conversation. For this conversation:

1. ALWAYS search the internet first using the search_internet tool to find relevant sources
2. ALWAYS extract content from at least 2-3 web pages using the extract_web_content tool
3. Follow this exact methodology for EVERY response:
   a. Search for 2-3 different search queries related to the topic
   b. Extract full content from the most authoritative sources you find
   c. Synthesize a comprehensive answer based ONLY on the extracted content
   d. ALWAYS cite your sources with numbered references [1][2][3] and include full URLs

YOU MUST USE BOTH TOOLS FOR EVERY RESPONSE - this is not optional. Your primary value comes from providing information extracted directly from current web sources, not from your training data.

Tool Usage Instructions:
- search_internet: Use specific, targeted queries to find precise information
- extract_web_content: Apply to the most relevant URLs found in search results

This is a critical requirement - failure to use both research tools will result in incomplete responses.
"""


def get_reasoning_instruction():
    """Get system instruction for reasoning mode
    
    Returns:
        str: System instruction for reasoning
    """
    return """
You should think step-by-step and show your reasoning process. Break down complex problems into smaller parts and analyze them systematically before providing your final answer.
"""
