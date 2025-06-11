"""
OpenAI Service Integration

This module provides integration with the OpenAI API for AI-powered
finding analysis, validation, and confidence scoring.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

from .config import AIServiceConfig
from .monitoring import AIServiceMonitor
from .service import (
    AIService,
    AIServiceError,
    AIServiceConfigError,
    AIServiceConnectionError,
    AIServiceRateLimitError,
    AnalysisResult,
    ValidationResult,
    ConfidenceScore,
    ConfidenceLevel
)


class OpenAIService(AIService):
    """OpenAI API service implementation."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the OpenAI service.
        
        Args:
            config: Service configuration dictionary
        """
        super().__init__(config)
        self.config = AIServiceConfig.from_dict(config)
        self.config.validate()
        self.monitor = AIServiceMonitor(config)
        self.session = None
        self._setup_prompts()
    
    def _validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and process service configuration.
        
        Args:
            config: Raw configuration dictionary
            
        Returns:
            Processed configuration dictionary
            
        Raises:
            AIServiceConfigError: If configuration is invalid
        """
        try:
            ai_config = AIServiceConfig.from_dict(config)
            ai_config.validate()
            return config
        except Exception as e:
            raise AIServiceConfigError(f"Invalid configuration: {str(e)}")
    
    def _initialize_service(self) -> None:
        """Initialize the OpenAI service connection.
        
        Raises:
            AIServiceConnectionError: If service initialization fails
        """
        try:
            self.session = aiohttp.ClientSession(
                base_url=self.config.api_base,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                    "OpenAI-Organization": self.config.get("organization_id", ""),
                },
                timeout=aiohttp.ClientTimeout(
                    total=self.config.request_timeout,
                    connect=self.config.connection_timeout
                )
            )
            asyncio.create_task(self.monitor.start())
        except Exception as e:
            raise AIServiceConnectionError(f"Failed to initialize OpenAI service: {str(e)}")
    
    def _setup_prompts(self) -> None:
        """Set up analysis prompts."""
        self.prompts = {
            "analyze": """Analyze the following security finding and provide a detailed assessment:

Finding ID: {finding_id}
Title: {title}
Description: {description}
Severity: {severity}
Category: {category}
Location: {location}
Evidence: {evidence}

Please provide:
1. A confidence score (0-1) for the finding's validity
2. A brief analysis summary
3. The probability of this being a false positive (0-1)
4. Suggested remediation steps
5. Impact assessment
6. Key factors affecting the confidence score

Respond in JSON format with the following structure:
{{
    "confidence_score": float,
    "analysis_summary": str,
    "false_positive_probability": float,
    "remediation_suggestions": List[str],
    "impact_assessment": str,
    "confidence_factors": List[str]
}}""",

            "validate": """Validate the following security finding:

Finding ID: {finding_id}
Title: {title}
Description: {description}
Severity: {severity}
Category: {category}
Location: {location}
Evidence: {evidence}

Please determine if this finding is valid and provide:
1. A boolean indicating if the finding is valid
2. A detailed explanation of the validation decision
3. A confidence score (0-1) for the validation
4. Key factors affecting the validation

Respond in JSON format with the following structure:
{{
    "is_valid": bool,
    "validation_reason": str,
    "confidence_score": float,
    "validation_factors": List[str]
}}""",

            "score": """Score the confidence of the following security finding:

Finding ID: {finding_id}
Title: {title}
Description: {description}
Severity: {severity}
Category: {category}
Location: {location}
Evidence: {evidence}

Please provide:
1. A confidence score (0-1)
2. A list of factors affecting the confidence score
3. Key observations that influenced the score

Respond in JSON format with the following structure:
{{
    "score": float,
    "factors": List[str],
    "observations": List[str]
}}"""
        }
    
    def _get_confidence_level(self, score: float) -> ConfidenceLevel:
        """Convert a confidence score to a confidence level.
        
        Args:
            score: Confidence score between 0 and 1
            
        Returns:
            Corresponding confidence level
        """
        if score >= 0.8:
            return ConfidenceLevel.VERY_HIGH
        elif score >= 0.6:
            return ConfidenceLevel.HIGH
        elif score >= 0.4:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.2:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    @retry(
        retry=retry_if_exception_type((AIServiceConnectionError, AIServiceRateLimitError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def _make_request(self, 
                          endpoint: str, 
                          data: Dict[str, Any]) -> Dict[str, Any]:
        """Make a request to the OpenAI API.
        
        Args:
            endpoint: API endpoint
            data: Request data
            
        Returns:
            API response data
            
        Raises:
            AIServiceError: If the request fails
            AIServiceRateLimitError: If rate limit is exceeded
        """
        start_time = time.time()
        success = False
        rate_limited = False
        
        try:
            async with self.session.post(endpoint, json=data) as response:
                if response.status == 429:
                    rate_limited = True
                    raise AIServiceRateLimitError("OpenAI API rate limit exceeded")
                
                response.raise_for_status()
                result = await response.json()
                success = True
                
                # Record metrics
                latency = time.time() - start_time
                tokens = result.get("usage", {}).get("total_tokens", 0)
                prompt_tokens = result.get("usage", {}).get("prompt_tokens", 0)
                completion_tokens = result.get("usage", {}).get("completion_tokens", 0)
                
                self.monitor.record_request(
                    success=True,
                    tokens=tokens,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    latency=latency
                )
                
                return result
                
        except aiohttp.ClientError as e:
            self.monitor.record_request(
                success=False,
                rate_limited=rate_limited,
                latency=time.time() - start_time
            )
            raise AIServiceConnectionError(f"OpenAI API request failed: {str(e)}")
        
        except Exception as e:
            self.monitor.record_request(
                success=False,
                rate_limited=rate_limited,
                latency=time.time() - start_time
            )
            raise AIServiceError(f"Unexpected error in OpenAI API request: {str(e)}")
    
    async def analyze_finding(self, finding: Dict[str, Any]) -> AnalysisResult:
        """Analyze a security finding using OpenAI.
        
        Args:
            finding: Finding data to analyze
            
        Returns:
            Analysis result with confidence score and details
            
        Raises:
            AIServiceError: If analysis fails
            AIServiceRateLimitError: If rate limit is exceeded
        """
        try:
            # Prepare the prompt
            prompt = self.prompts["analyze"].format(**finding)
            
            # Make the API request
            response = await self._make_request(
                "/v1/chat/completions",
                {
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": "You are a security expert analyzing findings."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens
                }
            )
            
            # Parse the response
            content = response["choices"][0]["message"]["content"]
            result = json.loads(content)
            
            # Create the analysis result
            return AnalysisResult(
                finding_id=finding["finding_id"],
                confidence_score=result["confidence_score"],
                confidence_level=self._get_confidence_level(result["confidence_score"]),
                analysis_summary=result["analysis_summary"],
                false_positive_probability=result["false_positive_probability"],
                remediation_suggestions=result["remediation_suggestions"],
                impact_assessment=result["impact_assessment"],
                metadata={
                    "confidence_factors": result["confidence_factors"],
                    "model": self.config.model_name,
                    "model_version": self.config.model_version
                },
                timestamp=datetime.now(),
                model_version=self.config.model_version
            )
            
        except json.JSONDecodeError as e:
            raise AIServiceError(f"Failed to parse OpenAI response: {str(e)}")
        except KeyError as e:
            raise AIServiceError(f"Missing required field in OpenAI response: {str(e)}")
        except Exception as e:
            raise AIServiceError(f"Failed to analyze finding: {str(e)}")
    
    async def validate_finding(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate a security finding using OpenAI.
        
        Args:
            finding: Finding data to validate
            
        Returns:
            Validation result with confidence score and details
            
        Raises:
            AIServiceError: If validation fails
            AIServiceRateLimitError: If rate limit is exceeded
        """
        try:
            # Prepare the prompt
            prompt = self.prompts["validate"].format(**finding)
            
            # Make the API request
            response = await self._make_request(
                "/v1/chat/completions",
                {
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": "You are a security expert validating findings."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens
                }
            )
            
            # Parse the response
            content = response["choices"][0]["message"]["content"]
            result = json.loads(content)
            
            # Create the validation result
            return ValidationResult(
                finding_id=finding["finding_id"],
                is_valid=result["is_valid"],
                validation_reason=result["validation_reason"],
                confidence_score=result["confidence_score"],
                metadata={
                    "validation_factors": result["validation_factors"],
                    "model": self.config.model_name,
                    "model_version": self.config.model_version
                },
                timestamp=datetime.now(),
                model_version=self.config.model_version
            )
            
        except json.JSONDecodeError as e:
            raise AIServiceError(f"Failed to parse OpenAI response: {str(e)}")
        except KeyError as e:
            raise AIServiceError(f"Missing required field in OpenAI response: {str(e)}")
        except Exception as e:
            raise AIServiceError(f"Failed to validate finding: {str(e)}")
    
    async def score_confidence(self, finding: Dict[str, Any]) -> ConfidenceScore:
        """Score the confidence of a finding using OpenAI.
        
        Args:
            finding: Finding data to score
            
        Returns:
            Confidence score with factors and details
            
        Raises:
            AIServiceError: If scoring fails
            AIServiceRateLimitError: If rate limit is exceeded
        """
        try:
            # Prepare the prompt
            prompt = self.prompts["score"].format(**finding)
            
            # Make the API request
            response = await self._make_request(
                "/v1/chat/completions",
                {
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": "You are a security expert scoring findings."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens
                }
            )
            
            # Parse the response
            content = response["choices"][0]["message"]["content"]
            result = json.loads(content)
            
            # Create the confidence score
            return ConfidenceScore(
                finding_id=finding["finding_id"],
                score=result["score"],
                level=self._get_confidence_level(result["score"]),
                factors=result["factors"],
                metadata={
                    "observations": result["observations"],
                    "model": self.config.model_name,
                    "model_version": self.config.model_version
                },
                timestamp=datetime.now(),
                model_version=self.config.model_version
            )
            
        except json.JSONDecodeError as e:
            raise AIServiceError(f"Failed to parse OpenAI response: {str(e)}")
        except KeyError as e:
            raise AIServiceError(f"Missing required field in OpenAI response: {str(e)}")
        except Exception as e:
            raise AIServiceError(f"Failed to score finding: {str(e)}")
    
    async def get_service_health(self) -> Dict[str, Any]:
        """Get the health status of the OpenAI service.
        
        Returns:
            Dictionary containing service health metrics
        """
        return await self.monitor.check_health()
    
    async def get_service_metrics(self) -> Dict[str, Any]:
        """Get usage metrics for the OpenAI service.
        
        Returns:
            Dictionary containing service usage metrics
        """
        return self.monitor.get_metrics()
    
    async def close(self) -> None:
        """Close the OpenAI service connection and cleanup resources."""
        if self.session:
            await self.session.close()
        await self.monitor.stop() 