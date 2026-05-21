import logging
import requests
import json
import time
import urllib3
from typing import List, Dict, Any, Optional
from requests.exceptions import RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class KeycloakTokenManager:
    _instances = {}

    def __new__(cls, auth_url: str, client_id: str, client_secret: str, ssl_verify: bool = False):
        key = (auth_url, client_id)
        if key not in cls._instances:
            instance = super().__new__(cls)
            instance._initialized = False
            cls._instances[key] = instance
        return cls._instances[key]

    def __init__(self, auth_url: str, client_id: str, client_secret: str, ssl_verify: bool = False):
        if getattr(self, '_initialized', False):
            return
            
        self.auth_url = auth_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.ssl_verify = ssl_verify
        self.token = None
        self.expires_at = 0
        self._initialized = True

    def get_token(self) -> Optional[str]:
        if not self.token or time.time() > (self.expires_at - 60):
            self._refresh_token()
        return self.token

    def _refresh_token(self):
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }
        try:
            response = requests.post(self.auth_url, data=payload, verify=self.ssl_verify, timeout=10)
            response.raise_for_status()
            token_data = response.json()
            self.token = token_data.get("access_token")
            self.expires_at = time.time() + token_data.get("expires_in", 300)
        except Exception as e:
            logger.error(f"Failed to fetch Keycloak token: {e}")
            raise

class vLLMClient:
    def __init__(self, config: Dict[str, Any], auth_cfg: Optional[Dict[str, Any]] = None, api_key: Optional[str] = None):
        self.model_name = config["model"]
        self.base_url = config["base_url"].rstrip('/')
        self.api_endpoint = config["api_endpoint"]
        self.api_url = f"{self.base_url}{self.api_endpoint}"
        self.chat_timeout = config["chat_timeout_seconds"]
        self.max_tokens = config["num_ctx"]
        self.ssl_verify = config["ssl_verify"]
        self.enable_thinking = config["enable_thinking"]

        self.session = requests.Session()
        self.token_manager = None
        self.api_key = api_key
        
        if auth_cfg and auth_cfg.get("auth_url") and auth_cfg.get("client_id") and auth_cfg.get("client_secret"):
            self.token_manager = KeycloakTokenManager(
                auth_url=auth_cfg["auth_url"],
                client_id=auth_cfg["client_id"],
                client_secret=auth_cfg["client_secret"],
                ssl_verify=self.ssl_verify
            )

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {}
        if self.token_manager:
            try:
                token = self.token_manager.get_token()
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            except Exception:
                pass
        elif self.api_key:
            if self.api_key.lower().startswith("bearer "):
                headers["Authorization"] = self.api_key
            else:
                headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def get_chat_completion(self, messages: List[Dict[str, Any]], temperature: float = 0.2, json_mode: bool = True, max_retries: int = 3, max_tokens: Optional[int] = None) -> Optional[Dict[str, Any]]:
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens or self.max_tokens,
            "stream": False
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
            
        if self.enable_thinking:
            payload["chat_template_kwargs"] = {"enable_thinking": True}

        # Global Retry & Exponential Backoff Logic
        for attempt in range(1, max_retries + 1):
            try:
                response = self.session.post(
                    self.api_url, 
                    json=payload, 
                    headers=self._get_auth_headers(),
                    timeout=self.chat_timeout, 
                    verify=self.ssl_verify
                )
                response.raise_for_status()
                data = response.json()
                if "choices" in data and len(data["choices"]) > 0:
                    return data["choices"][0]["message"]
                return None
            except RequestException as e:
                if attempt < max_retries:
                    sleep_time = 2 ** attempt  # 2s, 4s, etc.
                    logger.warning(f"vLLM API request failed (Attempt {attempt}/{max_retries}): {e}. Retrying in {sleep_time}s...")
                    time.sleep(sleep_time)
                else:
                    logger.error(f"vLLM API request critically failed after {max_retries} attempts: {e}")
                    return None
