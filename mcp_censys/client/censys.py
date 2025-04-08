"""
CensysClient wrapper for the Censys Search API.

This class handles authentication and wraps host-level and certificate-level
search functionality, returning paginated results for MCP tools.

Environment variables required:
  - CENSYS_API_ID
  - CENSYS_API_SECRET
"""

import os
from dotenv import load_dotenv
from censys.search import CensysHosts, CensysCerts

# Load credentials from .env file
load_dotenv()

CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")

if not CENSYS_API_ID or not CENSYS_API_SECRET:
    raise EnvironmentError(
        "CENSYS_API_ID and CENSYS_API_SECRET must be set in environment variables."
    )


class CensysClient:
    def __init__(self):
        """Initialize the Censys Hosts and Certs clients with credentials."""
        self.hosts = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        self.certs = CensysCerts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)

    def search_hosts(self, query: str, fields: list, per_page: int = 10):
        """
        Execute a host search query and return raw paginated generator.

        Args:
            query (str): Censys Search Language query string
            fields (list): List of fields to return in results
            per_page (int): Number of results per page

        Returns:
            generator: Paginated response generator from Censys SDK
        """
        return self.hosts.search(query=query, fields=fields, per_page=per_page)

    def search_certs(self, query: str, fields: list, per_page: int = 10):
        """
        Execute a certificate search query and return raw paginated generator.

        Args:
            query (str): Censys Search Language query string
            fields (list): List of fields to return in results
            per_page (int): Number of results per page

        Returns:
            generator: Paginated response generator from Censys SDK
        """
        return self.certs.search(query=query, fields=fields, per_page=per_page)
