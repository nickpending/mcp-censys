"""
Censys MCP tools module

This module defines Claude-compatible tools that use the Censys Search API to
perform recon on domains and IPs through natural language interactions.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from mcp_censys.client.censys import CensysClient
from mcp.server.fastmcp import FastMCP
import sys

mcp = FastMCP("Censys MCP Server")
censys = CensysClient()


def debug_log(msg: str):
    print(f"[DEBUG] {msg}", file=sys.stderr)


def is_domain_match(hostname: str, domain: str) -> bool:
    hostname = hostname.rstrip(".").lower()
    domain = domain.rstrip(".").lower()
    return hostname == domain or hostname.endswith(f".{domain}")


@mcp.tool(
    description="Summarize a domain's infrastructure: IPs, reverse DNS names, open ports, and ASNs."
)
def lookup_domain(domain: str) -> dict:
    query = f"(dns.names: {domain} OR dns.reverse_dns.names: {domain})"
    fields = [
        "ip",
        "dns.names",
        "dns.reverse_dns.names",
        "autonomous_system.name",
        "services.port",
    ]

    # Initialize sets to collect all data
    ips, dns_names, reverse_dns, asns, ports = set(), set(), set(), set(), set()

    # Use search_hosts which handles pagination automatically
    search = censys.search_hosts(query, fields, per_page=100)

    # Process results from all pages
    for page in search:
        for r in page:  # Results are directly in the page, not in a "results" key
            if ip := r.get("ip"):
                ips.add(ip)
            dns = r.get("dns", {})
            dns_names.update(dns.get("names", []))
            reverse_dns.update(dns.get("reverse_dns", {}).get("names", []))
            if asn := r.get("autonomous_system", {}).get("name"):
                asns.add(asn)
            ports.update(s.get("port") for s in r.get("services", []) if s.get("port"))

    return {
        "domain": domain,
        "ips": sorted(ips),
        "dns_names": sorted(dns_names),
        "reverse_dns": sorted(reverse_dns),
        "asns": sorted(asns),
        "ports": sorted(ports),
    }


@mcp.tool(
    description="Return full host records for a domain (services, ASN, geo, TLS). Shows a limited sample of matching records."
)
def lookup_domain_detailed(domain: str) -> dict:
    query = f"(dns.names: {domain} OR dns.reverse_dns.names: {domain})"
    per_page = 3  # Limit to just 3 records

    # Use raw_search to get metadata including total count
    raw_response = censys.hosts.raw_search(query=query, per_page=per_page)

    # Extract total count and results
    total_records = raw_response.get("result", {}).get("total", 0)
    results = raw_response.get("result", {}).get("hits", [])

    # Create an informative note about available records
    note = None
    if total_records > per_page:
        note = f"Showing {len(results)} of {total_records} total records. There are {total_records - per_page} additional records not displayed."
    else:
        note = f"Showing all {total_records} record(s)."

    return {
        "domain": domain,
        "record_count": total_records,
        "sample_limit": per_page,
        "note": note,
        "records": results,
    }


@mcp.tool(
    description="Get full metadata for an IP: DNS, ASN, ports, TLS, and location."
)
def lookup_ip(ip: str) -> dict:
    query = f"ip: {ip}"

    # Use specific leaf fields instead of parent fields
    fields = [
        "ip",
        "autonomous_system.name",
        "autonomous_system.asn",
        "location.country",
        "location.continent",
        "location.coordinates.latitude",  # Separate leaf field for latitude
        "location.coordinates.longitude",  # Separate leaf field for longitude
        "dns.names",
        "dns.reverse_dns.names",
        "services.port",
        "services.service_name",
        "services.transport_protocol",
        "services.tls.certificates.leaf_data.names",
        "last_updated_at",
    ]

    # Use search_hosts which handles pagination automatically
    search = censys.search_hosts(query, fields, per_page=1)

    results = []
    # We only need the first page since we're looking up a specific IP
    for page in search:
        results.extend(page)  # Page is directly iterable with results
        break

    return {"ip": ip, "records": results}


@mcp.tool(description="Find recently seen FQDNs tied to a domain in DNS and certs.")
def new_fqdns(domain: str, days: int = 1) -> dict:
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    fqdns = defaultdict(lambda: {"sources": set(), "last_seen": None})

    # Search for DNS records
    dns_query = f"(dns.names: {domain} OR dns.reverse_dns.names: {domain}) AND last_updated_at: [{since} TO *]"
    dns_fields = ["dns.names", "dns.reverse_dns.names", "last_updated_at"]
    dns_search = censys.search_hosts(query=dns_query, fields=dns_fields, per_page=100)

    # Process each page of DNS results
    for page in dns_search:
        for r in page:  # Direct iteration over page items instead of using .get()
            last_seen = r.get("last_updated_at")
            dns_data = r.get("dns", {})
            for name in dns_data.get("names", []):
                if is_domain_match(name, domain):
                    fqdns[name]["sources"].add("hosts-dns")
                    fqdns[name]["last_seen"] = last_seen
            for name in dns_data.get("reverse_dns", {}).get("names", []):
                if is_domain_match(name, domain):
                    fqdns[name]["sources"].add("hosts-reverse")
                    fqdns[name]["last_seen"] = last_seen

    # Search for certificates
    cert_query = f"names: {domain} AND added_at: [{since} TO *]"
    cert_fields = ["names", "added_at"]
    cert_results = censys.certs.search(cert_query, fields=cert_fields, per_page=100)

    # Process certificate results
    for result in cert_results:
        items = result if isinstance(result, list) else [result]
        for r in items:
            added_at = r.get("added_at")
            for name in r.get("names", []):
                if is_domain_match(name, domain):
                    fqdns[name]["sources"].add("certs")
                    fqdns[name]["last_seen"] = added_at

    return {
        "domain": domain,
        "days": days,
        "new_fqdns": sorted(fqdns.keys()),
        "count": len(fqdns),
        "details": {
            name: {
                "sources": sorted(list(data["sources"])),
                "last_seen": data["last_seen"],
            }
            for name, data in fqdns.items()
        },
    }


@mcp.tool(description="List exposed ports and service names for a given IP address.")
def host_services(ip: str) -> dict:
    query = f"ip: {ip}"
    fields = ["services.port", "services.service_name", "last_updated_at"]
    search = censys.search_hosts(query, fields, per_page=100)

    services = []
    for page in search:
        for r in page:  # Direct iteration over page items
            for s in r.get("services", []):
                services.append(
                    {
                        "port": s.get("port"),
                        "service": s.get("service_name"),
                        "last_seen": r.get("last_updated_at"),
                    }
                )

    return {"ip": ip, "services": services}


__all__ = ["mcp"]
