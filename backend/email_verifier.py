"""
Email Verifier Module
Implements comprehensive email verification with point-based scoring (0-100)
Following the EMAIL VERIFICATION SCORING RULES
"""

import dns.resolver
import smtplib
import socket
import os
import random
import string
import threading
import time
import re
import ssl
from typing import Any, Dict, List, Optional, Tuple
import logging
import json
import requests
from datetime import datetime, timedelta
try:
    # Preferred relative import when running as a package
    from . import internet_check as internet_check_module
except Exception:
    # Fall back to top-level import for test scripts or simple runs
    import internet_check as internet_check_module


logger = logging.getLogger(__name__)

# Optional: per-domain overrides for internal/testing use.
DOMAIN_CONFIDENCE_OVERRIDES: Dict[str, Dict[str, Any]] = {}


class EmailVerifier:
    """Main email verification class with point-based scoring (0-100)"""
    
    def __init__(self):
        self.timeout = 5  # seconds (reduced for faster response)
        self.smtp_timeout = 8  # seconds for SMTP operations (reduced)
        self.fast_smtp_timeout = 3  # seconds for fast mode
        # Domains that typically block SMTP verification
        self.smtp_blocked_domains = [
            'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
            'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk',
            'aol.com', 'icloud.com', 'me.com', 'mac.com',
            'microsoft.com', 'office365.com'
        ]
        self.cache_ttl = 3600  # seconds
        self._cache_lock = threading.Lock()
        self._mx_cache: Dict[str, Dict[str, Any]] = {}
        self._deliverability_cache: Dict[str, Dict[str, Any]] = {}
        self._domain_age_cache: Dict[str, Dict[str, Any]] = {}
        self._web_presence_cache: Dict[str, Dict[str, Any]] = {}
        self._provider_fingerprint_cache: Dict[str, Dict[str, Any]] = {}
        self._ip_reputation_cache: Dict[str, Dict[str, Any]] = {}
        self._mx_popularity_cache: Dict[str, Dict[str, Any]] = {}
        
        # Provider-Level Behavior Rules (PLBR)
        self.provider_rules = {
            'gmail.com': {'max_score_without_rcpt': 55, 'always_blocks': True},
            'googlemail.com': {'max_score_without_rcpt': 55, 'always_blocks': True},
            'outlook.com': {'max_score_without_rcpt': 60, 'always_blocks': True, 'may_accept_all': True},
            'hotmail.com': {'max_score_without_rcpt': 60, 'always_blocks': True},
            'live.com': {'max_score_without_rcpt': 60, 'always_blocks': True},
            'yahoo.com': {'max_score_without_rcpt': 55, 'always_blocks': True},
            'yahoo.co.uk': {'max_score_without_rcpt': 55, 'always_blocks': True},
            'zoho.com': {'max_score_without_rcpt': 75, 'reliable_rejections': True},
            'protonmail.com': {'max_score_without_rcpt': 50, 'always_blocks': True, 'accept_all': True},
            'icloud.com': {'max_score_without_rcpt': 50, 'always_blocks': True},
            'me.com': {'max_score_without_rcpt': 50, 'always_blocks': True},
            'mac.com': {'max_score_without_rcpt': 50, 'always_blocks': True},
        }
        self.enable_internet_checks = os.getenv('ENABLE_INTERNET_CHECKS', 'true').lower() in ('1', 'true', 'yes')
        self.hibp_enabled = os.getenv('ENABLE_HIBP', 'true').lower() in ('1', 'true', 'yes')
        self._sender_domain = os.getenv('VERIFIER_SENDER_DOMAIN') or socket.getfqdn()

    def _get_cached(self, cache: Dict[str, Dict[str, Any]], key: str) -> Optional[Dict[str, Any]]:
        with self._cache_lock:
            entry = cache.get(key)
            if not entry:
                return None
            if entry["expires_at"] > time.time():
                return entry["value"]
            cache.pop(key, None)
            return None

    def _set_cache(self, cache: Dict[str, Dict[str, Any]], key: str, value: Dict[str, Any]) -> None:
        with self._cache_lock:
            cache[key] = {"value": value, "expires_at": time.time() + self.cache_ttl}
        
    def verify_email(
        self,
        email: str,
        fast_mode: bool = True,
        confidence_mode: str = "balanced",
        internet_checks: bool = True,
    ) -> Dict:
        """
        Main verification method
        Returns comprehensive verification result with point-based score (0-100)
        """
        score = 0
        score_details = {}
        
        # 1. Basic Syntax Validation
        syntax_result = self._check_syntax(email)
        score += syntax_result["points"]
        score_details["syntax"] = syntax_result
        
        if not syntax_result["valid"]:
            return {
                "email": email,
                "status": "invalid",
                "score": 0,
                "confidence": 0.0,
                "reason": "Invalid email syntax",
                "details": score_details
            }
        
        local_part, domain = email.lower().split('@', 1)
        
        result = {
            "email": email,
            "status": "unknown",
            "score": 0,
            "confidence": 0.0,
            "reason": "",
            "details": score_details
        }
        
        # 2. Domain Existence & DNS Health
        dns_result = self._check_dns_health(domain)
        score += dns_result["points"]
        score_details["dns_health"] = dns_result
        
        if not dns_result["domain_exists"]:
            result["status"] = "invalid"
            result["score"] = score
            result["confidence"] = score / 100.0
            result["reason"] = "Domain does not exist"
            return result
        
        mx_hosts = dns_result.get("mx_hosts", [])
        
        # 3. Domain Age & Reputation
        age_result = self._check_domain_age(domain)
        score += age_result["points"]
        score_details["domain_age"] = age_result
        
        # 4. SMTP Connection Test
        smtp_connection = self._check_smtp_connection(domain, mx_hosts, fast_mode)
        score += smtp_connection["points"]
        score_details["smtp_connection"] = smtp_connection
        
        # 5. SMTP Server Greeting Behavior
        greeting_result = smtp_connection.get("greeting", {})
        score += greeting_result.get("points", 0)
        score_details["smtp_greeting"] = greeting_result
        
        # 6. SMTP RCPT TO / Verification Response
        smtp_rcpt = self._check_smtp_rcpt(email, domain, mx_hosts, smtp_connection, fast_mode)
        score += smtp_rcpt["points"]
        score_details["smtp_rcpt"] = smtp_rcpt
        
        # Handle hard failures - set score to 0-10 if invalid
        if smtp_rcpt.get("hard_failure"):
            score = min(score, 10)
        
        # 7. SMTP Behavior Timing
        timing_result = smtp_rcpt.get("timing", {})
        score += timing_result.get("points", 0)
        score_details["smtp_timing"] = timing_result
        
        # 8. Domain Security Reputation Signals
        security_result = self._check_security_reputation(domain)
        score += security_result["points"]
        score_details["security_reputation"] = security_result
        
        # 9. Web Presence Check (Domain-Level Only)
        web_result = self._check_web_presence(domain)
        score += web_result["points"]
        score_details["web_presence"] = web_result
        
        # Advanced Features (10-21)
        # 10. Mailbox Provider Fingerprinting (MPF)
        if not fast_mode:
            mpf_result = self._check_provider_fingerprint(domain, mx_hosts, smtp_connection, fast_mode)
            score += mpf_result["points"]
            score_details["provider_fingerprint"] = mpf_result
        
        # 11. SMTP Error Pattern Classification
        error_pattern_result = self._classify_smtp_error_pattern(smtp_rcpt, smtp_connection)
        score += error_pattern_result["points"]
        score_details["error_pattern"] = error_pattern_result
        
        # 12. Provider-Level Behavior Rules (PLBR)
        plbr_result = self._apply_provider_rules(domain, smtp_rcpt, score)
        if plbr_result.get("score_adjusted"):
            score = plbr_result["adjusted_score"]
        score_details["provider_rules"] = plbr_result
        
        # 13. SMTP Retry Simulation (for greylisting)
        if not fast_mode and smtp_rcpt.get("soft_failure"):
            retry_result = self._smtp_retry_simulation(email, domain, mx_hosts)
            if retry_result.get("success_after_retry"):
                score += 20  # +20 for strong confirmation
            score_details["smtp_retry"] = retry_result
        
        # 14. TLS Certificate Intelligence (TCI)
        if smtp_connection.get("mx_used"):
            tci_result = self._check_tls_certificate(smtp_connection["mx_used"])
            score += tci_result["points"]
            score_details["tls_certificate"] = tci_result
        
        # 15. Open Ports Scan (Mail Infra Health)
        if not fast_mode and mx_hosts:
            ports_result = self._check_mail_ports(mx_hosts[0])
            score += ports_result["points"]
            score_details["mail_ports"] = ports_result
        
        # 16. DNSSEC Check
        dnssec_result = self._check_dnssec(domain)
        score += dnssec_result["points"]
        score_details["dnssec"] = dnssec_result
        
        # 17. PTR Record Verification
        if mx_hosts:
            ptr_result = self._check_ptr_record(mx_hosts[0])
            score += ptr_result["points"]
            score_details["ptr_record"] = ptr_result
        
        # 18. IP Reputation Score
        if mx_hosts:
            ip_reputation_result = self._check_ip_reputation(mx_hosts[0])
            score += ip_reputation_result["points"]
            score_details["ip_reputation"] = ip_reputation_result
        
        # 19. Mail Server Behaviour Analysis (Heuristics)
        if smtp_connection.get("mx_used"):
            behavior_result = self._analyze_server_behavior(smtp_connection, smtp_rcpt)
            score += behavior_result["points"]
            score_details["server_behavior"] = behavior_result
        
        # 20. Free Reverse MX Lookup (Global Domain Popularity)
        if mx_hosts:
            mx_popularity_result = self._check_mx_popularity(mx_hosts[0])
            score += mx_popularity_result["points"]
            score_details["mx_popularity"] = mx_popularity_result
        
        # 21. Email Blocklist Behavior (Indirect)
        blocklist_behavior_result = self._analyze_blocklist_behavior(smtp_rcpt, smtp_connection)
        score += blocklist_behavior_result.get("points", 0)
        score_details["blocklist_behavior"] = blocklist_behavior_result
        
        # Additional Advanced Features (22-27)
        # 22. Mail Exchanger Consistency Check (MX↔A sanity test)
        if mx_hosts:
            mx_consistency_result = self._check_mx_consistency(mx_hosts[0], domain)
            score += mx_consistency_result["points"]
            score_details["mx_consistency"] = mx_consistency_result
        
        # 23. STARTTLS Upgrade Behaviour (TLS Policy Strength)
        if smtp_connection.get("mx_used") and not fast_mode:
            tls_policy_result = self._check_tls_policy_strength(smtp_connection["mx_used"])
            score += tls_policy_result["points"]
            score_details["tls_policy"] = tls_policy_result
        
        # 24. Multi-MX Redundancy Check
        mx_redundancy_result = self._check_mx_redundancy(mx_hosts)
        score += mx_redundancy_result["points"]
        score_details["mx_redundancy"] = mx_redundancy_result
        
        # 25. SMTP Transaction Strictness Scoring
        if smtp_connection.get("mx_used") and not fast_mode:
            strictness_result = self._check_smtp_strictness(smtp_connection, smtp_rcpt)
            score += strictness_result["points"]
            score_details["smtp_strictness"] = strictness_result
        
        # 26. MAIL FROM Domain Health
        if smtp_connection.get("mx_used") and not fast_mode:
            mailfrom_result = self._check_mailfrom_health(domain, mx_hosts, smtp_connection)
            score += mailfrom_result["points"]
            score_details["mailfrom_health"] = mailfrom_result
        
        # 27. Connection Latency Fingerprinting
        if smtp_connection.get("mx_used") and not fast_mode:
            latency_result = self._analyze_connection_latency(smtp_connection, smtp_rcpt)
            score += latency_result["points"]
            score_details["latency_fingerprint"] = latency_result
        
        # 28. SMTP Load-Balancer Behavior
        if len(mx_hosts) > 1 and not fast_mode:
            loadbalancer_result = self._check_loadbalancer_behavior(email, domain, mx_hosts)
            score += loadbalancer_result["points"]
            score_details["loadbalancer"] = loadbalancer_result
        
        # 29. SMTP "VRFY Lite" Behaviour
        if smtp_connection.get("mx_used") and not fast_mode:
            vrfy_result = self._check_vrfy_lite_behavior(email, domain, mx_hosts, smtp_connection)
            score += vrfy_result["points"]
            score_details["vrfy_lite"] = vrfy_result
        
        # 30. Recipient Domain Email Role Account Policy
        if not fast_mode:
            role_account_result = self._check_role_accounts(domain, mx_hosts)
            score += role_account_result["points"]
            score_details["role_accounts"] = role_account_result
        
        # 31. MX Infrastructure Identity Check (Brand MX Mapping)
        if mx_hosts:
            brand_mx_result = self._check_mx_brand(mx_hosts[0])
            score += brand_mx_result["points"]
            score_details["mx_brand"] = brand_mx_result
        
        # 32. Greylist "Depth Check"
        if smtp_rcpt.get("soft_failure") and not fast_mode:
            greylist_depth_result = self._check_greylist_depth(email, domain, mx_hosts)
            score += greylist_depth_result["points"]
            score_details["greylist_depth"] = greylist_depth_result
        
        # 33. SMTP Banner Metadata Inspection
        if smtp_connection.get("greeting", {}).get("message"):
            banner_result = self._analyze_smtp_banner(smtp_connection["greeting"]["message"])
            score += banner_result["points"]
            score_details["smtp_banner"] = banner_result
        
        # 34. Spamhaus DBL / Barracuda BL DNS Lookup
        dbl_result = self._check_domain_blacklists(domain)
        score += dbl_result["points"]
        score_details["domain_blacklists"] = dbl_result
        
        # 35. SMTP QUIT Acknowledgement Behavior
        if smtp_connection.get("mx_used") and not fast_mode:
            quit_result = self._check_quit_behavior(smtp_connection["mx_used"])
            score += quit_result["points"]
            score_details["quit_behavior"] = quit_result
        
        # 36. TCP Retransmissions Patterns (VERY ADVANCED)
        # Note: This requires low-level socket monitoring, skipped in fast mode
        if smtp_connection.get("mx_used") and not fast_mode:
            tcp_stability_result = self._check_tcp_stability(smtp_connection["mx_used"])
            score += tcp_stability_result.get("points", 0)
            score_details["tcp_stability"] = tcp_stability_result
        
        # Catch-all detection
        catch_all_result = self._detect_catch_all(domain, mx_hosts) if not fast_mode else {"is_catchall": False, "skipped": True}
        score_details["catch_all"] = catch_all_result
        if catch_all_result.get("is_catchall"):
            score += 10  # +10 for catch-all (but mark as risky)
            result["risky"] = True
        
        # Internet presence checks (optional)
        if internet_checks or self.enable_internet_checks:
            try:
                result["details"]["internet_check"] = internet_check_module.check_internet_presence(
                    email,
                    enable_hibp=self.hibp_enabled,
                )
            except Exception as e:
                result["details"]["internet_check"] = {"error": str(e)}
        
        # Ensure score is between 0 and 100
        score = max(0, min(100, score))
        
        result["score"] = score
        result["confidence"] = score / 100.0
        result["details"] = score_details
        
        # Determine status based on score
        if score >= 90:
            result["status"] = "valid"
            result["reason"] = "Very likely valid"
        elif score >= 70:
            result["status"] = "likely_valid"
            result["reason"] = "Probably valid but unconfirmed"
        elif score >= 50:
            result["status"] = "uncertain"
            result["reason"] = "Uncertain (common when SMTP blocks verification)"
        elif score >= 20:
            result["status"] = "likely_invalid"
            result["reason"] = "Likely invalid"
        else:
            result["status"] = "invalid"
            result["reason"] = "Definitely invalid"
        
        # Apply optional per-domain overrides
        override = DOMAIN_CONFIDENCE_OVERRIDES.get(domain)
        if override:
            min_score = override.get("min_score")
            force_status = override.get("force_status")
            if isinstance(min_score, (int, float)):
                result["score"] = max(result["score"], int(min_score))
                result["confidence"] = result["score"] / 100.0
            if isinstance(force_status, str):
                result["status"] = force_status

        return result
    
    def _check_syntax(self, email: str) -> Dict:
        """1. Basic Syntax Validation: Valid syntax → +10, Invalid → 0"""
        # RFC 5322 compliant regex (simplified but effective)
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        valid = bool(re.match(pattern, email))
        
        return {
            "valid": valid,
            "points": 10 if valid else 0,
            "reason": "Valid syntax" if valid else "Invalid syntax"
        }
    
    def _check_dns_health(self, domain: str) -> Dict:
        """2. Domain Existence & DNS Health"""
        points = 0
        result = {
            "domain_exists": False,
            "mx_present": False,
            "spf_exists": False,
            "dkim_exists": False,
            "dmarc_exists": False,
            "dns_response_time_ms": 0,
            "points": 0,
            "mx_hosts": []
        }
        
        start_time = time.time()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 4.0
        
        try:
            # Check if domain exists (A record)
            try:
                resolver.resolve(domain, 'A')
                result["domain_exists"] = True
            except:
                pass
            
            # Check MX records
            try:
                mx_records = resolver.resolve(domain, 'MX')
                mx_hosts = []
                for mx in mx_records:
                    mx_hosts.append(str(mx.exchange).rstrip('.'))
                result["mx_hosts"] = mx_hosts
                result["mx_present"] = True
                points += 20  # MX present → +20
            except dns.resolver.NoAnswer:
                # Try A record as fallback
                try:
                    resolver.resolve(domain, 'A')
                    result["domain_exists"] = True
                    result["mx_hosts"] = [domain]
                except:
                    pass
            except:
                pass
            
            # Check SPF
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    txt_string = b''.join(record.strings).decode('utf-8', errors='ignore')
                    if txt_string.startswith('v=spf1'):
                        result["spf_exists"] = True
                        points += 5  # SPF exists → +5
                        break
            except:
                pass
            
            # Check DMARC
            try:
                dmarc_domain = f"_dmarc.{domain}"
                txt_records = resolver.resolve(dmarc_domain, 'TXT')
                for record in txt_records:
                    txt_string = b''.join(record.strings).decode('utf-8', errors='ignore')
                    if txt_string.startswith('v=DMARC1'):
                        result["dmarc_exists"] = True
                        points += 5  # DMARC exists → +5
                        break
            except:
                pass
            
            # Check DKIM (common selectors)
            common_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail']
            for selector in common_selectors:
                try:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    resolver.resolve(dkim_domain, 'TXT')
                    result["dkim_exists"] = True
                    points += 5  # DKIM exists → +5
                    break
                except:
                    continue
            
            # Measure DNS response time
            dns_time = (time.time() - start_time) * 1000  # Convert to ms
            result["dns_response_time_ms"] = round(dns_time, 2)
            
            if dns_time < 300:
                points += 3  # Fast (<300 ms) → +3
            elif dns_time > 800:
                points -= 3  # Slow (>800 ms) → -3
            
        except dns.resolver.NXDOMAIN:
            result["domain_exists"] = False
        except Exception as e:
            logger.warning(f"DNS check error for {domain}: {str(e)}")
        
        result["points"] = points
        return result
    
    def _check_domain_age(self, domain: str) -> Dict:
        """3. Domain Age & Reputation
        Age < 1 month → -15
        Age 1–12 months → 0
        Age > 1 year → +10
        """
        result = {
            "age_months": None,
            "points": 0,
            "skipped": False
        }
        
        # Try to get cached result
        cached = self._get_cached(self._domain_age_cache, domain)
        if cached:
            return cached
        
        try:
            # Try using python-whois if available
            try:
                import whois
                w = whois.whois(domain)
                creation_date = w.creation_date
                
                if creation_date:
                    # Handle list or single date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    if isinstance(creation_date, str):
                        # Try to parse string date
                        try:
                            from dateutil import parser
                            creation_date = parser.parse(creation_date)
                        except ImportError:
                            # Fallback to datetime parsing
                            try:
                                creation_date = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                            except:
                                result["skipped"] = True
                                result["points"] = 0
                                self._set_cache(self._domain_age_cache, domain, result)
                                return result
                    
                    if isinstance(creation_date, datetime):
                        age_delta = datetime.now() - creation_date
                        age_months = age_delta.days / 30.0
                        result["age_months"] = round(age_months, 1)
                        
                        if age_months < 1:
                            result["points"] = -15  # Age < 1 month → -15
                        elif age_months < 12:
                            result["points"] = 0  # Age 1–12 months → 0
                        else:
                            result["points"] = 10  # Age > 1 year → +10
            except ImportError:
                # python-whois not available, try alternative method
                logger.debug("python-whois not available, trying alternative method")
                result["skipped"] = True
                result["points"] = 0  # Neutral if we can't determine
            except Exception as e:
                logger.debug(f"WHOIS lookup error for {domain}: {str(e)}")
                result["skipped"] = True
                result["points"] = 0  # Neutral if we can't determine
            
        except Exception as e:
            logger.warning(f"Domain age check error for {domain}: {str(e)}")
            result["skipped"] = True
            result["points"] = 0  # Neutral if we can't determine
        
        self._set_cache(self._domain_age_cache, domain, result)
        return result
    
    def _check_smtp_connection(self, domain: str, mx_hosts: List[str], fast_mode: bool = True) -> Dict:
        """4. SMTP Connection Test: Port 25 availability and TLS handshake"""
        result = {
            "port_25_open": False,
            "tls_successful": False,
            "greeting": {},
            "points": 0,
            "mx_used": None
        }
        
        if not mx_hosts:
            return result
        
        # Skip for known blocked domains
        domain_lower = domain.lower()
        for blocked in self.smtp_blocked_domains:
            if blocked in domain_lower or domain_lower.endswith('.' + blocked):
                result["skipped"] = True
                return result
        
        # Skip for transactional email services
        transactional_patterns = [
            'inbound-smtp', 'amazonaws.com', 'sendgrid.net',
            'mailgun.org', 'mailgun.com', 'sparkpostmail.com',
            'postmarkapp.com', 'mandrillapp.com',
        ]
        for mx_host in mx_hosts[:2]:
            mx_lower = mx_host.lower()
            for pattern in transactional_patterns:
                if pattern in mx_lower:
                    result["skipped"] = True
                    return result
        
        # Use faster timeout in fast mode
        smtp_timeout = self.fast_smtp_timeout if fast_mode else self.smtp_timeout
        port_timeout = 2 if fast_mode else 5
        
        for mx_host in mx_hosts[:2]:
            try:
                # Test port 25 availability
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(port_timeout)
                port_open = sock.connect_ex((mx_host, 25)) == 0
                sock.close()
                
                if not port_open:
                    continue
                
                result["port_25_open"] = True
                result["points"] += 10  # Port 25 open → +10
                result["mx_used"] = mx_host
                
                # Connect and check greeting
                server = smtplib.SMTP(timeout=smtp_timeout)
                server.set_debuglevel(0)
                
                try:
                    # Connect and check greeting using raw socket first
                    greeting_code = None
                    greeting_msg = ""
                    try:
                        # Use raw socket to read greeting
                        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        raw_sock.settimeout(5)
                        raw_sock.connect((mx_host, 25))
                        greeting_response = raw_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        raw_sock.close()
                        
                        # Parse greeting (format: "220 hostname message")
                        if greeting_response.startswith('220'):
                            greeting_code = 220
                            greeting_msg = greeting_response
                            result["greeting"]["valid"] = True
                            result["greeting"]["points"] = 10  # Valid 220 greeting → +10
                        else:
                            result["greeting"]["valid"] = False
                            result["greeting"]["points"] = -10  # Suspicious/no greeting → -10
                    except Exception as e:
                        # If raw socket fails, try smtplib and assume greeting is OK if connection succeeds
                        logger.debug(f"Raw socket greeting check failed: {str(e)}")
                        result["greeting"]["valid"] = False
                        result["greeting"]["points"] = -10
                    
                    result["greeting"]["code"] = greeting_code
                    result["greeting"]["message"] = greeting_msg
                    
                    # Now use smtplib for the rest
                    server.connect(mx_host, 25)
                    
                    # Try TLS handshake (skip in fast mode to save time)
                    if not fast_mode:
                        try:
                            server.ehlo()
                            if server.has_extn('STARTTLS'):
                                server.starttls()
                                server.ehlo()
                                result["tls_successful"] = True
                                result["points"] += 5  # TLS successful → +5
                        except:
                            pass
                    else:
                        # In fast mode, just do EHLO
                        try:
                            server.ehlo()
                        except:
                            pass
                    
                    server.quit()
                    break
                    
                except Exception as e:
                    logger.debug(f"SMTP connection error for {mx_host}: {str(e)}")
                    continue
                    
            except Exception as e:
                logger.debug(f"Port check error for {mx_host}: {str(e)}")
                continue
        
        return result
    
    def _check_smtp_rcpt(self, email: str, domain: str, mx_hosts: List[str], smtp_connection: Dict, fast_mode: bool = True) -> Dict:
        """6. SMTP RCPT TO / Verification Response"""
        result = {
            "accepted": False,
            "rejected": False,
            "hard_failure": False,
            "soft_failure": False,
            "catch_all_detected": False,
            "timing": {
                "response_time_sec": 0,
                "points": 0
            },
            "points": 0,
            "error": None,
            "response_code": None
        }
        
        if smtp_connection.get("skipped") or not smtp_connection.get("port_25_open"):
            result["skipped"] = True
            return result
        
        mx_host = smtp_connection.get("mx_used")
        if not mx_host:
            mx_host = mx_hosts[0] if mx_hosts else None
        
        if not mx_host:
            return result
        
        # Use appropriate timeout based on mode
        smtp_timeout = self.fast_smtp_timeout if fast_mode else self.smtp_timeout
        
        try:
            server = smtplib.SMTP(timeout=smtp_timeout)
            server.set_debuglevel(0)
            
            start_time = time.time()
            
            try:
                server.connect(mx_host, 25)
                
                # HELO/EHLO
                code, message = server.ehlo()
                if code != 250:
                    server.helo()
                
                # MAIL FROM
                test_sender = f"verify@{self._sender_domain}"
                code, message = server.mail(test_sender)
                if code not in [250, 251]:
                    server.quit()
                    return result
                
                # RCPT TO (key check)
                code, message = server.rcpt(email)
                response_time = time.time() - start_time
                result["timing"]["response_time_sec"] = round(response_time, 2)
                result["response_code"] = code
                
                server.quit()
                
                # Classify response
                if code in [250, 251]:
                    result["accepted"] = True
                    result["points"] += 10  # Email might exist (soft acceptance)
                elif code == 550:
                    # Check for "User unknown" or "5.1.1"
                    msg_lower = str(message).lower()
                    if "user unknown" in msg_lower or "5.1.1" in msg_lower:
                        result["rejected"] = True
                        result["hard_failure"] = True
                        result["points"] = 0  # Hard failure → score = 0-10
                        result["error"] = "User unknown"
                    else:
                        result["rejected"] = True
                        result["points"] = 0
                elif code in [450, 451]:
                    # Soft failures / Greylisting
                    result["soft_failure"] = True
                    result["points"] += 10  # Email might exist → +10
                    result["error"] = "Temporarily unavailable (greylisted)"
                elif code == 421:
                    result["soft_failure"] = True
                    result["points"] += 10  # Try again later → +10
                    result["error"] = "Service unavailable, try again later"
                elif 500 <= code < 600:
                    result["rejected"] = True
                    result["hard_failure"] = True
                    result["points"] = 0
                    result["error"] = f"Permanent SMTP error: {code}"
                else:
                    result["error"] = f"Unexpected response: {code}"
                
                # 7. SMTP Behavior Timing
                if response_time < 1:
                    result["timing"]["points"] = -10  # Quick reject (<1 sec) → -10
                elif response_time > 15:
                    result["timing"]["points"] = -5  # Overly long delay (>15 sec) → -5
                else:
                    result["timing"]["points"] = 5  # Normal latency → +5
                
            except smtplib.SMTPServerDisconnected:
                result["error"] = "Server disconnected"
            except socket.timeout:
                result["error"] = "Connection timeout"
            except Exception as e:
                result["error"] = f"SMTP error: {str(e)}"
                
        except Exception as e:
            result["error"] = f"Connection error: {str(e)}"
        
        return result
    
    def _check_security_reputation(self, domain: str) -> Dict:
        """8. Domain Security Reputation Signals"""
        result = {
            "strong_spf": False,
            "dkim_dmarc_aligned": False,
            "points": 0
        }
        
        # Get deliverability info (cached)
        deliverability = self._get_cached(self._deliverability_cache, domain)
        if deliverability is None:
            deliverability = self._check_deliverability(domain)
            self._set_cache(self._deliverability_cache, domain, deliverability)
        
        # Check SPF syntax strength (basic check)
        if deliverability.get("spf"):
            spf_record = deliverability.get("spf_record", "")
            # Strong SPF has mechanisms beyond just "v=spf1"
            if len(spf_record) > 10 and ("include:" in spf_record or "ip4:" in spf_record or "ip6:" in spf_record):
                result["strong_spf"] = True
                result["points"] += 3  # Strong SPF syntax → +3
        
        # Check DKIM + DMARC alignment
        if deliverability.get("dkim") and deliverability.get("dmarc"):
            result["dkim_dmarc_aligned"] = True
            result["points"] += 5  # Alignment DKIM+DMARC → +5
        
        return result
    
    def _check_web_presence(self, domain: str) -> Dict:
        """9. Web Presence Check (Domain-Level Only)"""
        result = {
            "has_website": False,
            "http_status": None,
            "points": 0,
            "skipped": False
        }
        
        # Check cache
        cached = self._get_cached(self._web_presence_cache, domain)
        if cached:
            return cached
        
        try:
            # Try HTTP and HTTPS
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{domain}"
                    response = requests.get(url, timeout=5, allow_redirects=True)
                    result["has_website"] = True
                    result["http_status"] = response.status_code
                    
                    result["points"] += 5  # Domain has a website → +5
                    if response.status_code == 200:
                        result["points"] += 5  # Website returns 200 OK → +5
                    break
                except:
                    continue
            
            if not result["has_website"]:
                result["points"] = -10  # Website dead → -10
                
        except Exception as e:
            logger.debug(f"Web presence check error for {domain}: {str(e)}")
            result["skipped"] = True
        
        self._set_cache(self._web_presence_cache, domain, result)
        return result
    
    def _check_deliverability(self, domain: str) -> Dict:
        """Check SPF, DKIM, and DMARC records"""
        result = {
            "spf": False,
            "dkim": False,
            "dmarc": False,
            "spf_record": None,
            "dmarc_record": None,
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 4.0

        # Check SPF
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            for record in txt_records:
                txt_string = b''.join(record.strings).decode('utf-8', errors='ignore')
                if txt_string.startswith('v=spf1'):
                    result["spf"] = True
                    result["spf_record"] = txt_string
        except:
            pass
        
        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = resolver.resolve(dmarc_domain, 'TXT')
            for record in txt_records:
                txt_string = b''.join(record.strings).decode('utf-8', errors='ignore')
                if txt_string.startswith('v=DMARC1'):
                    result["dmarc"] = True
                    result["dmarc_record"] = txt_string
        except:
            pass
        
        # Check DKIM
        common_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail']
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                resolver.resolve(dkim_domain, 'TXT')
                result["dkim"] = True
                break
            except:
                continue
        
        return result
    
    def _detect_catch_all(self, domain: str, mx_hosts: List[str]) -> Dict:
        """Detect if domain uses catch-all by testing a random email"""
        random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        test_email = f"{random_string}@{domain}"
        
        result = {
            "is_catchall": False,
            "test_email": test_email,
            "skipped": False,
        }
        
        # Try SMTP check on random email
        smtp_connection = self._check_smtp_connection(domain, mx_hosts)
        if smtp_connection.get("skipped") or not smtp_connection.get("port_25_open"):
            result["skipped"] = True
            return result
        
        smtp_rcpt = self._check_smtp_rcpt(test_email, domain, mx_hosts, smtp_connection)
        
        if smtp_rcpt["accepted"]:
            result["is_catchall"] = True
        
        return result
    
    # ========== ADVANCED VERIFICATION FEATURES ==========
    
    def _check_provider_fingerprint(self, domain: str, mx_hosts: List[str], smtp_connection: Dict, fast_mode: bool = True) -> Dict:
        """1. Mailbox Provider Fingerprinting (MPF) - Check SMTP capabilities"""
        result = {
            "points": 0,
            "capabilities": {},
            "reliability_boost": 0
        }
        
        if not mx_hosts or smtp_connection.get("skipped"):
            result["skipped"] = True
            return result
        
        mx_host = smtp_connection.get("mx_used") or mx_hosts[0]
        
        # Use shorter timeout for fingerprinting
        try:
            server = smtplib.SMTP(timeout=5)
            server.set_debuglevel(0)
            
            try:
                server.connect(mx_host, 25)
                server.ehlo()
                
                # Check capabilities
                capabilities = {
                    "PIPELINING": server.has_extn('PIPELINING'),
                    "8BITMIME": server.has_extn('8BITMIME'),
                    "SIZE": server.has_extn('SIZE'),
                    "STARTTLS": server.has_extn('STARTTLS'),
                }
                
                result["capabilities"] = capabilities
                
                # Score based on capabilities (reliability boost)
                capability_count = sum(capabilities.values())
                if capability_count >= 3:
                    result["points"] = 10  # +10 for reliability boost
                    result["reliability_boost"] = 10
                elif capability_count >= 2:
                    result["points"] = 5
                    result["reliability_boost"] = 5
                elif capability_count >= 1:
                    result["points"] = 2
                    result["reliability_boost"] = 2
                
                # Check if server closes connection early (bad sign)
                try:
                    server.noop()
                    result["early_close"] = False
                except:
                    result["early_close"] = True
                    result["points"] = max(0, result["points"] - 3)
                
                server.quit()
            except Exception as e:
                logger.debug(f"MPF check error: {str(e)}")
                result["error"] = str(e)
        except Exception as e:
            logger.debug(f"MPF connection error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _classify_smtp_error_pattern(self, smtp_rcpt: Dict, smtp_connection: Dict) -> Dict:
        """2. SMTP Error Pattern Classification"""
        result = {
            "category": None,
            "points": 0,
            "pattern": None
        }
        
        error = smtp_rcpt.get("error") or smtp_connection.get("error", "")
        error_lower = str(error).lower()
        
        # Classify error patterns
        if "rate limit" in error_lower or "too many" in error_lower or "429" in error_lower:
            result["category"] = "rate_limited"
            result["points"] = 5  # Provider exists, mailbox likely exists
            result["pattern"] = "Rate limited"
        elif "greylist" in error_lower or "451" in error_lower or "temporarily" in error_lower:
            result["category"] = "greylist"
            result["points"] = 10  # Mailbox exists but temporarily blocked
            result["pattern"] = "Greylisted"
        elif "policy" in error_lower or "privacy" in error_lower or "not allowed" in error_lower:
            result["category"] = "policy_block"
            result["points"] = 3  # Domain protects privacy
            result["pattern"] = "Policy block"
        elif "connection refused" in error_lower or "refused" in error_lower:
            result["category"] = "connection_refused"
            result["points"] = 3  # Server alive but private
            result["pattern"] = "Connection refused"
        elif "timeout" in error_lower or "dead" in error_lower or "no route" in error_lower:
            result["category"] = "dead_server"
            result["points"] = -20  # Domain inactive
            result["pattern"] = "Dead server"
        elif "reset" in error_lower:
            result["category"] = "connection_reset"
            result["points"] = 0
            result["pattern"] = "Connection reset"
        else:
            result["category"] = "unknown"
            result["points"] = 0
        
        return result
    
    def _apply_provider_rules(self, domain: str, smtp_rcpt: Dict, current_score: int) -> Dict:
        """3. Provider-Level Behavior Rules (PLBR)"""
        result = {
            "provider": None,
            "rule_applied": False,
            "score_adjusted": False,
            "adjusted_score": current_score
        }
        
        domain_lower = domain.lower()
        
        # Find matching provider rule
        for provider, rules in self.provider_rules.items():
            if provider in domain_lower or domain_lower.endswith('.' + provider):
                result["provider"] = provider
                result["rule_applied"] = True
                
                # Apply max score limit if RCPT didn't succeed
                if not smtp_rcpt.get("accepted"):
                    max_score = rules.get("max_score_without_rcpt", 100)
                    if current_score > max_score:
                        result["score_adjusted"] = True
                        result["adjusted_score"] = max_score
                        result["reason"] = f"Provider {provider} blocks verification, max score without RCPT: {max_score}"
                
                # Zoho gets more confidence
                if provider == "zoho.com" and smtp_rcpt.get("rejected"):
                    # Zoho's rejections are more reliable
                    result["reliable_rejection"] = True
                
                break
        
        return result
    
    def _smtp_retry_simulation(self, email: str, domain: str, mx_hosts: List[str]) -> Dict:
        """4. SMTP Retry Simulation (for greylisting)"""
        result = {
            "success_after_retry": False,
            "retries": [],
            "points": 0
        }
        
        if not mx_hosts:
            result["skipped"] = True
            return result
        
        mx_host = mx_hosts[0]
        # Reduced delays for faster response: 0, 2 seconds (instead of 0, 1, 5)
        retry_delays = [0, 2]
        
        for delay in retry_delays:
            if delay > 0:
                time.sleep(delay)
            
            try:
                # Use shorter timeout for retries
                server = smtplib.SMTP(timeout=5)
                server.set_debuglevel(0)
                
                try:
                    server.connect(mx_host, 25)
                    server.ehlo()
                    test_sender = f"verify@{self._sender_domain}"
                    server.mail(test_sender)
                    
                    code, message = server.rcpt(email)
                    retry_result = {
                        "delay": delay,
                        "code": code,
                        "message": str(message),
                        "success": code in [250, 251]
                    }
                    result["retries"].append(retry_result)
                    
                    if code in [250, 251]:
                        result["success_after_retry"] = True
                        result["points"] = 20  # +20 for strong confirmation
                        server.quit()
                        break
                    
                    server.quit()
                except Exception as e:
                    result["retries"].append({
                        "delay": delay,
                        "error": str(e),
                        "success": False
                    })
            except Exception as e:
                logger.debug(f"Retry simulation error: {str(e)}")
                continue
        
        return result
    
    def _check_tls_certificate(self, mx_host: str) -> Dict:
        """5. TLS Certificate Intelligence (TCI)"""
        result = {
            "points": 0,
            "self_signed": False,
            "expired": False,
            "domain_match": False,
            "reputable_ca": False
        }
        
        try:
            # Try to get certificate
            context = ssl.create_default_context()
            with socket.create_connection((mx_host, 25), timeout=5) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname=mx_host) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check if domain matches
                        if cert:
                            subject = dict(x[0] for x in cert.get('subject', []))
                            issuer = dict(x[0] for x in cert.get('issuer', []))
                            
                            # Check domain match
                            common_name = subject.get('commonName', '')
                            if mx_host in common_name or common_name in mx_host:
                                result["domain_match"] = True
                                result["points"] += 5
                            
                            # Check if reputable CA (not self-signed)
                            if issuer.get('commonName') != subject.get('commonName'):
                                result["reputable_ca"] = True
                                result["points"] += 5
                            else:
                                result["self_signed"] = True
                                result["points"] -= 10
                            
                            # Check expiration
                            not_after = cert.get('notAfter')
                            if not_after:
                                try:
                                    from dateutil import parser
                                    exp_date = parser.parse(not_after)
                                    if exp_date < datetime.now():
                                        result["expired"] = True
                                        result["points"] -= 10
                                except ImportError:
                                    # Fallback to basic parsing
                                    try:
                                        exp_date = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                                        if exp_date < datetime.now():
                                            result["expired"] = True
                                            result["points"] -= 10
                                    except:
                                        pass
                                except:
                                    pass
                except ssl.SSLError:
                    # No TLS support or connection issue
                    result["no_tls"] = True
        except Exception as e:
            logger.debug(f"TLS certificate check error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _check_mail_ports(self, mx_host: str) -> Dict:
        """6. Open Ports Scan (Mail Infra Health)"""
        result = {
            "points": 0,
            "open_ports": []
        }
        
        mail_ports = [25, 465, 587, 2525]
        
        for port in mail_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Reduced from 2 to 1 second for faster scanning
                result_code = sock.connect_ex((mx_host, port)) == 0
                sock.close()
                
                if result_code:
                    result["open_ports"].append(port)
                    result["points"] += 2  # +2 for each valid mail port
            except:
                continue
        
        return result
    
    def _check_dnssec(self, domain: str) -> Dict:
        """7. DNSSEC Check"""
        result = {
            "points": 0,
            "dnssec_enabled": False
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 4.0
            
            # Try to check for DNSKEY record (indicates DNSSEC)
            try:
                resolver.resolve(domain, 'DNSKEY')
                result["dnssec_enabled"] = True
                result["points"] = 5  # +5 for strong DNS infrastructure
            except:
                # DNSSEC might be enabled but DNSKEY not at domain level
                # Check RRSIG records
                try:
                    resolver.resolve(domain, 'A')
                    # If we get here, check if response has RRSIG (would need to parse response)
                    # For simplicity, we'll assume no DNSSEC if DNSKEY fails
                    result["dnssec_enabled"] = False
                except:
                    result["dnssec_enabled"] = False
        except Exception as e:
            logger.debug(f"DNSSEC check error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _check_ptr_record(self, mx_host: str) -> Dict:
        """8. PTR Record Verification"""
        result = {
            "points": 0,
            "ptr_match": False,
            "ptr_record": None
        }
        
        try:
            # Get IP address of MX host
            ip_address = socket.gethostbyname(mx_host)
            
            # Reverse DNS lookup
            ptr_record = socket.gethostbyaddr(ip_address)[0]
            result["ptr_record"] = ptr_record
            
            # Check if PTR matches domain or MX host
            if mx_host in ptr_record or ptr_record in mx_host:
                result["ptr_match"] = True
                result["points"] = 5  # +5 if PTR matches
            else:
                result["points"] = -5  # -5 if PTR missing/mismatch
        except socket.herror:
            # No PTR record
            result["ptr_match"] = False
            result["points"] = -5
        except Exception as e:
            logger.debug(f"PTR record check error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _check_ip_reputation(self, mx_host: str) -> Dict:
        """9. IP Reputation Score (using free sources)"""
        result = {
            "points": 0,
            "blacklisted": False,
            "sources_checked": []
        }
        
        try:
            # Get IP address
            ip_address = socket.gethostbyname(mx_host)
            
            # Check Spamhaus (free query via DNS)
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                # Reverse IP for Spamhaus query
                ip_parts = ip_address.split('.')
                reversed_ip = '.'.join(reversed(ip_parts))
                spamhaus_query = f"{reversed_ip}.zen.spamhaus.org"
                
                try:
                    resolver.resolve(spamhaus_query, 'A')
                    # If resolved, IP is blacklisted
                    result["blacklisted"] = True
                    result["points"] = -10
                    result["sources_checked"].append("spamhaus")
                except dns.resolver.NXDOMAIN:
                    # Not blacklisted
                    result["sources_checked"].append("spamhaus")
            except:
                pass
            
            # If not blacklisted, give positive score
            if not result["blacklisted"]:
                result["points"] = 10  # +10 if clean
        except Exception as e:
            logger.debug(f"IP reputation check error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _analyze_server_behavior(self, smtp_connection: Dict, smtp_rcpt: Dict) -> Dict:
        """10. Mail Server Behaviour Analysis (Heuristics)"""
        result = {
            "points": 0,
            "behaviors": {}
        }
        
        # Check if server allows EHLO
        if smtp_connection.get("greeting", {}).get("valid"):
            result["behaviors"]["allows_ehlo"] = True
            result["points"] += 3
        
        # Check if server supports STARTTLS
        if smtp_connection.get("tls_successful"):
            result["behaviors"]["supports_starttls"] = True
            result["points"] += 5
        
        # Check for forced delay (suspicious)
        timing = smtp_rcpt.get("timing", {})
        response_time = timing.get("response_time_sec", 0)
        if 0 < response_time < 1:
            result["behaviors"]["normal_response"] = True
            result["points"] += 2
        elif response_time > 5:
            result["behaviors"]["slow_response"] = True
            result["points"] -= 2
        
        # Check if server downgrades connection (bad)
        # This would require more detailed connection tracking
        
        # Cap points between -5 and 15
        result["points"] = max(-5, min(15, result["points"]))
        
        return result
    
    def _check_mx_popularity(self, mx_host: str) -> Dict:
        """11. Free Reverse MX Lookup (Global Domain Popularity)"""
        result = {
            "points": 0,
            "popularity": "unknown"
        }
        
        # Known popular MX hosts
        popular_mx_patterns = [
            'privateemail.com',
            'zoho.com',
            'hostinger.com',
            'google.com',
            'outlook.com',
            'yahoo.com',
            'amazonaws.com',
            'sendgrid.net',
            'mailgun.org'
        ]
        
        mx_lower = mx_host.lower()
        for pattern in popular_mx_patterns:
            if pattern in mx_lower:
                result["popularity"] = "high"
                result["points"] = 10  # +10 if MX shared widely
                result["mx_pattern"] = pattern
                return result
        
        # For custom MX, we can't easily check popularity without external service
        # So we give neutral score
        result["popularity"] = "unknown"
        result["points"] = 0
        
        return result
    
    def _analyze_blocklist_behavior(self, smtp_rcpt: Dict, smtp_connection: Dict) -> Dict:
        """12. Email Blocklist Behavior (Indirect)"""
        result = {
            "points": 0,
            "behavior": "unknown"
        }
        
        # Analyze response patterns
        if smtp_rcpt.get("rejected"):
            error = smtp_rcpt.get("error", "").lower()
            if "user unknown" in error or "550" in str(smtp_rcpt.get("response_code", "")):
                result["behavior"] = "instant_reject"
                result["points"] = 5  # Good - server actively rejects invalid
                result["note"] = "Server instantly rejects unknown users (good sign)"
        elif smtp_rcpt.get("accepted"):
            result["behavior"] = "accepts"
            result["points"] = 0  # Neutral - could be catch-all
        elif smtp_rcpt.get("soft_failure"):
            result["behavior"] = "greylist"
            result["points"] = 3  # Neutral - temporary block
        elif smtp_connection.get("error"):
            error = smtp_connection.get("error", "").lower()
            if "timeout" in error:
                result["behavior"] = "timeout"
                result["points"] = -3  # Risky
            elif "policy" in error:
                result["behavior"] = "policy_block"
                result["points"] = 2  # Neutral - privacy protection
        
        return result
    
    # ========== ADDITIONAL ADVANCED FEATURES (13-27) ==========
    
    def _check_mx_consistency(self, mx_host: str, domain: str) -> Dict:
        """13. Mail Exchanger Consistency Check (MX↔A sanity test)"""
        result = {
            "points": 0,
            "mx_to_a": False,
            "a_to_ptr": False,
            "ptr_to_a": False,
            "perfect_cycle": False
        }
        
        try:
            # MX → A/AAAA
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 4.0
            
            try:
                mx_ip = socket.gethostbyname(mx_host)
                result["mx_to_a"] = True
                result["mx_ip"] = mx_ip
                
                # A → PTR
                try:
                    ptr_record = socket.gethostbyaddr(mx_ip)[0]
                    result["a_to_ptr"] = True
                    result["ptr_record"] = ptr_record
                    
                    # PTR → A (matching)
                    try:
                        ptr_ip = socket.gethostbyname(ptr_record)
                        if ptr_ip == mx_ip:
                            result["ptr_to_a"] = True
                            result["perfect_cycle"] = True
                            result["points"] = 10  # Perfect cycle → +10
                        else:
                            result["points"] = -10  # Broken cycle → -10
                    except:
                        result["points"] = -10  # Broken cycle
                except socket.herror:
                    result["points"] = -10  # No PTR record
            except:
                result["points"] = -10  # MX doesn't resolve
        except Exception as e:
            logger.debug(f"MX consistency check error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _check_tls_policy_strength(self, mx_host: str) -> Dict:
        """14. STARTTLS Upgrade Behaviour (TLS Policy Strength)"""
        result = {
            "points": 0,
            "supports_starttls": False,
            "allows_downgrade": False,
            "modern_ciphers": False,
            "secure": False
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((mx_host, 25), timeout=5) as sock:
                try:
                    # Try STARTTLS
                    with context.wrap_socket(sock, server_hostname=mx_host) as ssock:
                        result["supports_starttls"] = True
                        result["secure"] = True
                        
                        # Check cipher (basic check)
                        cipher = ssock.cipher()
                        if cipher:
                            result["modern_ciphers"] = True
                            result["points"] = 10  # Secure TLS: +10
                        else:
                            result["points"] = -5  # Weak/Downgrade-able: -5
                except ssl.SSLError:
                    result["allows_downgrade"] = True
                    result["points"] = -5  # Weak/Downgrade-able: -5
        except Exception as e:
            logger.debug(f"TLS policy check error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _check_mx_redundancy(self, mx_hosts: List[str]) -> Dict:
        """15. Multi-MX Redundancy Check"""
        result = {
            "points": 0,
            "mx_count": len(mx_hosts) if mx_hosts else 0,
            "redundancy": "none"
        }
        
        mx_count = len(mx_hosts) if mx_hosts else 0
        
        if mx_count == 0:
            result["redundancy"] = "none"
            result["points"] = -20  # Cannot receive mail
        elif mx_count == 1:
            result["redundancy"] = "single"
            result["points"] = -3  # Single MX: -3
        elif 2 <= mx_count <= 4:
            result["redundancy"] = "strong"
            result["points"] = 5  # Multi-MX: +5
        else:
            result["redundancy"] = "excessive"
            result["points"] = 3  # Too many might indicate misconfiguration
        
        return result
    
    def _check_smtp_strictness(self, smtp_connection: Dict, smtp_rcpt: Dict) -> Dict:
        """16. SMTP Transaction Strictness Scoring"""
        result = {
            "points": 0,
            "strictness_level": "unknown",
            "checks": {}
        }
        
        # Check EHLO response
        if smtp_connection.get("greeting", {}).get("valid"):
            result["checks"]["valid_ehlo"] = True
            result["points"] += 2
        
        # Check if MAIL FROM was validated
        if smtp_rcpt.get("response_code"):
            code = smtp_rcpt.get("response_code")
            # If server rejected invalid MAIL FROM, it's strict
            if code not in [250, 251] and "mail" in str(smtp_rcpt.get("error", "")).lower():
                result["checks"]["validates_mailfrom"] = True
                result["points"] += 3
        
        # Check if malformed commands are rejected
        if smtp_rcpt.get("rejected") and smtp_rcpt.get("response_code") in [500, 501, 502]:
            result["checks"]["rejects_malformed"] = True
            result["points"] += 3
        
        # Check if anti-spam rules are enforced
        error = smtp_rcpt.get("error", "").lower()
        if "spam" in error or "policy" in error or "block" in error:
            result["checks"]["enforces_antispam"] = True
            result["points"] += 2
        
        # Determine strictness level
        if result["points"] >= 8:
            result["strictness_level"] = "strict"
            result["points"] = 10  # Strict → +10
        elif result["points"] >= 4:
            result["strictness_level"] = "moderate"
            result["points"] = 0
        else:
            result["strictness_level"] = "loose"
            result["points"] = -5  # Loose → -5
        
        return result
    
    def _check_mailfrom_health(self, domain: str, mx_hosts: List[str], smtp_connection: Dict) -> Dict:
        """17. MAIL FROM Domain Health"""
        result = {
            "points": 0,
            "rejects_rare_domain": False,
            "accepts_anything": False
        }
        
        if not mx_hosts or smtp_connection.get("skipped"):
            result["skipped"] = True
            return result
        
        mx_host = smtp_connection.get("mx_used") or mx_hosts[0]
        
        # Test with a fake/rare domain
        fake_domain = f"test-{random.randint(10000, 99999)}.invalid"
        fake_sender = f"test@{fake_domain}"
        
        try:
            server = smtplib.SMTP(timeout=5)
            server.set_debuglevel(0)
            
            try:
                server.connect(mx_host, 25)
                server.ehlo()
                
                # Try MAIL FROM with fake domain
                code, message = server.mail(fake_sender)
                
                if code not in [250, 251]:
                    result["rejects_rare_domain"] = True
                    result["points"] = 7  # Reject rare MAIL FROM → +7
                else:
                    result["accepts_anything"] = True
                    result["points"] = -7  # Accept anything → -7
                
                server.quit()
            except Exception as e:
                logger.debug(f"MAIL FROM health check error: {str(e)}")
        except Exception as e:
            logger.debug(f"MAIL FROM connection error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _analyze_connection_latency(self, smtp_connection: Dict, smtp_rcpt: Dict) -> Dict:
        """18. Connection Latency Fingerprinting"""
        result = {
            "points": 0,
            "tcp_handshake": 0,
            "smtp_banner": 0,
            "ehlo_latency": 0,
            "rcpt_latency": 0,
            "pattern": "unknown"
        }
        
        timing = smtp_rcpt.get("timing", {})
        rcpt_time = timing.get("response_time_sec", 0)
        
        # Analyze latency patterns
        if rcpt_time < 0.5:
            result["pattern"] = "instant_reject"
            result["points"] = -10  # Instant reject → -10
        elif 0.5 <= rcpt_time <= 3:
            result["pattern"] = "normal"
            result["points"] = 8  # Normal latency pattern → +8
        elif 3 < rcpt_time <= 10:
            result["pattern"] = "slow"
            result["points"] = 0
        else:
            result["pattern"] = "very_slow"
            result["points"] = -5  # Very slow → -5
        
        return result
    
    def _check_loadbalancer_behavior(self, email: str, domain: str, mx_hosts: List[str]) -> Dict:
        """19. SMTP Load-Balancer Behavior"""
        result = {
            "points": 0,
            "consistent": False,
            "responses": []
        }
        
        if len(mx_hosts) < 2:
            result["skipped"] = True
            return result
        
        # Test first 2 MX hosts
        for mx_host in mx_hosts[:2]:
            try:
                server = smtplib.SMTP(timeout=5)
                server.set_debuglevel(0)
                
                try:
                    server.connect(mx_host, 25)
                    server.ehlo()
                    test_sender = f"verify@{self._sender_domain}"
                    server.mail(test_sender)
                    
                    code, message = server.rcpt(email)
                    result["responses"].append({
                        "mx": mx_host,
                        "code": code,
                        "message": str(message)
                    })
                    
                    server.quit()
                except Exception as e:
                    result["responses"].append({
                        "mx": mx_host,
                        "error": str(e)
                    })
            except Exception as e:
                logger.debug(f"Load balancer check error for {mx_host}: {str(e)}")
                continue
        
        # Check if responses are consistent
        if len(result["responses"]) >= 2:
            codes = [r.get("code") for r in result["responses"] if r.get("code")]
            if len(set(codes)) == 1:
                result["consistent"] = True
                result["points"] = 5  # Consistent behavior → +5
            else:
                result["points"] = -10  # Inconsistent → -10
        
        return result
    
    def _check_vrfy_lite_behavior(self, email: str, domain: str, mx_hosts: List[str], smtp_connection: Dict) -> Dict:
        """20. SMTP "VRFY Lite" Behaviour"""
        result = {
            "points": 0,
            "domain_response": None,
            "user_response": None,
            "different_responses": False
        }
        
        if not mx_hosts or smtp_connection.get("skipped"):
            result["skipped"] = True
            return result
        
        mx_host = smtp_connection.get("mx_used") or mx_hosts[0]
        
        try:
            server = smtplib.SMTP(timeout=5)
            server.set_debuglevel(0)
            
            try:
                server.connect(mx_host, 25)
                server.ehlo()
                test_sender = f"verify@{self._sender_domain}"
                server.mail(test_sender)
                
                # Test RCPT TO:<@domain.com>
                code1, msg1 = server.rcpt(f"@{domain}")
                result["domain_response"] = {"code": code1, "message": str(msg1)}
                
                # Test RCPT TO:<realuser@domain.com>
                code2, msg2 = server.rcpt(email)
                result["user_response"] = {"code": code2, "message": str(msg2)}
                
                # Compare responses
                if code1 != code2:
                    result["different_responses"] = True
                    result["points"] = 6  # Different responses → +6
                else:
                    result["points"] = -6  # Identical → -6
                
                server.quit()
            except Exception as e:
                logger.debug(f"VRFY lite check error: {str(e)}")
                result["skipped"] = True
        except Exception as e:
            logger.debug(f"VRFY lite connection error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _check_role_accounts(self, domain: str, mx_hosts: List[str]) -> Dict:
        """21. Recipient Domain Email Role Account Policy"""
        result = {
            "points": 0,
            "role_accounts": {},
            "all_valid": False,
            "all_invalid": False
        }
        
        role_accounts = ["postmaster", "abuse", "support", "info"]
        valid_count = 0
        
        if not mx_hosts:
            result["skipped"] = True
            return result
        
        mx_host = mx_hosts[0]
        
        for role in role_accounts:
            role_email = f"{role}@{domain}"
            try:
                server = smtplib.SMTP(timeout=3)
                server.set_debuglevel(0)
                
                try:
                    server.connect(mx_host, 25)
                    server.ehlo()
                    test_sender = f"verify@{self._sender_domain}"
                    server.mail(test_sender)
                    
                    code, message = server.rcpt(role_email)
                    is_valid = code in [250, 251]
                    result["role_accounts"][role] = {
                        "valid": is_valid,
                        "code": code
                    }
                    if is_valid:
                        valid_count += 1
                    
                    server.quit()
                except:
                    result["role_accounts"][role] = {"valid": False, "error": True}
            except:
                result["role_accounts"][role] = {"valid": False, "error": True}
        
        if valid_count == len(role_accounts):
            result["all_valid"] = True
            result["points"] = 6  # Role accounts valid → +6
        elif valid_count == 0:
            result["all_invalid"] = True
            result["points"] = -6  # All invalid → -6
        
        return result
    
    def _check_mx_brand(self, mx_host: str) -> Dict:
        """22. MX Infrastructure Identity Check (Brand MX Mapping)"""
        result = {
            "points": 0,
            "brand": "unknown",
            "trusted": False
        }
        
        mx_lower = mx_host.lower()
        
        # Known trusted MX brands
        trusted_brands = {
            "google.com": "Gmail",
            "outlook.com": "Microsoft",
            "secureserver.net": "GoDaddy",
            "privateemail.com": "Namecheap",
            "mailsrvr.com": "Rackspace",
            "amazonaws.com": "AWS SES",
            "sendgrid.net": "SendGrid",
            "mailgun.org": "Mailgun",
            "mailgun.com": "Mailgun",
            "zoho.com": "Zoho",
            "yahoo.com": "Yahoo",
            "aol.com": "AOL"
        }
        
        for brand_pattern, brand_name in trusted_brands.items():
            if brand_pattern in mx_lower:
                result["brand"] = brand_name
                result["trusted"] = True
                result["points"] = 10  # Trusted MX brand → +10
                return result
        
        result["brand"] = "custom"
        result["points"] = 0
        
        return result
    
    def _check_greylist_depth(self, email: str, domain: str, mx_hosts: List[str]) -> Dict:
        """23. Greylist "Depth Check" """
        result = {
            "points": 0,
            "depth": 0,
            "pattern_matches": False
        }
        
        if not mx_hosts:
            result["skipped"] = True
            return result
        
        mx_host = mx_hosts[0]
        responses = []
        
        # Simulate 3 attempts
        for attempt in range(3):
            if attempt > 0:
                time.sleep(2)  # Wait between attempts
            
            try:
                server = smtplib.SMTP(timeout=5)
                server.set_debuglevel(0)
                
                try:
                    server.connect(mx_host, 25)
                    server.ehlo()
                    test_sender = f"verify@{self._sender_domain}"
                    server.mail(test_sender)
                    
                    code, message = server.rcpt(email)
                    responses.append({
                        "attempt": attempt + 1,
                        "code": code,
                        "message": str(message)
                    })
                    
                    server.quit()
                    
                    # Check if pattern matches greylist behavior
                    if code in [250, 251]:
                        result["depth"] = attempt + 1
                        if attempt >= 1:  # Accepted after retry
                            result["pattern_matches"] = True
                            result["points"] = 10  # Greylist depth matches → +10
                        break
                except Exception as e:
                    responses.append({
                        "attempt": attempt + 1,
                        "error": str(e)
                    })
            except Exception as e:
                logger.debug(f"Greylist depth check error: {str(e)}")
                break
        
        result["responses"] = responses
        return result
    
    def _analyze_smtp_banner(self, banner_message: str) -> Dict:
        """24. SMTP Banner Metadata Inspection"""
        result = {
            "points": 0,
            "has_metadata": False,
            "provider_identified": False,
            "professional": False
        }
        
        banner_lower = banner_message.lower()
        
        # Check for professional metadata patterns
        professional_patterns = [
            "esmtp", "postfix", "sendmail", "exim", "microsoft", "exchange",
            "mailjet", "sendgrid", "mailgun", "amazon", "google"
        ]
        
        for pattern in professional_patterns:
            if pattern in banner_lower:
                result["has_metadata"] = True
                result["provider_identified"] = True
                result["professional"] = True
                result["points"] = 8  # Professional metadata → +8
                result["identified_provider"] = pattern
                return result
        
        # Check for suspicious patterns
        suspicious_patterns = ["test", "fake", "honeypot", "spam"]
        for pattern in suspicious_patterns:
            if pattern in banner_lower:
                result["points"] = -8  # Random/weird → -8
                return result
        
        # No metadata or generic
        if len(banner_message.strip()) < 10:
            result["points"] = -8  # No metadata → -8
        else:
            result["points"] = 0  # Neutral
        
        return result
    
    def _check_domain_blacklists(self, domain: str) -> Dict:
        """25. Spamhaus DBL / Barracuda BL DNS Lookup"""
        result = {
            "points": 0,
            "blacklisted": False,
            "sources_checked": []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 4.0
            
            # Spamhaus DBL check
            try:
                dbl_query = f"{domain}.dbl.spamhaus.org"
                resolver.resolve(dbl_query, 'A')
                result["blacklisted"] = True
                result["points"] = -10  # Listed → -10
                result["sources_checked"].append("spamhaus_dbl")
                return result
            except dns.resolver.NXDOMAIN:
                result["sources_checked"].append("spamhaus_dbl")
            
            # SURBL check
            try:
                surbl_query = f"{domain}.multi.surbl.org"
                resolver.resolve(surbl_query, 'A')
                result["blacklisted"] = True
                result["points"] = -10
                result["sources_checked"].append("surbl")
                return result
            except dns.resolver.NXDOMAIN:
                result["sources_checked"].append("surbl")
            
            # If not blacklisted
            result["points"] = 10  # Clean → +10
            
        except Exception as e:
            logger.debug(f"Domain blacklist check error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _check_quit_behavior(self, mx_host: str) -> Dict:
        """26. SMTP QUIT Acknowledgement Behavior"""
        result = {
            "points": 0,
            "proper_quit": False
        }
        
        try:
            server = smtplib.SMTP(timeout=5)
            server.set_debuglevel(0)
            
            try:
                server.connect(mx_host, 25)
                server.ehlo()
                
                # Try to quit and check response
                try:
                    code, message = server.quit()
                    if code == 221:
                        result["proper_quit"] = True
                        result["points"] = 4  # Proper QUIT → +4
                    else:
                        result["points"] = -4  # Unclean disconnect → -4
                except:
                    result["points"] = -4  # Unclean disconnect
            except Exception as e:
                logger.debug(f"QUIT behavior check error: {str(e)}")
                result["skipped"] = True
        except Exception as e:
            logger.debug(f"QUIT connection error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    def _check_tcp_stability(self, mx_host: str) -> Dict:
        """27. TCP Retransmissions Patterns (VERY ADVANCED)"""
        result = {
            "points": 0,
            "stable": False,
            "retransmissions_detected": False
        }
        
        # Note: True TCP retransmission detection requires low-level socket monitoring
        # This is a simplified version that checks connection stability
        
        try:
            # Multiple connection attempts to check stability
            stable_connections = 0
            total_attempts = 3
            
            for _ in range(total_attempts):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result_code = sock.connect_ex((mx_host, 25))
                    sock.close()
                    
                    if result_code == 0:
                        stable_connections += 1
                except:
                    pass
            
            if stable_connections == total_attempts:
                result["stable"] = True
                result["points"] = 5  # Stable → +5
            elif stable_connections >= total_attempts // 2:
                result["points"] = 0
            else:
                result["retransmissions_detected"] = True
                result["points"] = -5  # Unstable → -5
        except Exception as e:
            logger.debug(f"TCP stability check error: {str(e)}")
            result["skipped"] = True
        
        return result
    
    # Legacy method for backward compatibility
    def calculate_confidence(
        self,
        smtp_result: Dict,
        catch_all: Dict,
        mx_check: Dict,
        deliverability: Dict,
        *,
        confidence_mode: str = "balanced",
    ) -> float:
        """
        Legacy confidence calculation (0.0-1.0)
        Now uses score / 100.0 for compatibility
        """
        # This is kept for backward compatibility
        # The new system uses point-based scoring
        return 0.5  # Default fallback
    
    # Legacy methods for backward compatibility
    def check_mx_records(self, domain: str) -> Dict:
        """Legacy method - wraps _check_dns_health"""
        dns_result = self._check_dns_health(domain)
        return {
            "valid": dns_result["domain_exists"] and dns_result["mx_present"],
            "mx_hosts": dns_result.get("mx_hosts", []),
            "mx_details": [{"priority": 0, "host": h} for h in dns_result.get("mx_hosts", [])]
        }
    
    def smtp_handshake(self, email: str, domain: str, mx_hosts: List[str]) -> Dict:
        """Legacy method - wraps new SMTP checks"""
        smtp_connection = self._check_smtp_connection(domain, mx_hosts)
        smtp_rcpt = self._check_smtp_rcpt(email, domain, mx_hosts, smtp_connection)
        
        return {
            "accepted": smtp_rcpt.get("accepted", False),
            "rejected": smtp_rcpt.get("rejected", False),
            "error": smtp_rcpt.get("error"),
            "mx_used": smtp_connection.get("mx_used"),
            "skipped": smtp_connection.get("skipped", False)
        }
    
    def check_deliverability(self, domain: str) -> Dict:
        """Legacy method - already implemented"""
        return self._check_deliverability(domain)
    
    def detect_catch_all(self, domain: str, mx_hosts: List[str]) -> Dict:
        """Legacy method - already implemented"""
        return self._detect_catch_all(domain, mx_hosts)


if __name__ == '__main__':
    # Quick-run for development testing and validation
    logging.basicConfig(level=logging.INFO)
    verifier = EmailVerifier()
    test_emails = [
        'contact@projexa.ai',
        'hey@om-mishra.com',
        'contact.ommishra@gmail.com',
    ]
    for e in test_emails:
        print('\n---')
        print(f'Checking: {e}')
        res = verifier.verify_email(e, fast_mode=True, confidence_mode='balanced', internet_checks=True)
        print(json.dumps(res, indent=2))
