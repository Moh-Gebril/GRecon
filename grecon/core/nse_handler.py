#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nmap Scripting Engine (NSE) handler module for GRecon.

This module provides functionality to select and run appropriate NSE scripts
based on discovered services and open ports.
"""

import os
import subprocess
import logging
import shlex
from typing import List, Dict, Optional, Any, Set, Tuple
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class NseHandler:
    """
    Handles NSE script selection and execution based on port scan results.
    
    Attributes:
        target (str): Target IP address or hostname
        open_ports (List[int]): List of open ports discovered during initial scan
        service_map (Dict[int, str]): Mapping of ports to detected services
        output_dir (str): Directory to store NSE script output files
    """
    
    # Standard NSE script categories
    NSE_CATEGORIES = [
        "auth", "broadcast", "brute", "default", "discovery", 
        "dos", "exploit", "external", "fuzzer", "intrusive", 
        "malware", "safe", "version", "vuln"
    ]
    
    # Common services and recommended NSE scripts
    SERVICE_SCRIPT_MAP = {
        "http": ["http-enum", "http-headers", "http-methods", "http-title", "http-vuln-*"],
        "https": ["ssl-enum-ciphers", "ssl-heartbleed", "http-enum", "http-headers"],
        "ssh": ["ssh-auth-methods", "ssh-hostkey", "ssh-brute"],
        "ftp": ["ftp-anon", "ftp-brute", "ftp-vuln-*"],
        "smb": ["smb-enum-shares", "smb-enum-users", "smb-os-discovery", "smb-vuln-*"],
        "mysql": ["mysql-databases", "mysql-empty-password", "mysql-info"],
        "mssql": ["ms-sql-info", "ms-sql-empty-password", "ms-sql-xp-cmdshell"],
        "rdp": ["rdp-enum-encryption", "rdp-ntlm-info"],
        "smtp": ["smtp-commands", "smtp-enum-users", "smtp-open-relay"],
        "dns": ["dns-recursion", "dns-service-discovery", "dns-zone-transfer"],
        "telnet": ["telnet-encryption", "telnet-brute"],
        "snmp": ["snmp-info", "snmp-brute", "snmp-interfaces"],
        "ajp": ["ajp-headers", "ajp-request"],
        "default": ["banner", "version"]
    }
    
    def __init__(self, 
                 target: str, 
                 open_ports: List[int], 
                 service_map: Optional[Dict[int, str]] = None,
                 output_dir: Optional[str] = None):
        """
        Initialize the NSE handler with scan configuration.
        
        Args:
            target: Target IP address or hostname
            open_ports: List of open ports discovered during initial scan
            service_map: Mapping of ports to detected services
            output_dir: Directory to store NSE output files
        """
        self.target = target
        self.open_ports = open_ports
        self.service_map = service_map or {}
        self.output_dir = output_dir or target
    
    def get_service_scripts(self, service: str) -> List[str]:
        """
        Get recommended NSE scripts for a specific service.
        Handles AJP (Apache JServ Protocol) by service name, following the same pattern as other services.

        Args:
            service: Service name (e.g., http, ssh, ftp)
        Returns:
            List of recommended NSE scripts for the service
        """
        service = service.lower()
        # Standard mapping, including AJP if detected by name
        scripts = self.SERVICE_SCRIPT_MAP.get(service, [])
        if not scripts:
            scripts = self.SERVICE_SCRIPT_MAP["default"]
        return scripts
    
    def generate_script_command(self, 
                               category: str = None, 
                               scripts: List[str] = None,
                               port: int = None,
                               service: str = None, 
                               safety_level: str = "safe") -> str:
        """
        Generate an Nmap command with NSE scripts based on category or script list.
        
        Args:
            category: NSE script category to use
            scripts: List of specific NSE scripts to run
            port: Specific port to scan (if None, all discovered ports are scanned)
            service: Service name for output file naming
            safety_level: Safety level of scripts to run (safe, default, intrusive, all)
        
        Returns:
            Formatted Nmap command with NSE script options
        """
        if not self.open_ports and not port:
            return f"nmap -p- -T4 -Pn {self.target}"
        
        # Create a port string - either for a specific port or all discovered ports
        if port:
            port_str = str(port)
        else:
            port_str = ",".join(map(str, self.open_ports))
        
        # Generate a descriptive output base filename
        if port and service:
            output_base = os.path.join(self.output_dir, f"nse_{service}_{port}")
        elif category:
            output_base = os.path.join(self.output_dir, f"nse_{category}")
        else:
            output_base = os.path.join(self.output_dir, f"nse_custom")
        
        # Define command based on provided parameters
        if category and category in self.NSE_CATEGORIES:
            script_part = f"--script={category}"
        elif scripts:
            script_part = f"--script={','.join(scripts)}"
        else:
            # Use safety level to determine script selection
            if safety_level == "safe":
                script_part = "--script=safe"
            elif safety_level == "default":
                script_part = "--script=default"
            elif safety_level == "intrusive":
                script_part = "--script='not intrusive and not dos and not brute'"
            elif safety_level == "all":
                script_part = "--script=all"
            else:
                script_part = "--script=safe"
        
        command = f"nmap -p{port_str} {script_part} -sV -T4 -Pn -oA {output_base} {self.target}"
        return command
    
    def suggest_scripts_by_service(self) -> Dict[str, List[str]]:
        """
        Suggest NSE scripts based on detected services.
        
        Returns:
            Dictionary mapping services to recommended scripts
        """
        suggestions = {}
        
        for port, service in self.service_map.items():
            if service not in suggestions:
                suggestions[service] = self.get_service_scripts(service)
        
        return suggestions
    
    def run_service_based_scripts(self, safety_level: str = "safe") -> Dict[str, Any]:
        """
        Run NSE scripts based on detected services.
        
        Args:
            safety_level: Safety level of scripts to run
        
        Returns:
            Dictionary containing scan results
        """
        results = {}
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # If service map is empty, run basic scripts on all ports
        if not self.service_map:
            logger.warning("No service information available, running basic scripts on all ports")
            command = self.generate_script_command(scripts=self.SERVICE_SCRIPT_MAP["default"])
            try:
                result = subprocess.run(
                    shlex.split(command),
                    capture_output=True,
                    text=True,
                    check=True
                )
                results["default_scan"] = {
                    "success": True,
                    "command": command,
                    "output": result.stdout,
                    "ports": self.open_ports
                }
            except subprocess.CalledProcessError as e:
                results["default_scan"] = {
                    "success": False,
                    "command": command,
                    "error": e.stderr,
                    "ports": self.open_ports
                }
            return results
        
        # Run service-specific scripts for each port
        for port, service in self.service_map.items():
            # Normalize service name for display and file naming
            service_clean = ''.join(c if c.isalnum() else '_' for c in service.lower())

            # Get recommended scripts for this service
            scripts = self.get_service_scripts(service)

            # Filter scripts based on safety level
            if safety_level == "safe":
                scripts = [s for s in scripts if "brute" not in s and "dos" not in s]
            elif safety_level == "default":
                scripts = [s for s in scripts if "dos" not in s]

            if scripts:
                # Generate a descriptive command with specific port and service
                command = self.generate_script_command(scripts=scripts, port=port, service=service_clean)
                logger.info(f"Running NSE scripts for {service} on port {port}: {command}")

                try:
                    # Execute the Nmap command
                    result = subprocess.run(
                        shlex.split(command),
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    # Use a descriptive key that shows both service and port
                    key = f"{service_clean}_{port}"
                    results[key] = {
                        "success": True,
                        "command": command,
                        "output": result.stdout,
                        "port": port,
                        "service": service,
                        "scripts": scripts
                    }
                except subprocess.CalledProcessError as e:
                    key = f"{service_clean}_{port}"
                    results[key] = {
                        "success": False,
                        "command": command,
                        "error": e.stderr,
                        "port": port,
                        "service": service,
                        "scripts": scripts
                    }
                    logger.error(f"NSE scripts for {service} on port {port} failed: {e}")

        return results
    
    def parse_nmap_xml(self, xml_file: str) -> Dict[int, str]:
        """
        Parse Nmap XML output to extract service information.
        
        Args:
            xml_file: Path to Nmap XML output file
        
        Returns:
            Dictionary mapping ports to service names
        """
        service_map = {}
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall(".//host"):
                for port in host.findall(".//port"):
                    port_num = int(port.get("portid"))
                    service = port.find("service")
                    
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        service_map[port_num] = service_name
        except (ET.ParseError, FileNotFoundError) as e:
            logger.error(f"Error parsing Nmap XML file: {e}")
        
        return service_map
    
    def update_service_map_from_xml(self, xml_file: str) -> None:
        """
        Update the service map from Nmap XML output.
        
        Args:
            xml_file: Path to Nmap XML output file
        """
        new_service_map = self.parse_nmap_xml(xml_file)
        self.service_map.update(new_service_map)
    
    @classmethod
    def get_available_script_categories(cls) -> Dict[str, str]:
        """
        Get available NSE script categories with descriptions.
        
        Returns:
            Dictionary mapping category names to descriptions
        """
        return {
            "auth": "Authentication related scripts",
            "broadcast": "Scripts that broadcast on the local network",
            "brute": "Brute force attack scripts",
            "default": "Default scripts run with -sC option",
            "discovery": "Host and service discovery scripts",
            "dos": "Denial of service scripts",
            "exploit": "Exploit scripts",
            "external": "Scripts that rely on external resources",
            "fuzzer": "Scripts that perform fuzzing",
            "intrusive": "Scripts that might crash services or be intensive",
            "malware": "Scripts that check for malware",
            "safe": "Safe scripts that won't crash services",
            "version": "Version detection scripts",
            "vuln": "Vulnerability assessment scripts"
        }
