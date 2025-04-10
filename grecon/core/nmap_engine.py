#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nmap integration module for GRecon.

This module provides functionality to generate and execute Nmap commands
based on port scanning results.
"""

import os
import subprocess
import logging
import shlex
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class NmapEngine:
    """
    Provides Nmap scanning capabilities integrated with GRecon port scanning results.
    
    Attributes:
        target (str): Target IP address or hostname
        open_ports (List[int]): List of open ports discovered during initial scan
        output_dir (str): Directory to store Nmap output files
    """
    
    def __init__(self, target: str, open_ports: List[int], output_dir: Optional[str] = None):
        """
        Initialize the Nmap engine with scan configuration.
        
        Args:
            target: Target IP address or hostname
            open_ports: List of open ports to scan with Nmap
            output_dir: Directory to store Nmap output files (default: target IP/hostname)
        """
        self.target = target
        self.open_ports = open_ports
        self.output_dir = output_dir or target
        
        # Check if Nmap is installed
        try:
            subprocess.run(
                ["nmap", "--version"], 
                capture_output=True, 
                check=True
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("Nmap not found or not executable. Please install Nmap.")
    
    def generate_command(self, scan_type: str = "default") -> str:
        """
        Generate an appropriate Nmap command based on scan type and discovered ports.
        
        Args:
            scan_type: Type of scan to perform (default, quick, comprehensive, or stealth)
        
        Returns:
            Formatted Nmap command string
        
        Raises:
            ValueError: If an invalid scan type is provided
        """
        if not self.open_ports:
            return f"nmap -p- -T4 -Pn {self.target}"
        
        port_str = ",".join(map(str, self.open_ports))
        output_base = os.path.join(self.output_dir, f"nmap_{scan_type}")
        
        scan_types = {
            "default": f"nmap -p{port_str} -sV -sC -T4 -Pn -oA {output_base} {self.target}",
            "quick": f"nmap -p{port_str} -T4 -Pn -oA {output_base} {self.target}",
            "comprehensive": f"nmap -p{port_str} -sV -sC -A -T4 -Pn -oA {output_base} {self.target}",
            "stealth": f"nmap -p{port_str} -sS -sV -T2 -Pn -oA {output_base} {self.target}",
            "udp": f"nmap -p{port_str} -sU -T4 -Pn -oA {output_base}_udp {self.target}",
            "all": f"nmap -p- -sV -sC -T4 -Pn -oA {output_base}_all {self.target}"
        }
        
        if scan_type not in scan_types:
            raise ValueError(f"Invalid scan type: {scan_type}. Available types: {', '.join(scan_types.keys())}")
        
        return scan_types[scan_type]
    
    def run_scan(self, scan_type: str = "default") -> Tuple[bool, str, str]:
        """
        Execute the Nmap scan based on discovered ports.
        
        Args:
            scan_type: Type of scan to perform
        
        Returns:
            Tuple containing success status, command executed, and output
        """
        command = self.generate_command(scan_type)
        logger.info(f"Executing Nmap scan: {command}")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        start_time = datetime.now()
        try:
            # Execute the Nmap command
            result = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                check=True
            )
            success = True
            output = result.stdout
            logger.info(f"Nmap scan completed successfully in {datetime.now() - start_time}")
        except subprocess.CalledProcessError as e:
            success = False
            output = f"Error: {e.stderr}"
            logger.error(f"Nmap scan failed: {e}")
        
        return success, command, output
    
    def get_scan_suggestions(self) -> Dict[str, str]:
        """
        Get suggested Nmap scan commands for different types of scans.
        
        Returns:
            Dictionary of scan types and their corresponding Nmap commands
        """
        return {
            "Default": self.generate_command("default"),
            "Quick": self.generate_command("quick"),
            "Comprehensive": self.generate_command("comprehensive"),
            "Stealth": self.generate_command("stealth"),
            "UDP": self.generate_command("udp"),
            "All Ports": self.generate_command("all")
        }

    def get_output_files(self) -> Dict[str, str]:
        """
        Get paths to Nmap output files.
        
        Returns:
            Dictionary of output file types and their paths
        """
        base_file = os.path.join(self.output_dir, "nmap_default")
        return {
            "XML": f"{base_file}.xml",
            "Grepable": f"{base_file}.gnmap",
            "Normal": f"{base_file}.nmap"
        }

def is_nmap_installed() -> bool:
    """
    Check if Nmap is installed and available on the system.
    
    Returns:
        True if Nmap is installed, False otherwise
    """
    try:
        subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            check=True
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
