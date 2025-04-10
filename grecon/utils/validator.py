#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Input validation module for GRecon.

This module provides functions to validate user input and ensure
that targets and options are properly formatted.
"""

import ipaddress
import re
import socket
import os
import subprocess
from typing import Union, Tuple, Optional, List, Dict

def is_valid_ip(ip: str) -> bool:
    """
    Check if the provided string is a valid IP address.
    
    Args:
        ip: IP address to validate
    
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_hostname(hostname: str) -> bool:
    """
    Check if the provided string is a valid hostname.
    
    Args:
        hostname: Hostname to validate
    
    Returns:
        True if valid, False otherwise
    """
    if len(hostname) > 255:
        return False
    
    hostname_regex = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    
    return hostname_regex.match(hostname) is not None

def is_valid_port_range(port_range: str) -> bool:
    """
    Check if the provided string is a valid port range.
    
    Args:
        port_range: Port range to validate (e.g., "1-1000" or "80,443,8080")
    
    Returns:
        True if valid, False otherwise
    """
    # Check for comma-separated list of ports
    if "," in port_range:
        ports = port_range.split(",")
        return all(p.strip().isdigit() and 1 <= int(p.strip()) <= 65535 for p in ports)
    
    # Check for range format (start-end)
    elif "-" in port_range:
        try:
            start, end = port_range.split("-")
            return (start.strip().isdigit() and end.strip().isdigit() and
                    1 <= int(start.strip()) <= 65535 and
                    1 <= int(end.strip()) <= 65535 and
                    int(start.strip()) <= int(end.strip()))
        except ValueError:
            return False
    
    # Check for single port
    else:
        return port_range.strip().isdigit() and 1 <= int(port_range.strip()) <= 65535

def parse_port_range(port_range: str) -> Tuple[int, int]:
    """
    Parse a port range string into start and end port numbers.
    
    Args:
        port_range: Port range string (e.g., "1-1000" or "80")
    
    Returns:
        Tuple of (start_port, end_port)
    
    Raises:
        ValueError: If the port range is invalid
    """
    if not is_valid_port_range(port_range):
        raise ValueError(f"Invalid port range: {port_range}")
    
    if "-" in port_range:
        start, end = port_range.split("-")
        return int(start.strip()), int(end.strip())
    else:
        port = int(port_range.strip())
        return port, port

def resolve_target(target: str) -> Tuple[str, Optional[str]]:
    """
    Resolve a target hostname to an IP address.
    
    Args:
        target: Target hostname or IP address
    
    Returns:
        Tuple of (target, resolved_ip)
        If target is already an IP, resolved_ip will be the same
        If target cannot be resolved, resolved_ip will be None
    
    Raises:
        ValueError: If the target is not a valid hostname or IP address
    """
    if is_valid_ip(target):
        return target, target
    
    if not is_valid_hostname(target):
        raise ValueError(f"Invalid target: {target}. Not a valid hostname or IP address.")
    
    try:
        ip = socket.gethostbyname(target)
        return target, ip
    except socket.gaierror:
        return target, None

def is_root() -> bool:
    """
    Check if the script is running with root privileges.
    
    Returns:
        True if running as root, False otherwise
    """
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False

def check_required_tools() -> Dict[str, bool]:
    """
    Check if required external tools are installed.
    
    Returns:
        Dictionary mapping tool names to availability status
    """
    tools = {
        "nmap": False
    }
    
    for tool in tools:
        try:
            subprocess.run(
                [tool, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            tools[tool] = True
        except (subprocess.SubprocessError, FileNotFoundError):
            tools[tool] = False
    
    return tools

def validate_timeout(timeout: Union[int, float, str]) -> float:
    """
    Validate and convert timeout value.
    
    Args:
        timeout: Timeout value in seconds
    
    Returns:
        Timeout as float
    
    Raises:
        ValueError: If timeout is not a positive number
    """
    try:
        timeout_float = float(timeout)
        if timeout_float <= 0:
            raise ValueError("Timeout must be a positive number")
        return timeout_float
    except (ValueError, TypeError):
        raise ValueError(f"Invalid timeout value: {timeout}")

def validate_thread_count(thread_count: Union[int, str]) -> int:
    """
    Validate and convert thread count value.
    
    Args:
        thread_count: Number of threads to use
    
    Returns:
        Thread count as integer
    
    Raises:
        ValueError: If thread count is not a positive integer
    """
    try:
        count = int(thread_count)
        if count <= 0:
            raise ValueError("Thread count must be a positive integer")
        
        # Warn if thread count is very high but don't block it
        if count > 500:
            print("Warning: Using a very high thread count may cause issues")
        
        return count
    except (ValueError, TypeError):
        raise ValueError(f"Invalid thread count: {thread_count}")
