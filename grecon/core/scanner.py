#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Core network scanning functionality for GRecon.

This module provides the primary port scanning capabilities using multi-threading
for efficient network reconnaissance.
"""

import socket
import threading
import time
from queue import Queue
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
import ipaddress
import logging

logger = logging.getLogger(__name__)

class PortScanner:
    """
    Multi-threaded port scanner that efficiently discovers open ports on target hosts.
    
    Attributes:
        target (str): Target IP address or hostname
        timeout (float): Socket connection timeout in seconds
        thread_count (int): Number of threads to use for scanning
        discovered_ports (list): List of open ports discovered during scan
    """
    
    def __init__(self, target: str, timeout: float = 0.3, thread_count: int = 200):
        """
        Initialize the port scanner with target and configuration.
        
        Args:
            target: Target IP address or hostname to scan
            timeout: Socket connection timeout in seconds
            thread_count: Number of threads to use for scanning
        
        Raises:
            ValueError: If the target is invalid or cannot be resolved
        """
        self.target = target
        self.timeout = timeout
        self.thread_count = thread_count
        self.discovered_ports: List[int] = []
        self.print_lock = threading.Lock()
        self.queue = Queue()
        
        # Resolve hostname to IP address
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Invalid target: {target}. Cannot resolve hostname to IP address.")
    
    def _port_scan(self, port: int) -> None:
        """
        Scan a single port on the target.
        
        Args:
            port: Port number to scan
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        
        try:
            result = s.connect_ex((self.target_ip, port))
            if result == 0:
                with self.print_lock:
                    logger.info(f"Port {port} is open")
                    print(f"Port {port} is open")
                    self.discovered_ports.append(port)
        except (ConnectionRefusedError, AttributeError, OSError) as e:
            logger.debug(f"Error scanning port {port}: {e}")
        finally:
            s.close()
    
    def _threader(self) -> None:
        """Worker thread function that processes the queue of ports to scan."""
        while True:
            port = self.queue.get()
            self._port_scan(port)
            self.queue.task_done()
    
    def scan(self, port_range: Tuple[int, int] = (1, 65535)) -> List[int]:
        """
        Perform the port scan on the target.
        
        Args:
            port_range: Tuple containing the start and end port numbers to scan
        
        Returns:
            List of discovered open ports
        """
        start_port, end_port = port_range
        start_time = datetime.now()
        
        logger.info(f"Starting scan of {self.target_ip} ({self.target})")
        logger.info(f"Port range: {start_port}-{end_port}")
        logger.info(f"Using {self.thread_count} threads")
        
        # Start the worker threads
        for _ in range(self.thread_count):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()
        
        # Add ports to the queue
        for port in range(start_port, end_port + 1):
            self.queue.put(port)
        
        # Wait for all ports to be scanned
        self.queue.join()
        
        end_time = datetime.now()
        scan_time = end_time - start_time
        
        logger.info(f"Scan completed in {scan_time}")
        logger.info(f"Found {len(self.discovered_ports)} open ports")
        
        return self.discovered_ports
    
    def get_scan_results(self) -> Dict[str, Any]:
        """
        Get the scan results in a structured format.
        
        Returns:
            Dictionary containing scan results and metadata
        """
        return {
            "target": self.target,
            "target_ip": self.target_ip,
            "open_ports": sorted(self.discovered_ports),
            "port_count": len(self.discovered_ports)
        }


def validate_target(target: str) -> bool:
    """
    Validate if a target is a valid IP address or resolvable hostname.
    
    Args:
        target: Target IP address or hostname to validate
    
    Returns:
        True if target is valid, False otherwise
    """
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Not an IP address, check if it's a resolvable hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

def quick_scan(target: str, timeout: float = 0.3, thread_count: int = 200) -> List[int]:
    """
    Convenience function to quickly scan a target without creating a scanner instance.
    
    Args:
        target: Target IP address or hostname
        timeout: Socket connection timeout in seconds
        thread_count: Number of threads to use for scanning
    
    Returns:
        List of discovered open ports
    
    Raises:
        ValueError: If the target is invalid
    """
    scanner = PortScanner(target, timeout, thread_count)
    return scanner.scan()
