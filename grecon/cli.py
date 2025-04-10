#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command Line Interface for GRecon.

This module provides the main CLI functionality, argument parsing,
and orchestrates the scanning process.
"""

import os
import sys
import logging
import argparse
import signal
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from grecon.core.scanner import PortScanner, validate_target
from grecon.core.nmap_engine import NmapEngine, is_nmap_installed
from grecon.core.nse_handler import NseHandler
from grecon.utils.banner import (print_banner, print_scan_header, 
                               print_results_header, print_completion_message,
                               print_section_header, print_colored,
                               animated_loading)
from grecon.utils.output import (display_port_scan_results, display_nmap_command,
                               display_nmap_scan_results, display_nse_scan_results,
                               export_to_json, export_to_xml, export_to_html)
from grecon.utils.validator import (is_valid_ip, is_valid_hostname, is_valid_port_range,
                                  parse_port_range, resolve_target, is_root,
                                  check_required_tools, validate_timeout,
                                  validate_thread_count)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('grecon.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def handle_keyboard_interrupt(signum, frame):
    """Handle keyboard interrupt (Ctrl+C) signal."""
    print_colored("\n\nScan interrupted by user. Exiting...", "YELLOW")
    sys.exit(1)

def main():
    """Main function that orchestrates the scanning process."""
    # Set up signal handler for keyboard interrupts
    signal.signal(signal.SIGINT, handle_keyboard_interrupt)
    
    # Parse command line arguments
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Display banner
    if not args.quiet:
        print_banner()
        
    # Initialize variables
    start_time = datetime.now()
    open_ports = []
    scan_results = {
        "target": args.target,
        "timestamp": start_time,
        "open_ports": []
    }
    
    # Check required tools
    tools = check_required_tools()
    if args.run_nmap and not tools["nmap"]:
        print_colored("Error: Nmap is required but not found. Please install Nmap.", "RED", bold=True)
        sys.exit(1)
    
    # Validate and resolve target
    try:
        target, resolved_ip = resolve_target(args.target)
        if not resolved_ip:
            print_colored(f"Warning: Could not resolve {target} to an IP address.", "YELLOW")
            if not args.quiet:
                continue_scan = input("Continue with the scan anyway? (y/n): ").lower()
                if continue_scan != 'y':
                    sys.exit(0)
    except ValueError as e:
        print_colored(f"Error: {e}", "RED", bold=True)
        sys.exit(1)
    
    # Create output directory
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except PermissionError:
        print_colored(f"Error: Permission denied creating directory {args.output_dir}", "RED", bold=True)
        sys.exit(1)
    
    # Initialize scanner and validate parameters
    try:
        timeout = validate_timeout(args.timeout)
        thread_count = validate_thread_count(args.threads)
    except ValueError as e:
        print_colored(f"Error: {e}", "RED", bold=True)
        sys.exit(1)
    
    # Set up port range
    try:
        start_port, end_port = parse_port_range(args.port_range)
    except ValueError as e:
        print_colored(f"Error: {e}", "RED", bold=True)
        sys.exit(1)
    
    # Check for --skip-port-scan option
    if args.skip_port_scan:
        if not args.specific_ports:
            print_colored("Error: --skip-port-scan requires --ports to be specified", "RED", bold=True)
            sys.exit(1)
        
        try:
            # Parse comma-separated ports
            open_ports = [int(p.strip()) for p in args.specific_ports.split(",")]
        except ValueError:
            print_colored("Error: Invalid port specification in --ports", "RED", bold=True)
            sys.exit(1)
        
        scan_results["open_ports"] = open_ports
    else:
        # Perform port scan
        if not args.quiet:
            print_scan_header(target)
        
        try:
            scanner = PortScanner(target, timeout, thread_count)
            open_ports = scanner.scan((start_port, end_port))
            scan_duration = datetime.now() - start_time
            
            if not args.quiet:
                display_port_scan_results(target, open_ports, start_time, datetime.now())
            
            scan_results["open_ports"] = open_ports
            scan_results["port_scan_duration"] = scan_duration
        except Exception as e:
            print_colored(f"Error during port scan: {e}", "RED", bold=True)
            sys.exit(1)
    
    # Nmap scanning
    if args.run_nmap and open_ports:
        if not args.quiet:
            print_section_header("NMAP SCAN")
        
        try:
            nmap_engine = NmapEngine(target, open_ports, args.output_dir)
            
            # Display suggested command
            suggested_command = nmap_engine.generate_command(args.nmap_scan_type)
            if not args.quiet:
                display_nmap_command(suggested_command)
            
            # Run the Nmap scan
            if not args.quiet:
                animated_loading("Running Nmap scan...", 1.0)
            
            success, command, output = nmap_engine.run_scan(args.nmap_scan_type)
            
            if not args.quiet:
                display_nmap_scan_results(success, command, output)
            
            scan_results["nmap_scan"] = {
                "success": success,
                "command": command,
                "output": output
            }
            
            # Parse Nmap XML output for service information if running NSE scripts
            if args.run_nse and success:
                output_files = nmap_engine.get_output_files()
                xml_file = output_files.get("XML")
                
                if os.path.exists(xml_file):
                    if not args.quiet:
                        animated_loading("Parsing Nmap results for service detection...", 1.0)
        except Exception as e:
            print_colored(f"Error during Nmap scan: {e}", "RED", bold=True)
            if not args.quiet:
                print_colored("Continuing with available results...", "YELLOW")
    
    # NSE script scanning
    if args.run_nse and args.run_nmap and open_ports:
        if not args.quiet:
            print_section_header("NSE SCRIPT SCAN")
        
        try:
            # Check if we have service information from Nmap
            service_map = {}
            output_files = nmap_engine.get_output_files()
            xml_file = output_files.get("XML")
            
            if os.path.exists(xml_file):
                nse_handler = NseHandler(target, open_ports, output_dir=args.output_dir)
                nse_handler.update_service_map_from_xml(xml_file)
                service_map = nse_handler.service_map
            else:
                nse_handler = NseHandler(target, open_ports, output_dir=args.output_dir)
            
            if not args.quiet:
                animated_loading("Running NSE scripts...", 1.0)
            
            # Run NSE scripts based on detected services
            nse_results = nse_handler.run_service_based_scripts(args.nse_safety)
            
            if not args.quiet:
                display_nse_scan_results(nse_results)
            
            scan_results["nse_scan"] = nse_results
        except Exception as e:
            print_colored(f"Error during NSE script scan: {e}", "RED", bold=True)
            if not args.quiet:
                print_colored("Continuing with available results...", "YELLOW")
    
    # Export results if requested
    if any([args.export_json, args.export_xml, args.export_html, args.export_all]):
        if not args.quiet:
            print_section_header("EXPORTING RESULTS")
        
        timestamp_str = start_time.strftime("%Y%m%d_%H%M%S")
        target_safe = target.replace(".", "_").replace(":", "_")
        base_filename = f"{args.output_dir}/{target_safe}_{timestamp_str}"
        
        if args.export_json or args.export_all:
            json_file = f"{base_filename}.json"
            if export_to_json(scan_results, json_file):
                print_colored(f"Results exported to JSON: {json_file}", "GREEN")
        
        if args.export_xml or args.export_all:
            xml_file = f"{base_filename}.xml"
            if export_to_xml(scan_results, xml_file):
                print_colored(f"Results exported to XML: {xml_file}", "GREEN")
        
        if args.export_html or args.export_all:
            html_file = f"{base_filename}.html"
            if export_to_html(scan_results, html_file):
                print_colored(f"Results exported to HTML: {html_file}", "GREEN")
    
    # Show completion message
    if not args.quiet:
        print_completion_message(start_time)

def setup_argument_parser() -> argparse.ArgumentParser:
    """
    Set up and configure the argument parser for the CLI.
    
    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="GRecon - Advanced Network Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  grecon -t example.com
  grecon -t 192.168.1.1 -p 1-1000 -T 0.5 -t 300
  grecon -t 10.0.0.1 -nmap -nse
  grecon -t 192.168.1.0/24 --ping-sweep --top-ports 100
  grecon -t example.com --export-all --output-dir ~/scans
        """
    )
    
    # Target specification
    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument("-t", "--target", dest="target", required=True,
                              help="Target IP address or hostname")
    target_group.add_argument("-p", "--port-range", dest="port_range", default="1-65535",
                             help="Port range to scan (e.g., 1-1000 or 80,443,8080)")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--timeout", dest="timeout", type=float, default=0.3,
                           help="Connection timeout in seconds")
    scan_group.add_argument("--threads", dest="threads", type=int, default=200,
                           help="Number of threads to use for scanning")
    scan_group.add_argument("--skip-port-scan", dest="skip_port_scan", action="store_true",
                           help="Skip the initial port scan (use with --ports)")
    scan_group.add_argument("--ports", dest="specific_ports",
                          help="Specify ports to use for Nmap (comma-separated, used with --skip-port-scan)")
    
    # Nmap integration
    nmap_group = parser.add_argument_group("Nmap Integration")
    nmap_group.add_argument("--nmap", dest="run_nmap", action="store_true",
                         help="Run Nmap scan after port discovery")
    nmap_group.add_argument("--nmap-scan-type", dest="nmap_scan_type", 
                          choices=["default", "quick", "comprehensive", "stealth", "udp", "all"],
                          default="default",
                          help="Type of Nmap scan to perform")
    nmap_group.add_argument("--nmap-args", dest="nmap_args",
                         help="Custom Nmap arguments")
    
    # NSE options
    nse_group = parser.add_argument_group("NSE Script Options")
    nse_group.add_argument("--nse", dest="run_nse", action="store_true",
                        help="Run NSE scripts after Nmap scan")
    nse_group.add_argument("--nse-category", dest="nse_category",
                         choices=["auth", "broadcast", "brute", "default", "discovery", 
                                 "dos", "exploit", "external", "fuzzer", "intrusive", 
                                 "malware", "safe", "version", "vuln"],
                         default="safe",
                         help="NSE script category to use")
    nse_group.add_argument("--nse-safety", dest="nse_safety",
                        choices=["safe", "default", "intrusive", "all"],
                        default="safe",
                        help="Safety level for NSE scripts")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--output-dir", dest="output_dir", default="results",
                           help="Directory to save results")
    output_group.add_argument("--export-json", dest="export_json", action="store_true",
                           help="Export results to JSON")
    output_group.add_argument("--export-xml", dest="export_xml", action="store_true",
                           help="Export results to XML")
    output_group.add_argument("--export-html", dest="export_html", action="store_true",
                           help="Export results to HTML report")
    output_group.add_argument("--export-all", dest="export_all", action="store_true",
                           help="Export results to all formats (JSON, XML, HTML)")
    output_group.add_argument("--quiet", dest="quiet", action="store_true",
                           help="Suppress banner and non-essential output")
    
    return parser

if __name__ == "__main__":
    main()
