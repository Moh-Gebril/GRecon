#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Output formatting module for GRecon.

This module provides functions to format and display scan results
in various formats (text, JSON, XML, HTML).
"""

import json
import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET

from .banner import COLORS, print_colored

logger = logging.getLogger(__name__)

def format_port_list(ports: List[int], show_count: bool = True) -> str:
    """
    Format a list of ports for display.
    
    Args:
        ports: List of port numbers
        show_count: Whether to show the count of ports
    
    Returns:
        Formatted string of ports
    """
    if not ports:
        return "No open ports found"
    
    sorted_ports = sorted(ports)
    result = ", ".join(map(str, sorted_ports))
    
    if show_count:
        result += f" ({len(sorted_ports)} ports)"
    
    return result

def format_scan_duration(start_time: datetime, end_time: datetime) -> str:
    """
    Format scan duration for display.
    
    Args:
        start_time: Scan start time
        end_time: Scan end time
    
    Returns:
        Formatted duration string
    """
    duration = end_time - start_time
    total_seconds = duration.total_seconds()
    
    if total_seconds < 60:
        return f"{total_seconds:.2f} seconds"
    elif total_seconds < 3600:
        minutes = total_seconds / 60
        return f"{minutes:.2f} minutes"
    else:
        hours = total_seconds / 3600
        return f"{hours:.2f} hours"

def display_port_scan_results(target: str, 
                              ports: List[int], 
                              start_time: datetime, 
                              end_time: datetime) -> None:
    """
    Display port scan results in the terminal.
    
    Args:
        target: Target IP address or hostname
        ports: List of open ports
        start_time: Scan start time
        end_time: Scan end time
    """
    print_colored("PORT SCAN RESULTS", "GREEN", bold=True)
    print_colored("-" * 40, "BLUE")
    print_colored(f"Target: {target}", "WHITE")
    print_colored(f"Scan Duration: {format_scan_duration(start_time, end_time)}", "WHITE")
    print_colored(f"Open Ports: {format_port_list(ports)}", "WHITE")
    print_colored("-" * 40, "BLUE")
    print()  # Add an empty line for spacing

def display_nmap_command(command: str) -> None:
    """
    Display the suggested Nmap command.
    
    Args:
        command: Nmap command string
    """
    print_colored("SUGGESTED NMAP COMMAND", "YELLOW", bold=True)
    print_colored("-" * 60, "BLUE")
    print_colored(command, "WHITE")
    print_colored("-" * 60, "BLUE")
    print()  # Add an empty line for spacing

def display_nmap_scan_results(success: bool, command: str, output: str) -> None:
    """
    Display Nmap scan results in the terminal.
    
    Args:
        success: Whether the scan was successful
        command: Nmap command that was executed
        output: Command output
    """
    if success:
        print_colored("NMAP SCAN RESULTS", "GREEN", bold=True)
    else:
        print_colored("NMAP SCAN FAILED", "RED", bold=True)
    
    print_colored("-" * 60, "BLUE")
    print_colored(f"Command: {command}", "WHITE")
    print_colored("-" * 60, "BLUE")
    
    if success:
        # Display the complete Nmap output
        if output:
            for line in output.split('\n'):
                # Highlight important lines with different colors for better readability
                if 'PORT' in line and 'STATE' in line and 'SERVICE' in line:
                    print_colored(line, "CYAN", bold=True)
                elif 'open' in line and 'tcp' in line:
                    print_colored(line, "GREEN")
                elif 'filtered' in line:
                    print_colored(line, "YELLOW")
                elif 'closed' in line:
                    print_colored(line, "RED")
                elif '|' in line:  # Script output
                    print_colored(line, "MAGENTA")
                elif 'Service Info:' in line or 'OS CPE:' in line or 'Running:' in line:
                    print_colored(line, "CYAN")
                elif 'Nmap done:' in line or 'Nmap scan report' in line:
                    print_colored(line, "WHITE", bold=True)
                else:
                    print_colored(line, "WHITE")
        else:
            print_colored("No output received from Nmap", "WHITE")
    else:
        print_colored(f"Error: {output}", "RED")
    
    print_colored("-" * 60, "BLUE")
    print()  # Add an empty line for spacing

def display_nse_scan_results(results: Dict[str, Any]) -> None:
    """
    Display NSE script scan results in the terminal.
    
    Args:
        results: Dictionary of NSE scan results
    """
    print_colored("NSE SCRIPT SCAN RESULTS", "MAGENTA", bold=True)
    print_colored("-" * 60, "BLUE")
    
    if not results:
        print_colored("No NSE script scans were performed", "WHITE")
    else:
        for service_port, data in results.items():
            # Display service and port information with a clear header
            if data.get("service"):
                service_name = data.get("service", "unknown")
                port_num = data.get("port", "unknown")
                print_colored(f"Service: {service_name} on Port: {port_num}", "CYAN", bold=True)
            else:
                print_colored(f"Scan: {service_port}", "CYAN", bold=True)
            
            # Show which scripts were run
            if "scripts" in data:
                script_list = data["scripts"]
                print_colored(f"Scripts: {', '.join(script_list)}", "WHITE")
            
            # Display the command that was executed
            cmd = data.get("command", "Unknown command")
            print_colored(f"Command: {cmd}", "WHITE")
            
            # Display success/failure status
            if data.get("success", False):
                print_colored("Status: Completed successfully", "GREEN")
                
                # Extract and display relevant script results
                output_lines = data.get("output", "").split("\n")
                script_results = []
                
                # Filter for interesting output lines
                for line in output_lines:
                    # Look for script results (lines with "|")
                    if "|" in line and "_" in line:
                        print_colored(line, "MAGENTA")
                    # Vulnerability findings
                    elif "VULNERABLE" in line:
                        print_colored(line, "RED", bold=True)
                    # Service info
                    elif "Service Info:" in line:
                        print_colored(line, "CYAN")
            else:
                print_colored("Status: Scan Failed", "RED", bold=True)
                print_colored(f"Error: {data.get('error', 'Unknown error')}", "RED")
            
            print_colored("-" * 60, "BLUE")
    
    print()  # Add an empty line for spacing

def export_to_json(data: Dict[str, Any], output_file: str) -> bool:
    """
    Export scan results to a JSON file.
    
    Args:
        data: Data to export
        output_file: Path to output file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        logger.info(f"Results exported to JSON: {output_file}")
        return True
    except Exception as e:
        logger.error(f"Error exporting to JSON: {e}")
        return False

def export_to_xml(data: Dict[str, Any], output_file: str) -> bool:
    """
    Export scan results to an XML file.
    
    Args:
        data: Data to export
        output_file: Path to output file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create root element
        root = ET.Element("grecon_scan")
        
        # Add metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "target").text = data.get("target", "unknown")
        ET.SubElement(metadata, "timestamp").text = str(data.get("timestamp", datetime.now()))
        
        # Add port scan results
        ports_elem = ET.SubElement(root, "port_scan")
        open_ports = data.get("open_ports", [])
        ET.SubElement(ports_elem, "port_count").text = str(len(open_ports))
        
        for port in open_ports:
            port_elem = ET.SubElement(ports_elem, "port")
            port_elem.text = str(port)
        
        # Add nmap results if available
        if "nmap_scan" in data:
            nmap_elem = ET.SubElement(root, "nmap_scan")
            ET.SubElement(nmap_elem, "command").text = data["nmap_scan"].get("command", "")
            ET.SubElement(nmap_elem, "success").text = str(data["nmap_scan"].get("success", False))
        
        # Add NSE results if available
        if "nse_scan" in data:
            nse_elem = ET.SubElement(root, "nse_scan")
            
            for service_port, scan_data in data["nse_scan"].items():
                service_elem = ET.SubElement(nse_elem, "service")
                service_elem.set("name", service_port)
                ET.SubElement(service_elem, "command").text = scan_data.get("command", "")
                ET.SubElement(service_elem, "success").text = str(scan_data.get("success", False))
        
        # Write to file with pretty formatting
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        with open(output_file, 'w') as f:
            f.write(xml_str)
        
        logger.info(f"Results exported to XML: {output_file}")
        return True
    except Exception as e:
        logger.error(f"Error exporting to XML: {e}")
        return False

def export_to_html(data: Dict[str, Any], output_file: str) -> bool:
    """
    Export scan results to an HTML report file.
    
    Args:
        data: Data to export
        output_file: Path to output file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        target = data.get("target", "unknown")
        timestamp = data.get("timestamp", datetime.now())
        open_ports = data.get("open_ports", [])
        
        # Create a basic HTML report
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GRecon Scan Report - {target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        header h1 {{
            color: white;
            margin: 0;
        }}
        .metadata {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .section {{
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        table, th, td {{
            border: 1px solid #ddd;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .success {{
            color: #28a745;
        }}
        .failure {{
            color: #dc3545;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        footer {{
            text-align: center;
            margin-top: 20px;
            font-size: 0.8em;
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>GRecon Scan Report</h1>
        </header>
        
        <div class="metadata">
            <h2>Scan Information</h2>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Date:</strong> {timestamp}</p>
        </div>
        
        <div class="section">
            <h2>Port Scan Results</h2>
            <p><strong>Open Ports:</strong> {len(open_ports)}</p>
            <table>
                <tr>
                    <th>Port</th>
                </tr>
        """
        
        # Add ports to the table
        for port in sorted(open_ports):
            html += f"<tr><td>{port}</td></tr>\n"
        
        html += """
            </table>
        </div>
        """
        
        # Add Nmap scan results if available
        if "nmap_scan" in data:
            nmap_data = data["nmap_scan"]
            success = nmap_data.get("success", False)
            command = nmap_data.get("command", "")
            
            html += f"""
        <div class="section">
            <h2>Nmap Scan Results</h2>
            <p><strong>Status:</strong> <span class="{'success' if success else 'failure'}">{'Successful' if success else 'Failed'}</span></p>
            <p><strong>Command:</strong> <code>{command}</code></p>
            """
            
            if success and "output" in nmap_data:
                html += f"<pre>{nmap_data['output']}</pre>"
            elif not success and "error" in nmap_data:
                html += f"<p class='failure'>Error: {nmap_data['error']}</p>"
            
            html += "</div>\n"
        
        # Add NSE scan results if available
        if "nse_scan" in data:
            html += """
        <div class="section">
            <h2>NSE Script Scan Results</h2>
            <table>
                <tr>
                    <th>Service</th>
                    <th>Status</th>
                    <th>Command</th>
                </tr>
            """
            
            for service_port, scan_data in data["nse_scan"].items():
                success = scan_data.get("success", False)
                command = scan_data.get("command", "")
                
                html += f"""
                <tr>
                    <td>{service_port}</td>
                    <td class="{'success' if success else 'failure'}">{'Successful' if success else 'Failed'}</td>
                    <td><code>{command}</code></td>
                </tr>
                """
            
            html += """
            </table>
        </div>
            """
        
        # Close the HTML document
        html += """
        <footer>
            <p>Generated by GRecon - Advanced Network Reconnaissance Tool</p>
        </footer>
    </div>
</body>
</html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        logger.info(f"Results exported to HTML: {output_file}")
        return True
    except Exception as e:
        logger.error(f"Error exporting to HTML: {e}")
        return False
