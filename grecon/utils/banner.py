#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Banner display module for GRecon.

This module provides functions to display professional ASCII art banners
and tool information.
"""

import sys
import random
import platform
import time
from datetime import datetime
from typing import List, Dict, Optional

# Color codes for terminal output
COLORS = {
    "RESET": "\033[0m",
    "BLACK": "\033[30m",
    "RED": "\033[31m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "BLUE": "\033[34m",
    "MAGENTA": "\033[35m",
    "CYAN": "\033[36m",
    "WHITE": "\033[37m",
    "BOLD": "\033[1m",
    "UNDERLINE": "\033[4m",
    "REVERSED": "\033[7m"
}

# Version information
VERSION = "1.0.0"
AUTHOR = "Mohamed Gebril"
GITHUB = "https://github.com/Moh-Gebril/grecon"

def get_random_color() -> str:
    """
    Get a random terminal color code.
    
    Returns:
        Random color code
    """
    color_keys = ["RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN"]
    return COLORS[random.choice(color_keys)]

def print_colored(text: str, color: str = "WHITE", bold: bool = False) -> None:
    """
    Print text with specified color and formatting.
    
    Args:
        text: Text to print
        color: Color name from COLORS dictionary
        bold: Whether to make the text bold
    """
    color_code = COLORS.get(color.upper(), COLORS["WHITE"])
    bold_code = COLORS["BOLD"] if bold else ""
    print(f"{bold_code}{color_code}{text}{COLORS['RESET']}")

def print_banner() -> None:
    """Display the GRecon banner with tool information."""
    banner = r"""
     ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔════╝ ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██║  ███╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
     ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    """
    
    random_color = get_random_color()
    print(f"{random_color}{banner}{COLORS['RESET']}")
    
    # Print tool information
    divider = "=" * 80
    print_colored(divider, "BLUE")
    print_colored(f"  GRecon v{VERSION} - Advanced Network Reconnaissance Tool", "CYAN", bold=True)
    print_colored(f"  Author: {AUTHOR}", "CYAN")
    print_colored(f"  GitHub: {GITHUB}", "CYAN")
    print_colored(f"  Running on: {platform.system()} {platform.release()}", "CYAN")
    print_colored(divider, "BLUE")
    
    # Print current time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print_colored(f"  Scan initiated at: {current_time}", "GREEN")
    print_colored(divider, "BLUE")
    print()  # Add an empty line for spacing

def print_scan_header(target: str) -> None:
    """
    Print header information for a scan.
    
    Args:
        target: Target IP address or hostname
    """
    divider = "-" * 80
    print_colored(divider, "BLUE")
    print_colored(f"  Target: {target}", "GREEN", bold=True)
    print_colored(f"  Time started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "GREEN")
    print_colored(divider, "BLUE")
    print()  # Add an empty line for spacing

def print_results_header() -> None:
    """Print header for scan results section."""
    divider = "=" * 80
    print()  # Add an empty line for spacing
    print_colored(divider, "YELLOW")
    print_colored("  SCAN RESULTS", "YELLOW", bold=True)
    print_colored(divider, "YELLOW")
    print()  # Add an empty line for spacing

def print_completion_message(start_time: datetime) -> None:
    """
    Print scan completion message with elapsed time.
    
    Args:
        start_time: Scan start time
    """
    end_time = datetime.now()
    elapsed = end_time - start_time
    
    divider = "=" * 80
    print()  # Add an empty line for spacing
    print_colored(divider, "GREEN")
    print_colored("  SCAN COMPLETED", "GREEN", bold=True)
    print_colored(f"  Elapsed time: {elapsed}", "GREEN")
    print_colored(f"  Completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}", "GREEN")
    print_colored(divider, "GREEN")
    print()  # Add an empty line for spacing

def print_section_header(title: str) -> None:
    """
    Print a section header.
    
    Args:
        title: Section title
    """
    divider = "-" * 80
    print()  # Add an empty line for spacing
    print_colored(divider, "CYAN")
    print_colored(f"  {title}", "CYAN", bold=True)
    print_colored(divider, "CYAN")
    print()  # Add an empty line for spacing

def animated_loading(message: str, duration: float = 3.0) -> None:
    """
    Display an animated loading message.
    
    Args:
        message: Message to display
        duration: Duration in seconds
    """
    chars = "|/-\\"
    start_time = time.time()
    
    i = 0
    while time.time() - start_time < duration:
        sys.stdout.write(f"\r{message} {chars[i % len(chars)]}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    sys.stdout.write(f"\r{message} Done!{' ' * 10}\n")
    sys.stdout.flush()
