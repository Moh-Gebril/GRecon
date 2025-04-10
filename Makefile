.PHONY: install install-dev uninstall clean test lint help

# Default target
.DEFAULT_GOAL := help

# Python and pip commands
PYTHON := python3
PIP := pip3

# Installation
install:
	@echo "Installing grecon..."
	@$(PIP) install .
	@echo "Installation complete! Run 'grecon --help' to get started."

install-dev:
	@echo "Installing grecon in development mode..."
	@$(PIP) install -e .
	@$(PIP) install -r requirements-dev.txt || echo "No requirements-dev.txt found, skipping development dependencies."
	@echo "Development setup complete!"

uninstall:
	@echo "Uninstalling grecon..."
	@$(PIP) uninstall -y grecon
	@echo "Uninstallation complete."

# Cleaning
clean:
	@echo "Cleaning up build artifacts..."
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info/
	@rm -rf .pytest_cache/
	@rm -rf .coverage
	@find . -name '*.pyc' -delete
	@find . -name '__pycache__' -delete
	@find . -name '*.log' -delete
	@echo "Cleanup complete."

# Testing
test:
	@echo "Running tests..."
	@pytest -v tests/ || echo "Tests failed or pytest not installed."

# Linting
lint:
	@echo "Running linters..."
	@flake8 grecon/ || echo "Linting failed or flake8 not installed."
	@pylint grecon/ || echo "Linting failed or pylint not installed."

# Build a distributable package
build:
	@echo "Building distributable package..."
	@$(PYTHON) setup.py sdist bdist_wheel
	@echo "Build complete. Files are in the 'dist' directory."

# Help message
help:
	@echo "grecon - Advanced Network Reconnaissance Tool"
	@echo ""
	@echo "Makefile commands:"
	@echo "  make install      - Install grecon"
	@echo "  make install-dev  - Install in development mode with extra dependencies"
	@echo "  make uninstall    - Uninstall grecon"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make test         - Run tests"
	@echo "  make lint         - Run linters"
	@echo "  make build        - Build distributable package"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Usage after installation:"
	@echo "  grecon --help  - Show command line options"
	@echo ""
