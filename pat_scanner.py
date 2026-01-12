#!/usr/bin/env python3
import sys
import os

# Add the current directory to sys.path to ensure local modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.cli import main

if __name__ == "__main__":
    main()
