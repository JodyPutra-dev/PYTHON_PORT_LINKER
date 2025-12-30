# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

"""
Configuration package for PortLinker application.

This package provides translation strings, default configuration values,
and language management functionality for the PortLinker application.

Exported modules:
    - translations: Translation strings and language management

Public API:
    - TRANSLATIONS: Dictionary containing all translation strings
    - DEFAULT_PORTS: List of default port numbers
    - get_text: Get translated text for a given key
    - get_current_language: Get the current language code
    - set_current_language: Set the current language
    - toggle_language: Toggle between supported languages
"""

from .translations import (
    TRANSLATIONS,
    DEFAULT_PORTS,
    get_text,
    get_current_language,
    set_current_language,
    toggle_language
)

__all__ = [
    "TRANSLATIONS",
    "DEFAULT_PORTS",
    "get_text",
    "get_current_language",
    "set_current_language",
    "toggle_language"
]
