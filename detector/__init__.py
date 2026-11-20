"""Detector package: URL/HTML features, brand check, ML model, verdict."""
from .url_features import extract_url_features
from .html_features import extract_html_features
from .brand import check_brand_impersonation
from .model import get_model
from .verdict import analyze_url

__all__ = [
    "extract_url_features",
    "extract_html_features",
    "check_brand_impersonation",
    "get_model",
    "analyze_url",
]
