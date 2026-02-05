"""Inference and prediction for BugPredict AI"""

from .predictor import ThreatPredictor
from .template_generator import NucleiTemplateGenerator

__all__ = [
    'ThreatPredictor',
    'NucleiTemplateGenerator'
]
