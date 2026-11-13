"""Compatibility rejection for Ren'Py titles requiring an excluded SDK."""
from __future__ import absolute_import, division, print_function, unicode_literals


def capabilities(core_info=None):
    return {"rendererAvailable": False, "rendererReason": "notIncluded",
            "offscreenSupported": False, "advancedBlendSupported": False}


def create_model(filename, model_json=None, base=''):
    raise RuntimeError("Live2D is not included in this version of Muxia")
