# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import shutil

project = "Documentation for scanoss-py"
copyright = "2024, Scan Open Source Solutions SL"
author = "Scan Open Source Solutions SL"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ["_templates"]
exclude_patterns = []


def setup():
    if not os.path.exists("_static"):
        os.makedirs("_static")

    schema_path = os.path.join("..", "asets", "scanoss-settings-schema.json")
    if os.path.exists(schema_path):
        shutil.copy2(schema_path, "_static/scanoss-settings-schema.json")


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_logo = "scanosslogo.png"
html_static_path = ["_static"]

html_context = {
    "schema_url": "https://scanoss.readthedocs.io/en/latest/_static/scanoss-settings-schema.json"
}
