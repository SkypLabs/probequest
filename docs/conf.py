# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# pylint: skip-file

from datetime import datetime
from os import environ

from probequest import __version__ as VERSION

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "ProbeQuest"
copyright = f"2017-{datetime.now().year}, Paul-Emmanuel Raoul"
author = "Paul-Emmanuel Raoul"

release = VERSION

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.todo",
    "sphinx.ext.viewcode",
    "sphinxarg.ext",
    "sphinxcontrib.seqdiag",
]

templates_path = ["_templates"]

master_doc = "index"

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"

html_static_path = ["_static"]

html_context = {
    "conf_py_path": "/docs/",
    "display_github": True,
    "github_user": "SkypLabs",
    "github_repo": "probequest",
    "github_version": "develop",
    "plausible_domain": "probequest.skyplabs.net",
}

# -- Extension configuration -------------------------------------------------

# -- Options for todo extension ----------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/todo.html

todo_include_todos = True

# -- Options for sphinxcontrib-seqdiag extension -----------------------------
# http://blockdiag.com/en/seqdiag/sphinxcontrib.html

seqdiag_fontpath = "/usr/share/fonts/truetype/ipafont/ipagp.ttf"

# -- Read the Docs -----------------------------------------------------------

# Set canonical URL from the Read the Docs Domain
html_baseurl = environ.get("READTHEDOCS_CANONICAL_URL", "")

# Tell Jinja2 templates the build is running on Read the Docs
if environ.get("READTHEDOCS", "") == "True":
    if "html_context" not in globals():
        html_context = {}

    html_context["READTHEDOCS"] = True
