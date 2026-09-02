"""Operator commands that ship with `agience-origin`.

Declared in `pyproject.toml`'s `[project.scripts]`, so `pip install agience-origin` yields them on
the PATH. A module here is a command a human runs by hand — never something the service imports at
runtime, so nothing in `origin.main`'s import path may depend on this package.
"""
