"""Example target project for the Daedalus Phase-1 demo.

This is an ordinary small Python project with ordinary problems: a function that has a
bug, a test that catches it, and a module that is deliberately outside the whitelist of
the demo task. Daedalus is pointed at it as the *target* repository.
"""

from example_project.textstats import summarize

__all__ = ["summarize"]
