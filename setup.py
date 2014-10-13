#!/usr/bin/env python
# encoding: utf-8

import os
from setuptools import setup, Command


class RunTests(Command):
    """
    Make sure the code is importable and properly-formatted. Will fail if
    dependencies aren't yet installed.
    """
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print("Attempting to import API and checking source code "
              "formatting...")
        import sys
        import subprocess
        sys.path.append('../')
        # Make sure there are no issues that would prevent import
        from afapi import AppFirstAPI  # NOQA
        return_code = subprocess.call(['flake8', os.path.join('..', 'afapi')])
        if return_code == 0:
            print("All tests passed!")
        else:
            print("Error(s) found in code formatting!")
        sys.exit(return_code)


setup(
    name='AppFirstAPI',
    version='1.0',
    packages=['afapi'],
    install_requires=['requests'],
    author="Michael Okner, Nick Reichel, Morgan Snyder",
    author_email="michael@appfirst.com",
    url="https://github.com/appfirst/afapi",
    cmdclass={'test': RunTests},
    description="A Python wrapper for interacting with AppFirst's APIs (v5)",
    license="Apache2",
    keywords="AppFirst API",
)
