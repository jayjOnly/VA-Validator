from setuptools import setup, find_packages

setup(
    name="nessus_validator",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click",
        "pandas",
        "colorama",
        "python-nmap",  
    ],
    entry_points={
        "console_scripts": [
            "nessus-validator=nessus_validator.cli:main",
        ],
    },
    author="Security Engineer",
    description="Tool for validating Nessus vulnerability findings",
)