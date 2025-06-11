"""
Setup script for the {{ cookiecutter.plugin_name }} plugin.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="{{ cookiecutter.plugin_name }}",
    version="0.1.0",
    author="{{ cookiecutter.author }}",
    author_email="",
    description="{{ cookiecutter.plugin_description }}",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: {{ cookiecutter.license }} License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "bbf.plugins": [
            "{{ cookiecutter.plugin_name }} = {{ cookiecutter.plugin_name }}:{{ cookiecutter.plugin_name|title }}Plugin",
        ],
    },
) 