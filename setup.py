from setuptools import setup, find_packages
import os

# Robust versioning for a security feed tool
VERSION = "2026.04.06"

setup(
    name="glsa-oval",
    version=VERSION,
    author="necrose99",
    author_email="your-email@example.com",
    description="Gentoo GLSA to Enriched OVAL Generator (CVSS 3.x/2.x via NVD)",
    long_description=open("README.md").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/Necrohol/GLSA-OVAL",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.9",
    # Essential for the GLSA -> NVD -> OVAL pipeline
    install_requires=[
        "requests>=2.28.0",
        "lxml>=4.9.0",
        "GitPython>=3.1.0",
        "nvdlib>=0.7.0",
        "pyforgejo>=0.1.0",
    ],
    # Extras for SecOps Visualization and Data Analysis
    extras_require={
        "ui": ["pandas", "tabulate", "sweetviz"],
    },
    # The "Magic" that creates the CLI command
    entry_points={
        "console_scripts": [
            "glsa-oval=glsa_parser.glsa_to_oval:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    zip_safe=False,
)
