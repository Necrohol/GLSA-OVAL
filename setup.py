from setuptools import setup, find_packages

setup(
    name="glsa-oval",
    version="2026.04.06",
    author="necrose99",
    description="Gentoo GLSA to OVAL generator with NVD CVSS enrichment",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://codeberg.org/necrose99/glsa-oval",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
        "lxml>=4.9.0",
        "GitPython>=3.1.0",
        "nvdlib>=0.7.0",
        "pyforgejo>=0.1.0",
    ],
    extras_require={
        "ui": ["sweetviz", "pandas"],
    },
    entry_points={
        "console_scripts": [
            "glsa-oval=glsa_parser.core:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
)
