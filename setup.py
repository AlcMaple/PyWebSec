from setuptools import setup, find_packages

setup(
    name="PyWebSec",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pyyaml>=5.1",
    ],
    author="Maple",
    author_email="2933724627wab@gmail.com",
    description="A lightweight web security middleware for Python applications",
    keywords="security, web, middleware, protection",
    url="",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.6",
)