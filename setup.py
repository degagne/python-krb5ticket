import os
import imp

from setuptools import setup, find_packages


version = imp.load_source(
    "krb5ticket.version", os.path.join("krb5ticket", "version.py")).version

setup(
    name="python-krb5ticket",
    version=version,
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=[
        "gssapi",
        "pandas==1.1.3"
    ],
    author="Deric Degagne",
    author_email="deric.degagne@gmail.com",
    description="Simple Python wrapper to create Kerberos ticket-granting tickets (TGT)",
    url="https://github.com/degagne/python-krb5ticket",
    license="MIT",
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: MIT License"
    ],
    python_requires=">=3.6",
)