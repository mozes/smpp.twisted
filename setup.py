import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

from setuptools import setup, find_packages
setup(
    name = "smpp.twisted",
    version = "0.4",
    author = "Roger Hoover",
    author_email = "roger.hoover@gmail.com",
    description = "SMPP 3.4 client built on Twisted",
    license = 'Apache License 2.0',
    packages = find_packages(),
    long_description=read('README.markdown'),
    keywords = "smpp twisted",
    url = "https://github.com/mozes/smpp.twisted",
    py_modules=["smpp.twisted"],
    include_package_data = True,
    package_data={'smpp.twisted': ['README.markdown']},
    zip_safe = False,   
    install_requires = [
        'twisted',
        'enum',
        'pyOpenSSL',
        'smpp.pdu',
    ],
    tests_require = [
        'mock',
    ],
    test_suite = 'smpp.twisted.tests',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Framework :: Twisted",
        "Topic :: System :: Networking",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)

