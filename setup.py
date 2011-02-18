"""
Copyright 2009-2010 Mozes, Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
from setuptools import setup, find_packages
setup(
    name = "smpp.twisted",
    version = "0.1",
    author = "Roger Hoover",
    author_email = "roger.hoover@gmail.com",
    description = "SMPP client using Twisted",
    license = 'Apache License 2.0',
    packages = find_packages(),
    py_modules=["smpp.twisted"],
    include_package_data = True,
    zip_safe = False,   
    install_requires = [
        'twisted',
        'enum',
        'pyOpenSSL',
    ],
    tests_require = [
        'mock',
    ],
    test_suite = 'smpp.twisted.tests',
)

