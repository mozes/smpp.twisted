from setuptools import setup, find_packages
setup(
    name = "smpp.twisted",
    version = "0.1",
    author = "Roger Hoover",
    author_email = "roger.hoover@gmail.com",
    description = "SMPP client using Twisted",
    license = 'GPL',
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

