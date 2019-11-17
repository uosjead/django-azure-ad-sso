import os
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages


def read_file(filename):
    """Read a file into a string"""
    path = os.path.abspath(os.path.dirname(__file__))
    filepath = os.path.join(path, filename)
    try:
        return open(filepath).read()
    except IOError:
        return ''


def get_readme():
    """Return the README file contents. Supports text,rst, and markdown"""
    for name in ('README', 'README.rst', 'README.md'):
        if os.path.exists(name):
            return read_file(name)
    return ''

setup(
    name = 'django-azure-ad-sso',
    version = __import__('django-azure-ad-sso-sso').get_version().replace(' ', '-'),
    url = 'https://github.com/uosjead/django-azure-ad-auth2-sso',
    author = 'Will',
    author_email = 'wrpearson9@gmail.com',
    description = 'Authenticates users using Azure Active Directory.',
    long_description = get_readme(),
    packages = find_packages(exclude=['tests']),
    include_package_data = True,
    install_requires = read_file('requirements.txt'),
    classifiers = [
        'Environment :: Web Environment',
        'License :: OSI Approved :: MIT License',
        'Framework :: Django',
        'Programming Language :: Python',
    ],
)
