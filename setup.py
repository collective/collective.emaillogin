from setuptools import setup, find_packages
import os.path

versionfile = os.path.join('collective', 'emaillogin', 'version.txt')
version = open(versionfile).read().strip()

readme = open('README.txt').read().strip()

historyfile = os.path.join('collective', 'emaillogin', 'HISTORY.txt')
history = open(historyfile).read().strip()

long_description = readme + '\n\n\n' + history

setup(name='collective.emaillogin',
      version=version,
      description="Allow logins with email address rather than login name.",
      long_description=long_description,
      # Get more strings from
      # http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        "Framework :: Plone",
        "Framework :: Plone :: 3.2",
        "Framework :: Plone :: 3.3",
        "Framework :: Zope2",
        "Framework :: Zope3",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        ],
      keywords='',
      author='Guido Wesdorp',
      author_email='guido@pragmagik.com',
      url='http://pypi.python.org/pypi/collective.emaillogin',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['collective'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-

      [z3c.autoinclude.plugin]
      target = plone
      """,
      )
