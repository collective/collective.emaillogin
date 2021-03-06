from setuptools import setup, find_packages
readme = open('README.txt').read().strip()
changes = open('CHANGES.rst').read().strip()
long_description = readme + '\n\n\n' + changes

setup(name='collective.emaillogin',
      version='1.4.dev0',
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
          "Programming Language :: Python :: 2.4",
          "Topic :: Software Development :: Libraries :: Python Modules",
          ],
      keywords='email login',
      author='Guido Wesdorp',
      author_email='guido@pragmagik.com',
      url='https://github.com/collective/collective.emaillogin',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['collective'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
      ],
      entry_points="""
      # -*- Entry points: -*-

      [z3c.autoinclude.plugin]
      target = plone
      """,
      )
