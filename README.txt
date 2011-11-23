collective.emaillogin Package Readme
====================================


Overview
--------

This package allow logins with email address rather than login name. It applies
some (somewhat hackish) patches to Plone's membership tool and memberdata
class, after which the email address, on save, is saved as the login name for
members. This makes that members can log in using their email address rather
than some additional id, and when the email address changes the login name
is changed along with it.

Since version 1.0 we explicitly convert e-mail addresses to
lowercase.  You should be able to login with any mix of upper and
lower case letters.


Installation
------------

Add it to the eggs of your Plone 3 buildout.  With Plone 3.2.x or
earlier also add it to the zcml option of your instance.  Install it
in the Add-ons (Extra Packages) control panel in your Plone Site.
Installing simply adds a new skin layer named 'emaillogin'.

It is best to install this on a fresh Plone site.  The login names of
current users are not changed.  There is code in core Plone 4 for
this, so you may want to look there if you need it.

.. WARNING::
  A major part of this package works by patching several core
  Plone and CMF classes.  The patches also apply when you do not have
  this package installed in your Plone Site.  This may give unwanted
  results, like changing the login name of a user when his or her e-mail
  address is changed.  This also means that when you have multiple Plone
  Sites in one Zope instance, you should either install this package in
  all of them or not use it at all and remove it from your buildout.


Upgrading
---------

When upgrading from version 0.8, an upgrade step is run to change all
login names to lower case, for those login names that are already
e-mail addresses.


Problems
--------

The solution is far from perfect, for instance on places where the
userid is displayed the original (underlying) id is shown, which works
fine until the email address is overwritten - once this is done the
old email address will be displayed rather than the new one.  There
may be some more spots in Plone that for example search only for users
by id so when you use that to search on login name this may fail.
Also, there are spots in the Plone or CMF or Zope code that have a
userid as input but use it as login name or the other way around.

There were some more issues, but we think those have been fixed.

Note that when you registered with old@example.org and changed that to
new@example.org, you can no longer login with your old address.  You
can only login with your current e-mail address, though the case
(upper, lower, mixed) should not matter anymore.

Since version 1.0, whenever an e-mail address is set, we convert it to
lowercase.


Future
------

In Plone 4 this package is deprecated, as Plone 4 already supports
logging in with your email address as an option:
http://dev.plone.org/plone/ticket/9214

So we strongly advise not to use this package on Plone 4.  But your
instance will still start up (tested on Plone 4.0a4) and you can
uninstall the package through the UI.  You may need to manually remove
``emaillogin`` from the skin selections in the Properties tab of
portal_skins in the ZMI.  Since the package does some patches on
startup, you should still remove it from the eggs and zcml options of
your instance, rerun buildout and start your instance again.
