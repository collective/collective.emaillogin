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


Gotchas
-------

No, these are not bugs.  Or if they are bugs, then they are bugs that
are too hard to fix without introducing other bugs.  They might be
unexpected though, so we call them gotchas.

- Since version 1.0, whenever an e-mail address is set, we
  automatically convert it to lowercase.  You cannot set an e-mail
  address to upper or mixed case.  When logging in or resetting a
  password the case does not need to match: we look for the given
  login but also for the lowercased login.

- As an administrator, when you change the login name of a user in the
  ZMI, this does not update the email.

- When you register with original@example.org and change this to
  new@example.org, you can no longer login with your original address.
  You can only login with your current e-mail address, though the case
  (upper, lower, mixed) should not matter anymore.

- The initial e-mail address is used as userid.  This id never ever
  changes. In places where the userid is displayed this original
  userid is shown, which is normally fine until the email address is
  overwritten -- once this is done the *original* email address will
  be displayed rather than the new one.  (Plone 4 fixes this in the
  core.)  There may be some more spots in Plone that for example
  search only for users by id so when you use that to search on login
  name this may fail.  Also, there are spots in the Plone or CMF or
  Zope code that have a userid as input but use it as login name or
  the other way around so be careful when you start hacking yourself.

- If you register with one@example.org, then change it to
  two@example.org, then no one can register a new user with
  one@example.org or change the e-mail address of an existing user to
  one@example.org.  This is because it will forever be used as
  userid.  Note that when you now change your address to
  three@example.org, your intermediate address of two@example.org is
  free for the taking.

- When you change your e-mail address, you do *not* get a confirmation
  e-mail to check if you did not make any typos and it is a real
  address.  This means you will not be able to login if you do not
  remember this typo; a password reset will then also not work.  This
  could be considered a problem of Plone in general and not specific
  for this add-on, though we are hit harder by it.  Might be a nice
  candidate for a PLIP (PLone Improvement Proposal) or first an extra
  add-on.


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
