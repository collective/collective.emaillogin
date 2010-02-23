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


Problems
--------

The solution is far from perfect, for instance on places where the userid is
displayed the original (underlying) id is shown, which works fine until the
email address is overwritten - once this is done the old email address will
be displayed rather than the new one.

It is expected that there are more issues, for now, however, there aren't any
known.


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
