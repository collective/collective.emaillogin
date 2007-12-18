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

