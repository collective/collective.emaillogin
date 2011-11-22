## Controller Python Script "validate_registration"
##bind container=container
##bind context=context
##bind namespace=
##bind script=script
##bind state=state
##bind subpath=traverse_subpath
##parameters=email='',password='',password_confirm=''
##title=validates the Registration of a User

from Products.CMFPlone import PloneMessageFactory as PMF
from collective.emaillogin.utils import EmailLoginMessageFactory as _

reg_tool=context.portal_registration
def missing(field):
    state.setError(field, PMF(u'This field is required, please provide some information.'), 'input_required')
def nomatch(field):
    state.setError(field, PMF(u'Passwords do not match.'), 'nomatch_password')
def minlimit(field):
    state.setError(field, PMF(u'Passwords must contain at least 5 letters.'), 'min_password')
def notallowed(field):
    state.setError(field, PMF(u'This username is reserved. Please choose a different name.'), 'not_allowed')

portal = context.portal_url.getPortalObject()
REQUEST = context.REQUEST

username = ''
if not email:
    missing('email')
else:
    # force lowercase email
    if email != email.lower():
        email = email.lower()
        REQUEST.set('email', email)
    username = email
    if username == portal.getId():
        notallowed('email')
    else:
        context.REQUEST.set('username', email)

if not portal.validate_email:
     if password!=password_confirm:
         nomatch('password')
         nomatch('password_confirm')
     elif not password:
         missing('password')
     elif not password_confirm:
         missing('password_confirm')
     elif len(password) < 5:
         minlimit('password')
         minlimit('password_confirm')

if not state.getError('email') and not reg_tool.isMemberIdAllowed(username):
    state.setError('email',
                   _('message_email_in_use',
                     u"The email address you selected is already in use or is "
                     "not valid as login name. Please choose another."),
                   'email_invalid' )

if state.getErrors():
    context.plone_utils.addPortalMessage(PMF(u'Please correct the indicated errors.'), 'error')
    return state.set(status='failure')

return state
