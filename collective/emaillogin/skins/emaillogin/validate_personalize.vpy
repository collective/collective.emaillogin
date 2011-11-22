## Controller Python Script "validate_personalize"
##bind container=container
##bind context=context
##bind namespace=
##bind script=script
##bind state=state
##bind subpath=traverse_subpath
##parameters=email=''
##title=validates user preferences

# Change compared to default Plone: check the validity of the email
# address as a login name.

from Products.CMFPlone import PloneMessageFactory as PMF
from collective.emaillogin.utils import EmailLoginMessageFactory as _

portal = context.portal_url.getPortalObject()
reg_tool = portal.portal_registration
membership_tool = portal.portal_membership


def missing(field):
    state.setError(
        field,
        PMF(u'This field is required, please provide some information.'),
        'input_required')


def notallowed(field):
    state.setError(
        field,
        PMF(u'This username is reserved. Please choose a different name.'),
        'not_allowed')


username = ''
if not email:
    missing('email')
else:
    # force lowercase email
    if email != email.lower():
        email = email.lower()
        context.REQUEST.set('email', email)
    username = email
    if username == portal.getId():
        notallowed('email')
    else:
        context.REQUEST.set('username', email)

if not state.getError('email') and not reg_tool.isMemberIdAllowed(username):
    member = membership_tool.getAuthenticatedMember()
    # Keeping your email the same (which happens when you change
    # something else on the personalize form) or changing it back to
    # your login name, is fine.
    if email not in (member.getId(), member.getProperty('email')):
        state.setError(
            'email',
            _('message_email_in_use',
              u"The email address you selected is already in use or is not "
              "valid as login name. Please choose another."),
            'email_invalid')

if state.getErrors():
    portal.plone_utils.addPortalMessage(
        PMF(u'Please correct the indicated errors.'), 'error')
    return state.set(status='failure')

return state
