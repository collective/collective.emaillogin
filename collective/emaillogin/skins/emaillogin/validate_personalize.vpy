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

reg_tool=context.portal_registration

def missing(field):
    state.setError(field, PMF(u'This field is required, please provide some information.'), 'input_required')

portal = context.portal_url.getPortalObject()

username = ''
if not email:
    missing('email')
else:
    username = email
    if username == portal.getId():
        notallowed('email')
    else:
        context.REQUEST.set('username', email)

if not state.getError('email') and not reg_tool.isMemberIdAllowed(username):
    state.setError(
        'email',
        _('message_email_already_in_use_',
          u"The email address you selected is already in use or is not valid "
          "as login name. Please choose another."),
        'email_invalid' )

if state.getErrors():
    context.plone_utils.addPortalMessage(PMF(u'Please correct the indicated errors.'), 'error')
    return state.set(status='failure')

return state
