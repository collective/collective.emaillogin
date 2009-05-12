from zope.i18nmessageid import MessageFactory
from Products.CMFCore.utils import getToolByName

EmailLoginMessageFactory = MessageFactory(u'collective.emaillogin')


def getMemberByLoginName(context, login_name, raise_exceptions=True):
    """Get a member by his login name.

    If raise_exceptions is False, we silently return None.
    """
    membership = getToolByName(context, 'portal_membership')
    # First the easy case: it may be a userid after all.
    member = membership.getMemberById(login_name)

    if member is not None:
        return member

    # Try to find this user via the login name.
    acl = getToolByName(context, 'acl_users')
    userids = [user.get('userid') for user in
               acl.searchUsers(login=login_name)
               if user.get('userid')]
    if len(userids) == 1:
        userid = userids[0]
        member = membership.getMemberById(userid)
    elif len(userids) > 1:
        if raise_exceptions:
            raise ValueError(
                'Multiple users found with the same login name.')
    if member is None and raise_exceptions:
        raise ValueError('The username you entered could not be found')
    return member
