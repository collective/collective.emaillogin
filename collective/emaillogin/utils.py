from zope.i18nmessageid import MessageFactory
from Products.CMFCore.utils import getToolByName

EmailLoginMessageFactory = MessageFactory(u'collective.emaillogin')


def _searchMemberByLoginName(context, login_name, raise_exceptions=True):
    """Search for a member by his login name.

    Used twice by getMemberByLoginName (once explicitly with lower
    case), so factored out into a separate function.
    """
    member = None
    acl = getToolByName(context, 'acl_users')
    # XXX Try: acl.searchUsers(login=login_name, exact_match=True)
    userids = [user.get('userid') for user in
               acl.searchUsers(login=login_name)
               if user.get('userid')]
    if len(userids) == 1:
        userid = userids[0]
        membership = getToolByName(context, 'portal_membership')
        member = membership.getMemberById(userid)
    elif len(userids) > 1:
        if raise_exceptions:
            raise ValueError(
                'Multiple users found with the same login name.')
    return member


def getMemberByLoginName(context, login_name, raise_exceptions=True,
                         allow_userid=True):
    """Get a member by his login name.

    If raise_exceptions is False, we silently return None.

    If allow_userid is True, we return the member with the login_name
    as userid when found.  When there is no '@' in the login_name we
    do the same.
    """
    membership = getToolByName(context, 'portal_membership')
    member = None
    # First the easy case: it may be a userid after all.
    if allow_userid or not '@' in login_name:
        member = membership.getMemberById(login_name)

    if member is not None:
        return member
    # Explicitly try lower case, but only for e-mail logins.
    if allow_userid and '@' in login_name and login_name != login_name.lower():
        member = membership.getMemberById(login_name.lower())
        if member is not None:
            return member

    # Try to find this user via the login name.
    member = _searchMemberByLoginName(context, login_name, raise_exceptions)
    if member is None:
        # Search for lower case, but only for e-mail logins.
        if '@' in login_name and login_name != login_name.lower():
            member = _searchMemberByLoginName(context, login_name.lower(),
                                              raise_exceptions)

    if member is None and raise_exceptions:
        raise ValueError('The username you entered could not be found')
    return member
