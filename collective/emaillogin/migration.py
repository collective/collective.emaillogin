import logging

from Products.CMFCore.utils import getToolByName

logger = logging.getLogger('collective.emaillogin')
PROFILE_ID = 'profile-collective.emaillogin:default'


def migrate_to_lowercase(context):
    """Migrate mixed/upper case login names to lower case.

    Which means updating the email property as well.

    We only do this for users in source_users.

    Perhaps walk through _login_to_userid.items() and _userid_to_login
    there.  But better handle each user individually.
    """
    pas = getToolByName(context, 'acl_users')
    userfolder = pas.source_users
    for user_info in userfolder.enumerateUsers():
        login = user_info.get('login')
        if not '@' in login:
            # None of our business.
            continue
        if login == login.lower():
            # Nothing to fix.
            continue
        user_id = user_info.get('id')
        user = pas.getUserById(user_id)
        email = user.getProperty('email')
        if not email:
            logger.warn("User id %s has login name %s, but no e-mail address. "
                        "I do not dare to change the login name.",
                        user_id, login)
            continue
        if email != login:
            # We will warn, but change the user anyway.
            logger.warn("User id %s has login name %s, but e-mail address %s",
                        user_id, login, email)
        # We use the e-mail property as the canonical value.
        new_login = email.lower()
        user.setProperties(email=new_login)
        userfolder.updateUser(user_id, new_login)
        logger.info("User id %s now has lowercase login name and e-mail "
                    "address: %s (was: %s)", user_id, new_login, email)
