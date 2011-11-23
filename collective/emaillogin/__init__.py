import logging
import re
import sha
from AccessControl import AuthEncoding
from smtplib import SMTPRecipientsRefused
from Products.CMFPlone.PloneTool import PloneTool
from Products.CMFPlone.RegistrationTool import RegistrationTool
from Products.CMFPlone.RegistrationTool import _checkEmail
from Products.CMFPlone.utils import safe_hasattr
from Products.CMFCore.MemberDataTool import MemberData
from Products.CMFCore.permissions import SetOwnProperties
from Products.CMFCore.utils import getToolByName
from Products.PlonePAS.tools.membership import MembershipTool
from Products.PasswordResetTool.PasswordResetTool import PasswordResetTool
from Products.PluggableAuthService.plugins.ZODBUserManager import \
    ZODBUserManager
from AccessControl import getSecurityManager
from AccessControl import Unauthorized
from AccessControl import allow_module

from collective.emaillogin import utils as email_utils

import os
here = os.path.abspath(os.path.dirname(__file__))
logger = logging.getLogger('collective.emaillogin')

# Allow to import utils.py from restricted python , mostly for the
# message factory:
allow_module('collective.emaillogin.utils')

# And we use that factory in this init as well:
_ = email_utils.EmailLoginMessageFactory


def initialize(context):
    enable = open(os.path.join(here, 'enable.cfg')).read()
    if not enable:
        return
    try:
        enable = eval(enable)
    except SyntaxError:
        enable = False
    if not enable:
        return
    # XXX rather nasty patch to allow email addresses as username
    logger.warn('Patching RegistrationTool._ALLOWED_MEMBER_ID_PATTERN')
    RegistrationTool._ALLOWED_MEMBER_ID_PATTERN = re.compile(
        r'^\w[\w\.\-@]+[a-zA-Z]$')

    # XXX another nasty one: monkey-patch CMF's MemberData object to allow
    # changing the login name of users from Python scripts
    def setLoginName(self, loginname):
        """ allow the user to set his/her own login name
        """
        secman = getSecurityManager()
        if not secman.checkPermission(SetOwnProperties, self):
            raise Unauthorized('you are not allowed to update this login name')
        membership = getToolByName(self, 'portal_membership')
        if not membership.isAnonymousUser():
            member = membership.getAuthenticatedMember()
            userfolder = self.acl_users.source_users
            try:
                userfolder.updateUser(member.id, loginname)
            except KeyError:
                raise ValueError('you are not a Plone member (you are '
                                 'probably registered on the root user '
                                 'folder, please notify an administrator if '
                                 'this is unexpected)')
        else:
            raise Unauthorized('you need to log in to change your own '
                               'login name')

    logger.warn('Adding method MemberData.setLoginName')
    MemberData.setLoginName = setLoginName

    # similar method for validation
    def validateLoginName(self, loginname):
        secman = getSecurityManager()
        if not secman.checkPermission(SetOwnProperties, self):
            raise Unauthorized('you are not allowed to update this login name')
        if loginname == self.id:
            return
        regtool = getToolByName(self, 'portal_registration')
        if not regtool.isMemberIdAllowed(loginname):
            raise ValueError(_(
                    'message_user_name_not_valid',
                    u"User name is not valid, or already in use."))
        userfolder = self.acl_users.source_users
        try:
            userfolder.getUserIdForLogin(loginname)
        except KeyError:
            pass
        else:
            # let's stay a little vague here, don't give away too much info
            raise ValueError(_(
                    'message_user_name_not_valid',
                    u"User name is not valid, or already in use."))
    logger.warn('Adding method MemberData.validateLoginName')
    MemberData.validateLoginName = validateLoginName

    # We need to change the mailPassword method of the registration
    # tool too, otherwise users can only reset their password by
    # entering their initial email address, not their current one.
    def mailPassword(self, forgotten_userid, REQUEST):
        """ Wrapper around mailPassword """
        membership = getToolByName(self, 'portal_membership')
        if not membership.checkPermission('Mail forgotten password', self):
            raise Unauthorized("Mailing forgotten passwords has been disabled")

        utils = getToolByName(self, 'plone_utils')
        # XXX Here is the change compared to the default method.
        # Try to find this user via the login name.
        member = email_utils.getMemberByLoginName(self, forgotten_userid)

        if member is None:
            raise ValueError('The username you entered could not be found')

        # We use the id member as new forgotten_userid, as in our
        # patched version of resetPassword we ask for the real member
        # id too, instead of the login name.
        forgotten_userid = member.getId()

        # assert that we can actually get an email address, otherwise
        # the template will be made with a blank To:, this is bad
        email = member.getProperty('email')
        if not email:
            raise ValueError('That user does not have an email address.')
        else:
            # add the single email address
            if not utils.validateSingleEmailAddress(email):
                raise ValueError('The email address did not validate')
        check, msg = _checkEmail(email)
        if not check:
            raise ValueError(msg)

        # Rather than have the template try to use the mailhost, we will
        # render the message ourselves and send it from here (where we
        # don't need to worry about 'UseMailHost' permissions).
        reset_tool = getToolByName(self, 'portal_password_reset')
        reset = reset_tool.requestReset(forgotten_userid)

        email_charset = getattr(self, 'email_charset', 'UTF-8')
        mail_text = self.mail_password_template( self
                                               , REQUEST
                                               , member=member
                                               , reset=reset
                                               , password=member.getPassword()
                                               , charset=email_charset
                                               )
        if isinstance(mail_text, unicode):
            mail_text = mail_text.encode(email_charset)
        host = self.MailHost
        try:
            host.send( mail_text )

            return self.mail_password_response( self, REQUEST )
        except SMTPRecipientsRefused:
            # Don't disclose email address on failure
            raise SMTPRecipientsRefused('Recipient address rejected by server')

    logger.warn('Patching RegistrationTool.mailPassword')
    RegistrationTool.mailPassword = mailPassword

    # We need to change resetPassword from PasswordResetTool too.
    # First we save the original with an underscore.
    PasswordResetTool._resetPassword = PasswordResetTool.resetPassword

    def resetPassword(self, userid, randomstring, password):
        """Reset the password of this user.

        But the userid will most likely be a login name.
        """
        member = email_utils.getMemberByLoginName(self, userid)
        if member is not None:
            userid = member.getId()
        # If no member was found, then the following will likely fail.
        self._resetPassword(userid, randomstring, password)

    logger.warn('Patching PasswordResetTool.resetPassword')
    PasswordResetTool.resetPassword = resetPassword

    def getValidUser(self, userid):
        """Returns the member with 'userid' if available and None otherwise."""
        return email_utils.getMemberByLoginName(
            self, userid, raise_exceptions=False)

    logger.warn('Patching PasswordResetTool.getValidUser')
    PasswordResetTool.getValidUser = getValidUser

    ZODBUserManager._ori_authenticateCredentials = \
        ZODBUserManager.authenticateCredentials

    def authenticateCredentials(self, credentials):
        """ See IAuthenticationPlugin.

        o We expect the credentials to be those returned by
          ILoginPasswordExtractionPlugin.
        """
        login = credentials.get('login')
        password = credentials.get('password')

        if login is None or password is None:
            return None

        # The original implementation does this, which unhelpfully
        # falls back to giving the login as userid when the login does
        # not match a user.  This means you will seem to login: you
        # get a message "welcome, you are now logged in".  But you are
        # not actually logged in.
        #userid = self._login_to_userid.get(login, login)

        # Instead, we do some more checking ourself.
        userid = None
        if '@' not in login or login == login.lower():
            userid = self._login_to_userid.get(login)
            logger.debug("Standard authentication for %s gives userid %s",
                         login, userid)
        else:
            # So at this point we have e-mail address as login and it
            # is not lowercase.  We try the given login and then the
            # lowercase version if nothing is found.
            userid = self._login_to_userid.get(login)
            logger.debug("Original case authentication for %s gives "
                         "userid %r", login, userid)
            if not userid:
                login = login.lower()
                userid = self._login_to_userid.get(login)
                logger.debug("Lower case authentication for %s gives "
                             "userid %r", login, userid)
                if userid:
                    # Might not be needed, but just in case.
                    credentials['login'] = login
        if not userid:
            return None
        reference = self._user_passwords.get(userid)
        if reference is None:
            return None
        if AuthEncoding.is_encrypted(reference):
            if AuthEncoding.pw_validate(reference, password):
                return userid, login

        # Support previous naive behavior
        digested = sha.sha(password).hexdigest()

        if reference == digested:
            return userid, login

        return None

    logger.warn('Patching ZODBUserManager.authenticateCredentials')
    ZODBUserManager.authenticateCredentials = authenticateCredentials

    MembershipTool._ori_addMember = MembershipTool.addMember

    def addMember(self, id, password, roles, domains, properties=None):
        if '@' in id and id != id.lower():
            logger.info("Going to add member with %r lowercased.", id)
            id = id.lower()
        return self._ori_addMember(id, password, roles, domains,
                                   properties=properties)

    logger.warn('Patching MembershipTool.addMember')
    MembershipTool.addMember = addMember

    PloneTool._ori_setMemberProperties = PloneTool.setMemberProperties

    def setMemberProperties(self, member, REQUEST=None, **properties):
        # Set the member properties.  When changing the e-mail
        # address, also update the login name.  And make the e-mail
        # address lowercase.
        pas = getToolByName(self, 'acl_users')
        if safe_hasattr(member, 'getId'):
            member_id = member.getId()
        else:
            member_id = member
        user = pas.getUserById(member_id)
        update_login_name = False
        if 'email' in properties:
            new_email = properties.get('email')
            if new_email != new_email.lower():
                new_email = new_email.lower()
                properties['email'] = new_email
                if REQUEST is not None and 'email' in REQUEST:
                    REQUEST['email'] = new_email
            old_email = user.getProperty('email')
            if new_email != old_email:
                update_login_name = True
        user.setProperties(**properties)
        if update_login_name:
            logger.info("Updating login name from %s to %s", old_email,
                        new_email)
            userfolder = pas.source_users
            try:
                userfolder.updateUser(member_id, new_email)
            except KeyError:
                raise ValueError('you are not a Plone member (you are '
                                 'probably registered on the root user '
                                 'folder, please notify an administrator if '
                                 'this is unexpected)')

    logger.warn('Patching PloneTool.setMemberProperties')
    PloneTool.setMemberProperties = setMemberProperties
