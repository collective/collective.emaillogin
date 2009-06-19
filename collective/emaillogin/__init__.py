import logging
import re
from smtplib import SMTPRecipientsRefused
from Products.CMFPlone.RegistrationTool import RegistrationTool
from Products.CMFPlone.RegistrationTool import _checkEmail
from Products.CMFCore.MemberDataTool import MemberData
from Products.CMFCore.permissions import SetOwnProperties
from Products.CMFCore.utils import getToolByName
from Products.PasswordResetTool.PasswordResetTool import PasswordResetTool
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
