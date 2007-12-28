import re
from Products.CMFPlone.RegistrationTool import RegistrationTool
from Products.CMFCore.MemberDataTool import MemberData
from Products.CMFCore.permissions import SetOwnProperties
from Products.CMFCore.utils import getToolByName
from AccessControl import getSecurityManager
from zope.i18nmessageid import MessageFactory

import os
here = os.path.abspath(os.path.dirname(__file__))

MessageFactory = _ = MessageFactory('collective.emaillogin')


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
    RegistrationTool._ALLOWED_MEMBER_ID_PATTERN = re.compile(
        r'^\w[\w\.\-\+@]+[a-zA-Z]$')

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
            raise ValueError(_('username is not valid, or already in use'))
        userfolder = self.acl_users.source_users
        try:
            userfolder.getUserIdForLogin(loginname)
        except KeyError:
            pass
        else:
            # let's stay a little vague here, don't give away too much info
            raise ValueError(_('username is not valid, or already in use'))
    MemberData.validateLoginName = validateLoginName

