###############################################################################
##
##  Copyright (C) 2014 Tavendo GmbH
##
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU Affero General Public License, version 3,
##  as published by the Free Software Foundation.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
##  GNU Affero General Public License for more details.
##
##  You should have received a copy of the GNU Affero General Public License
##  along with this program. If not, see <http://www.gnu.org/licenses/>.
##
###############################################################################

from __future__ import absolute_import

__all__ = (
   'PendingAuth',
   'PendingAuthPersona',
   'PendingAuthWampCra',
)

from twisted.python import log

from autobahn.wamp import auth



class PendingAuth:
   """
   Base class for pending WAMP authentications.
   """



class PendingAuthPersona(PendingAuth):
   """
   Pending Mozilla Persona authentication.
   """
   def __init__(self, provider, audience, role = None):
      self.provider = provider
      self.audience = audience
      self.role = role



class PendingAuthWampCra(PendingAuth):
   """
   Pending WAMP-CRA authentication.
   """

   def __init__(self, key, session, authid, authrole, authmethod, authprovider):
      self.authid = authid
      self.authrole = authrole
      self.authmethod = authmethod
      self.authprovider = authprovider

      self.session = session
      self.timestamp = util.utcnow()
      self.nonce = util.newid()

      challenge_obj = {
         'authid': self.authid,
         'authrole': self.authrole,
         'authmethod': self.authmethod,
         'authprovider': self.authprovider,
         'session': self.session,
         'nonce': self.nonce,
         'timestamp': self.timestamp
      }
      self.challenge = json.dumps(challenge_obj)
      self.signature = auth.compute_wcs(key, self.challenge)




class CrossbarAuthMethod:

   ID = None

   def __init__(self, router, debug = False):
      """

      :param router: The router this role exists on.
      :type router: instance of :class:`crossbar.router.router.CrossbarRouter`
      :param debug: Flag to turn on debug logging.
      :type debug: bool
      """
      self.router = router
      self.debug = debug



class CrossbarAuthMethodAnonymous(CrossbarAuthMethod):

   ID = 'anonymous'




class CrossbarAuthMethodWampCra(CrossbarAuthMethod):

   ID = 'wampcra'



class CrossbarAuthMethodDynamic(CrossbarAuthMethod):

   ID = 'custom'

   def __init__(self, router, authorizer, debug = False):
      """

      :param router: The router this role exists on.
      :type router: instance of :class:`crossbar.router.router.CrossbarRouter`
      :param authenticator: The URI of the custom authentication procedure.
      :type unicode
      :param debug: Flag to turn on debug logging.
      :type debug: bool
      """
      CrossbarRouterRole.__init__(self, router, uri, debug)
      self._authorizer = authorizer
      self._session = router._realm.session


   def authorize(self, session, uri, action):
      """
      Authorize a session connected under this role to perform the given action
      on the given URI.

      :param session: The WAMP session that requests the action.
      :type session: Instance of :class:`autobahn.wamp.protocol.ApplicationSession`
      :param uri: The URI on which to perform the action.
      :type uri: str
      :param action: The action to be performed.
      :type action: str

      :return: bool -- Flag indicating whether session is authorized or not.
      """
      if self.debug:
         log.msg("CrossbarRouterRoleDynamicAuth.authorize", self.uri, uri, action)
      return self._session.call(self._authorizer, session._session_details, uri, action)
