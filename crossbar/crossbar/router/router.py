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
   'CrossbarRouter',
   'CrossbarRouterFactory',
)

from twisted.python import log

from autobahn.wamp import types
from autobahn.twisted.wamp import Router, RouterFactory
from autobahn.wamp.interfaces import IRouter

from crossbar.router.role import CrossbarRouterRoleStaticAuth, \
                                 CrossbarRouterRoleDynamicAuth, \
                                 CrossbarRouterTrustedRole



class CrossbarRouter(Router):
   """
   Crossbar.io core router class. This provides routing of calls and events
   with a given realm.
   """

   RESERVED_ROLES = ["trusted"]
   """
   Roles with these URIs are built-in and cannot be added/dropped.
   """


   def __init__(self, factory, realm, options = None):
      """
      
      :param factory: The router factory this router was created by.
      :type factory: instance of :class:`crossbar.router.session.CrossbarRouterFactory`
      :param realm: The realm this router manages.
      :type realm: unicode
      :param options: Router options.
      :type options: None or instance of :class:`autobahn.wamp.types.RouterOptions`
      """
      uri = realm.config['name']
      Router.__init__(self, factory, uri, options)
      self._roles = {
         "trusted": CrossbarRouterTrustedRole(self, "trusted", debug = self.debug)
      }
      self._realm = realm
      #self.debug = True


   def has_role(self, uri):
      """
      Check if a role with given URI exists on this router.

      :returns: bool - `True` if a role under the given URI exists on this router.
      """
      return uri in self._roles


   def add_role(self, role):
      """
      Adds a role to this router.

      :param role: The role to add.
      :type role: An instance of :class:`crossbar.router.session.CrossbarRouterRole`.

      :returns: bool -- `True` if a role under the given URI actually existed before and was overwritten.
      """
      if self.debug:
         log.msg("CrossbarRouter.add_role", role)

      if role.uri in self.RESERVED_ROLES:
         raise Exception("cannot add reserved role '{}'".format(role.uri))

      overwritten = role.uri in self._roles

      self._roles[role.uri] = role

      return overwritten


   def drop_role(self, uri):
      """
      Drops a role from this router.

      :param uri: The URI of the role to drop.
      :type uri: str

      :returns: bool -- `True` if a role under the given URI actually existed and was removed.
      """
      if self.debug:
         log.msg("CrossbarRouter.drop_role", role)

      if role.uri in self.RESERVED_ROLES:
         raise Exception("cannot drop reserved role '{}'".format(role.uri))

      if uri in self._roles:
         del self._roles[uri]
         return True
      else:
         return False


   def authorize(self, session, uri, action):
      """
      Authorizes a session for an action on an URI.

      Implements :func:`autobahn.wamp.interfaces.IRouter.authorize`
      """
      role = session._authrole
      action = IRouter.ACTION_TO_STRING[action]

      authorized = False
      if role in self._roles:
         authorized = self._roles[role].authorize(session, uri, action)

      if self.debug:
         log.msg("CrossbarRouter.authorize: {} {} {} {} {} {} {} -> {}".format(session._session_id, uri, action, session._authid, session._authrole, session._authmethod, session._authprovider, authorized))

      return authorized



class CrossbarRouterFactory(RouterFactory):
   """
   Crossbar.io core router factory.
   """

   def __init__(self, options = None, debug = False):
      """
      Ctor.
      """
      options = types.RouterOptions(uri_check = types.RouterOptions.URI_CHECK_LOOSE)
      RouterFactory.__init__(self, options, debug)


   def __getitem__(self, realm):
      return self._routers[realm]


   def __contains__(self, realm):
      return realm in self._routers


   def get(self, realm):
      """
      Implements :func:`autobahn.wamp.interfaces.IRouterFactory.get`
      """
      return self._routers[realm]


   def start_realm(self, realm):
      """
      Starts a realm on this router.

      :param realm: The realm to start.
      :type realm: instance of :class:`crossbar.worker.router.RouterRealm`.
      """
      if self.debug:
         log.msg("CrossbarRouterFactory.start_realm(realm = {})".format(realm))

      uri = realm.config['name']
      assert(uri not in self._routers)

      self._routers[uri] = CrossbarRouter(self, realm, self._options)
      if self.debug:
         log.msg("Router created for realm '{}'".format(uri))


   def stop_realm(self, realm):
      if self.debug:
         log.msg("CrossbarRouterFactory.stop_realm(realm = {})".format(realm))


   def add_role(self, realm, config):
      if self.debug:
         log.msg("CrossbarRouterFactory.add_role(realm = {}, config = {})".format(realm, config))

      assert(realm in self._routers)

      router = self._routers[realm]
      uri = config['name']

      if 'permissions' in config:
         role = CrossbarRouterRoleStaticAuth(router, uri, config['permissions'], debug = self.debug)
      elif 'authorizer' in config:
         role = CrossbarRouterRoleDynamicAuth(router, uri, config['authorizer'], debug = self.debug)
      else:
         role = CrossbarRouterRole(router, uri, debug = self.debug)

      router.add_role(role)


   def drop_role(self, realm, role):
      if self.debug:
         log.msg("CrossbarRouterFactory.drop_role(realm = {}, role = {})".format(realm, role))
