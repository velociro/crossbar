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
   'CrossbarRouterSession',
   'CrossbarRouterSessionFactory',
   'CrossbarRouterServiceSession'
)

import json
import datetime
import traceback

from six.moves import urllib

from twisted.python import log
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue

from autobahn import util
from autobahn.websocket import http
from autobahn.websocket.compress import *

from autobahn import wamp
from autobahn.wamp import types
from autobahn.wamp import message
from autobahn.wamp.exception import ApplicationError
from autobahn.twisted.wamp import ApplicationSession
from autobahn.twisted.wamp import RouterSession, RouterSessionFactory

import crossbar

from crossbar.router.userstore import UserStore



class CrossbarRouterSession(RouterSession):
   """
   Router-side of (non-embedded) Crossbar.io WAMP sessions.
   """

   def onOpen(self, transport):
      """
      Implements :func:`autobahn.wamp.interfaces.ITransportHandler.onOpen`
      """
      RouterSession.onOpen(self, transport)

      if hasattr(self._transport, 'factory') and hasattr(self._transport.factory, '_config'):
         self._transport_config = self._transport.factory._config
      else:
         self._transport_config = {}

      self._pending_auth = None
      self._session_details = None


   #@inlineCallbacks
   def onHello(self, realm, details):

      try:

         ## check if the realm the session wants to join actually exists
         ##
         if realm not in self._router_factory:
            return types.Deny(ApplicationError.NO_SUCH_REALM, message = "no realm '{}' exists on this router".format(realm))

         router = self._router_factory[realm]

         authmethods = details.authmethods or ["anonymous"]

         reply, pending = router.authenticate(self, authmethods, details.authid)

         print "5"*10, reply, pending

         #returnValue(reply)

         return reply

      except Exception as e:
         traceback.print_exc()
         return types.Deny(message = "internal error: {}".format(e))


   def onHello2(self, realm, details):

      try:

         ## check if the realm the session wants to join actually exists
         ##
         if realm not in self._router_factory:
            return types.Deny(ApplicationError.NO_SUCH_REALM, message = "no realm '{}' exists on this router".format(realm))

         router = self._router_factory[realm]
         print "444", router, type(router)

         ## perform authentication
         ##
         if self._transport._authid is not None:

            ## already authenticated .. e.g. via cookie

            ## check if role still exists on realm
            ##
            allow = self._router_factory[realm].has_role(self._transport._authrole)

            if allow:
               return types.Accept(authid = self._transport._authid,
                                   authrole = self._transport._authrole,
                                   authmethod = self._transport._authmethod,
                                   authprovider = 'transport')
            else:
               return types.Deny(ApplicationError.NO_SUCH_ROLE, message = "session was previously authenticated (via transport), but role '{}' no longer exists on realm '{}'".format(self._transport._authrole, realm))

         else:
            ## if authentication is enabled on the transport ..
            ##
            if "auth" in self._transport_config:

               ## iterate over authentication methods announced by client ..
               ##
               for authmethod in details.authmethods or ["anonymous"]:

                  ## .. and if the configuration has an entry for the authmethod
                  ## announced, process ..
                  if authmethod in self._transport_config["auth"]:


                     ## "Mozilla Persona" authentication
                     ##
                     if authmethod == "mozilla_persona":
                        cfg = self._transport_config['auth']['mozilla_persona']

                        audience = cfg.get('audience', self._transport._origin)
                        provider = cfg.get('provider', "https://verifier.login.persona.org/verify")

                        ## authrole mapping
                        ##
                        authrole = cfg.get('role', 'anonymous')

                        ## check if role exists on realm anyway
                        ##
                        if not self._router_factory[realm].has_role(authrole):
                           return types.Deny(ApplicationError.NO_SUCH_ROLE, message = "authentication failed - realm '{}' has no role '{}'".format(realm, authrole))

                        ## ok, now challenge the client for doing Mozilla Persona auth.
                        ##
                        self._pending_auth = PendingAuthPersona(provider, audience, authrole)
                        return types.Challenge("mozilla-persona")


                     ## "Anonymous" authentication
                     ##
                     elif authmethod == "anonymous":
                        cfg = self._transport_config['auth']['anonymous']

                        ## authrole mapping
                        ##
                        authrole = cfg.get('role', 'anonymous')

                        ## check if role exists on realm anyway
                        ##
                        if not self._router_factory[realm].has_role(authrole):
                           return types.Deny(ApplicationError.NO_SUCH_ROLE, message = "authentication failed - realm '{}' has no role '{}'".format(realm, authrole))

                        ## authid generation
                        ##
                        if self._transport._cbtid:
                           ## if cookie tracking is enabled, set authid to cookie value
                           ##
                           authid = self._transport._cbtid
                        else:
                           ## if no cookie tracking, generate a random value for authid
                           ##
                           authid = util.newid(24)

                        self._transport._authid = authid
                        self._transport._authrole = authrole
                        self._transport._authmethod = authmethod

                        return types.Accept(authid = authid, authrole = authrole, authmethod = self._transport._authmethod)


                     ## "WAMP-CRA" authentication
                     ##
                     elif authmethod == "wampcra":

                        cfg = self._transport_config['auth']['wampcra']

                        # audience = cfg.get('audience', self._transport._origin)
                        # provider = cfg.get('provider', "https://verifier.login.persona.org/verify")

                        # ## authrole mapping
                        # ##
                        # authrole = cfg.get('role', 'anonymous')

                        # ## check if role exists on realm anyway
                        # ##
                        # if not self._router_factory[realm].has_role(authrole):
                        #    return types.Deny(ApplicationError.NO_SUCH_ROLE, message = "authentication failed - realm '{}' has no role '{}'".format(realm, authrole))

                        # ## ok, now challenge the client for doing Mozilla Persona auth.
                        # ##
                        # self._pending_auth = PendingAuthPersona(provider, audience, authrole)
                        # return types.Challenge("mozilla-persona")


                     ## "Cookie" authentication
                     ##
                     elif authmethod == "cookie":
                        pass
                        # if self._transport._cbtid:
                        #    cookie = self._transport.factory._cookies[self._transport._cbtid]
                        #    authid = cookie['authid']
                        #    authrole = cookie['authrole']
                        #    authmethod = "cookie.{}".format(cookie['authmethod'])
                        #    return types.Accept(authid = authid, authrole = authrole, authmethod = authmethod)
                        # else:
                        #    return types.Deny()

                     else:
                        log.msg("unknown authmethod '{}'".format(authmethod))
                        return types.Deny(message = "unknown authentication method {}".format(authmethod))


               ## if authentication is configured, by default, deny.
               ##
               return types.Deny(message = "authentication using method '{}' denied by configuration".format(authmethod))


            else:
               ## if authentication is _not_ configured, by default, allow anyone.
               ##

               ## authid generation
               ##
               if self._transport._cbtid:
                  ## if cookie tracking is enabled, set authid to cookie value
                  ##
                  authid = self._transport._cbtid
               else:
                  ## if no cookie tracking, generate a random value for authid
                  ##
                  authid = util.newid(24)


               return types.Accept(authid = authid, authrole = "anonymous", authmethod = "anonymous")

      except Exception as e:
         traceback.print_exc()
         return types.Deny(message = "internal error: {}".format(e))



   def onAuthenticate(self, signature, extra):

      if isinstance(self._pending_auth, PendingAuthPersona):

         dres = Deferred()

         ## The client did it's Mozilla Persona authentication thing
         ## and now wants to verify the authentication and login.
         assertion = signature
         audience = str(self._pending_auth.audience) # eg "http://192.168.1.130:8080/"
         provider = str(self._pending_auth.provider) # eg "https://verifier.login.persona.org/verify"

         ## To verify the authentication, we need to send a HTTP/POST
         ## to Mozilla Persona. When successful, Persona will send us
         ## back something like:

         # {
         #    "audience": "http://192.168.1.130:8080/",
         #    "expires": 1393681951257,
         #    "issuer": "gmail.login.persona.org",
         #    "email": "tobias.oberstein@gmail.com",
         #    "status": "okay"
         # }

         headers = {'Content-Type': 'application/x-www-form-urlencoded'}
         body = urllib.urlencode({'audience': audience, 'assertion': assertion})

         from twisted.web.client import getPage
         d = getPage(url = provider,
                     method = 'POST',
                     postdata = body,
                     headers = headers)

         log.msg("Authentication request sent.")

         def done(res):
            res = json.loads(res)
            try:
               if res['status'] == 'okay':

                  ## awesome: Mozilla Persona successfully authenticated the user
                  self._transport._authid = res['email']
                  self._transport._authrole = self._pending_auth.role
                  self._transport._authmethod = 'mozilla_persona'

                  log.msg("Authenticated user {} with role {}".format(self._transport._authid, self._transport._authrole))
                  dres.callback(types.Accept(authid = self._transport._authid, authrole = self._transport._authrole, authmethod = self._transport._authmethod))

                  ## remember the user's auth info (this marks the cookie as authenticated)
                  if self._transport._cbtid and self._transport.factory._cookiestore:
                     cs = self._transport.factory._cookiestore
                     cs.setAuth(self._transport._cbtid, self._transport._authid, self._transport._authrole, self._transport._authmethod)

                     ## kick all sessions using same cookie (but not _this_ connection)
                     if True:
                        for proto in cs.getProtos(self._transport._cbtid):
                           if proto and proto != self._transport:
                              try:
                                 proto.close()
                              except Exception as e:
                                 pass
               else:
                  log.msg("Authentication failed!")
                  log.msg(res)
                  dres.callback(types.Deny(reason = "wamp.error.authorization_failed", message = res.get("reason", None)))
            except Exception as e:
               log.msg("internal error during authentication verification: {}".format(e))
               dres.callback(types.Deny(reason = "wamp.error.internal_error", message = str(e)))

         def error(err):
            log.msg("Authentication request failed: {}".format(err.value))
            dres.callback(types.Deny(reason = "wamp.error.authorization_request_failed", message = str(err.value)))

         d.addCallbacks(done, error)

         return dres

      else:

         log.msg("don't know how to authenticate")

         return types.Deny()


   def onJoin(self, details):

      self._session_details = {
         'authid': details.authid,
         'authrole': details.authrole,
         'authmethod': details.authmethod,
         'authprovider': details.authprovider,
         'realm': details.realm,
         'session': details.session
      }

      ## dispatch session metaevent from WAMP AP
      ##
      msg = message.Publish(0, u'wamp.metaevent.session.on_join', [self._session_details])
      self._router.process(self, msg)


   def onLeave(self, details):

      ## dispatch session metaevent from WAMP AP
      ##
      msg = message.Publish(0, u'wamp.metaevent.session.on_leave', [self._session_details])
      self._router.process(self, msg)
      self._session_details = None

      ## if asked to explicitly close the session ..
      if details.reason == u"wamp.close.logout":

         ## if cookie was set on transport ..
         if self._transport._cbtid and self._transport.factory._cookiestore:
            cs = self._transport.factory._cookiestore

            ## set cookie to "not authenticated"
            cs.setAuth(self._transport._cbtid, None, None, None)

            ## kick all session for the same auth cookie
            for proto in cs.getProtos(self._transport._cbtid):
               proto.sendClose()



class CrossbarRouterSessionFactory(RouterSessionFactory):
   """
   Factory creating the router side of (non-embedded) Crossbar.io WAMP sessions.
   This is the session factory that will given to router transports.
   """
   session = CrossbarRouterSession



class CrossbarRouterServiceSession(ApplicationSession):
   """
   Router service session which is used internally by a router to
   issue WAMP calls or publish events.
   """

   def __init__(self, config, schemas = None):
      """
      Ctor.

      :param config: WAMP application component configuration.
      :type config: Instance of :class:`autobahn.wamp.types.ComponentConfig`.
      :param schemas: An (optional) initial schema dictionary to load.
      :type schemas: dict
      """
      ApplicationSession.__init__(self, config)
      self._schemas = {}
      if schemas:
         self._schemas.update(schemas)
         print("CrossbarRouterServiceSession: initialized schemas cache with {} entries".format(len(self._schemas)))


   @inlineCallbacks
   def onJoin(self, details):
      if self.debug:
         log.msg("CrossbarRouterServiceSession.onJoin({})".format(details))

      regs = yield self.register(self)
      if self.debug:
         log.msg("CrossbarRouterServiceSession: registered {} procedures".format(len(regs)))


   @wamp.register('wamp.reflect.describe')
   def describe(self, uri = None):
      """
      Describe a given URI or all URIs.

      :param uri: The URI to describe or `None` to retrieve all declarations.
      :type uri: str

      :returns: list -- A list of WAMP declarations.
      """
      if uri:
         return self._schemas.get(uri, None)
      else:
         return self._schemas


   @wamp.register('wamp.reflect.define')
   def define(self, uri, schema):
      """
      Declare metadata for a given URI.

      :param uri: The URI for which to declare metadata.
      :type uri: str
      :param decl: The WAMP schema declaration for
         the URI or `None` to remove any declarations for the URI.
      :type decl: dict

      :returns: bool -- `None` if declaration was unchanged, `True` if
         declaration was new, `False` if declaration existed, but was modified.
      """
      if not schema:
         if uri in self._schemas:
            del self._schemas
            self.publish('wamp.reflect.on_undefine', uri)
            return uri
         else:
            return None

      if uri not in self._schemas:
         was_new = True
         was_modified = False
      else:
         was_new = False
         if json.dumps(schema) != json.dumps(self._schemas[uri]):
            was_modified = True
         else:
            was_modified = False

      if was_new or was_modified:
         self._schemas[uri] = schema
         self.publish('wamp.reflect.on_define', uri, schema, was_new)
         return was_new
      else:
         return None
