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
