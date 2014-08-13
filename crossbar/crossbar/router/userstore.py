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


from autobahn.wamp import auth


class UserStore:
   """
   A transient (in-memory) user database.
   """

   def __init__(self):
      self._creds = {}

   def add(self, authid, authrole, secret, salt = None):
      if salt:
         key = auth.derive_key(secret, salt)
      else:
         key = secret
      self._creds[authid] = (salt, key, authrole)
      return self._creds[authid]

   def get(self, authid):
      """
      
      """
      ## we return a deferred to simulate an asynchronous lookup
      return defer.succeed(self._creds.get(authid, (None, None, None)))
