# -*- coding: utf-8 -*-
'''
Copyright 2014 FreshPlanet (http://freshplanet.com | opensource@freshplanet.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
import logging
import random
from socket import socket, AF_INET, SOCK_STREAM

from google.appengine.ext import ndb

from tlslite import TLSConnection, X509, X509CertChain, parsePEMKey


class PooledConnection(object):
    """
    Manage a pool of sockets to a same destination (host, port, certificate).
    Sockets are created and managed as the demand evolves,
    trying to optimize the re-utilization of each socket.
    
    This is an abstract class, you need to implement 'communicate' to start using it.
    Then you can instantiate a new PooledConnection subclass each time you need to send something,
    and use the 'run' or 'runAsync' methods.
    """
    
    # File path -> (X509CertChain, RSAKey)
    _AUTH_CACHE = {}
    
    _SOCKET_EXPIRE = 120  # seconds. That's how long an inactive socket remains open on AppEngine
    
    def __init__(self, poolName, host, port, pemPath=None):
        """
        @param poolName: Identify the kind of connection you open.
                         We will create and manage new sockets as needed as the demand evolves.
                         Basically it should be unique per (host, port, certificate).
        @param host:
        @param port:
        @type pemPath: Absolute path to the certificate file to use.
                       Override 'getCertChainKey' if you need another way to retrieve your certificate information.
        """
        self.poolName = poolName
        self.host = host
        self.port = port
        self._pemPath = pemPath
    
    def communicate(self, connection):
        """
        Given an open connection, do the stuff you need to do with it.
        This will be called via the 'run' or 'runAsync' methods with the connection you should use.
        
        If this returns a Future, the future is waited upon before returning the final result to 'run'.
        (This means you can make a tasklet out of 'communicate')
        
        If this raises an exception, the connection is removed from the pool and not re-used.
        
        @return: tuple (connection, result)
                    'connection' can be either the input connection or a newly created one
                    (in which case the new one will replace the input one in the pool)
                    'result' will be passed as returned value for run().
        """
        raise NotImplementedError()

    def run(self):
        """
        Find a connection to re-use and call 'communicate' to execute your custom logic.
        Once communicate() is done, if no error is raised, the connection is returned to the pool.
        """
        return self.runAsync().get_result()
    
    @ndb.tasklet
    def runAsync(self):
        """
        Asynchronous version of 'run'.
        
        @rtype: ndb.Future
        """
        connId, connection = yield self._findConnection()
        
        output = self.communicate(connection)
        if isinstance(output, ndb.Future):
            output = yield output
        connection, result = output
        
        yield self._saveConnection(connId, connection)
        raise ndb.Return(result)
    
    def getCertChainKey(self):
        """
        Retrieve cert chain and private key to use.
        
        By default we use the constructor parameter 'pemPath' and read the file.
        Override this if you have a custom way to retrieve them.
        
        @rtype: tuple (X509CertChain, RSAKey)
        """
        return self.getAuthFromPEM(self._pemPath)
    
    def getNewConnection(self):
        """
        Initialize a new serializable TLSConnection.
        """
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.host, self.port))
        connection = TLSConnection(sock)
        chain, key = self.getCertChainKey()
        connection.handshakeClientCert(chain, key)
        return connection
    
    @classmethod
    def getAuthFromPEM(cls, certFilePath):
        """
        Utility to read a .pem file and return the objects used by TLSConnection to authenticate the connection.
        These objects are cached in memory.
        
        @return: certChain, privateKey
        @rtype: tuple (X509CertChain, RSAKey)
        """
        if certFilePath not in cls._AUTH_CACHE:
            with open(certFilePath) as f:
                s = f.read()
            
            x509 = X509()
            x509.parse(s)
            certChain = X509CertChain([x509])
            privateKey = parsePEMKey(s, private=True)
            cls._AUTH_CACHE[certFilePath] = (certChain, privateKey)
        
        return cls._AUTH_CACHE[certFilePath]
    
    @ndb.tasklet
    def _findConnection(self):
        """
        Find an available connection in a pool.
        Create one and update the poll if needed.
        """
        ctx = ndb.get_context()
        keySuffix = "TLSConnection_%s" % self.poolName
        
        # We can have several active connections to reuse.
        poolSize = yield ctx.memcache_get('poolSize_' + keySuffix)
        if poolSize:
            # If too many connections in pool, look for a subset.
            # This means we plan to have enough connections to always have one tenth available.
            if poolSize > 10:
                index = random.randint(0, poolSize - 10)
                numbers = range(index, index + 10)
            else:
                numbers = range(0, poolSize)
        else:
            numbers = []
            
        availability = {}
        for number in numbers:
            connId = 'poolItem_' + str(number) + '_' + keySuffix
            availability[connId] = ctx.memcache_get('lock_' + connId)
        availableIds = []
        for connId, fut in availability.items():
            result = yield fut
            if not result:
                availableIds.append(connId)
        
        # Not enough connections in pool: increase size and allocate one
        # Increase faster than we decrease to avoid being too short too often
        if not availableIds:
            increment = 2 if poolSize else 1
            poolSize = yield ctx.memcache_incr('poolSize_' + keySuffix, delta=increment, initial_value=0)
            if poolSize:
                logging.info("Pool too small, we increased it (+%i). New size: %s", increment, poolSize)
                for i in xrange(increment):
                    availableIds.append('poolItem_' + str(poolSize - 1 - i) + '_' + keySuffix)
            else:
                logging.error("Failed to increase pool size. We won't use the pooling this time.")
                raise ndb.Return((None, self.getNewConnection()))
        
        # If too many connections available, reduce the pool size.
        elif len(availableIds) > 1 and len(availableIds) == len(availability):
            # 50 calls with all available => reduce size
            if random.random() < 0.02:
                ctx.memcache_decr('poolSize_' + keySuffix, delta=1)
                logging.info("Pool too large, we reduce its size (%s) by 1", poolSize)
            
        # Pick one connection and lock it
        connId = random.choice(availableIds)
        connFut = ctx.memcache_get(connId)
        locked = yield ctx.memcache_add('lock_' + connId, True, time=60)
        if locked:
            try:
                connection = yield connFut
                if not connection:
                    logging.debug("Create connection with ID %s", connId)
                    connection = self.getNewConnection()
                elif connection.closed:
                    logging.debug("Closed connection found. Re-open it: %s", connId)
                    connection = self.getNewConnection()
                else:
                    logging.debug("Re-use connection with ID %s", connId)
            except Exception as e:
                # Release the lock if we failed to retrieve or create a new connection for this slot.
                yield ctx.memcache_delete('lock_' + connId)
                raise e
        else:
            # Failed to book our connection.
            # We won't retry but create one just for this time, with no associated pool.
            # Also increase pool as it's probably because of concurrency
            logging.warn("Failed to lock connection %s. Increasing pool size.", connId)
            ctx.memcache_incr('poolSize_' + keySuffix, delta=1, initial_value=0)
            connId = None
            connection = self.getNewConnection()
            
        raise ndb.Return((connId, connection))
    
    @ndb.tasklet
    def _saveConnection(self, connId, connection):
        """ Set the connection back to the pool and unlock it. """
        if connId and connection:
            ctx = ndb.get_context()
            # Save the connection for 2 minutes max: after that the socket expires.
            yield ctx.memcache_set(connId, connection, time=self._SOCKET_EXPIRE)
            yield ctx.memcache_delete('lock_' + connId)
