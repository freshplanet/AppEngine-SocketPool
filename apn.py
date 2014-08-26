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
import binascii
import json
import logging
import os
import struct

from socketPool import PooledConnection


class APNSender(PooledConnection):
    """
    Send your notifications using:
    
    APNSender(certFileName, hostName, requests).run()
    
    """
    GATEWAY_PORT = 2195
    
    def __init__(self, certFileName, hostName, requests):
        """
        @param certFileName: Name certificate file located inside the 'certificates' directory of this package.
                                Ex: 'SongPopFree.dev.pem'
        @param hostName: Host. Like 'gateway.sandbox.push.apple.com'
        @param requests: list of (token, payload) for notifications to send through the connection.
                            token: binary data for the device push token
                            payload: str
        
        """
        poolName = '%s_%s' % (certFileName, hostName)
        pemPath = os.path.join(os.path.dirname(__file__), "certificates", certFileName)
        
        PooledConnection.__init__(self, poolName, hostName, self.GATEWAY_PORT, pemPath=pemPath)
        
        self.requests = requests
        
    def communicate(self, connection):
        """
        Encode and send our requests to APNs
        """
        # TODO: Make this a tasklet by integrating sockets operations to our NDB loop
        for notif in self.requests:
            if not notif:
                continue
            token, payload = notif
            fmt = "!cH32sH%ds" % len(payload)
            msg = struct.pack(fmt, '\x00', 32, token, len(payload), payload)
            
            try:
                connection.write(msg)
            except IOError as e:
                logging.warn("IOError while writing: %r. The socket has probably expired, we try with a new one.", e)
                connection = self.getNewConnection()
                # This time if it fails we raise the error
                connection.write(msg)
        return connection, True


def getNotifRequest(token, message, badge=None, sound="default", context=None, hasContent=True):
    """
    Builds an object that will be used to send a notification to a single device.
    Pass this object into "APNSender" list of notification requests.
    
    @param token: push token given by iOS App (string).
    @param message: The message you want to send
    @param badge: None to ignore, 0 to clear the badge, other to update it.
    @param sound: None for no sound
    @param context: A dict of custom params you want to send
    @param hasContent: flags message as having 'content-available' (background fetch)
    
    @return: False if can't build the request, otherwise an object to be given to APNSender.
    """
    if isinstance(message, str):
        # json.dumps with ensure_ascii false wants unicode
        message = message.decode('utf-8')
    
    payload = context.copy() if context else {}
    payload['aps'] = {'alert': message}
    
    if hasContent:
        payload['aps']['content-available'] = 1

    if badge is not None:
        payload['aps']['badge'] = badge
    if sound:
        payload['aps']['sound'] = sound
    
    # This ensures that we strip any whitespace to fit in the 256 bytes
    # Also with non-ascii characters, we can use unicode formatting as it's supported by Apple => shorter
    payload = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    if isinstance(payload, unicode):
        payload = payload.encode('utf-8')
    
    if len(payload) > 256:
        logging.error("The JSON generated is too large: %s", payload)
        return False
    
    try:
        token = binascii.unhexlify(token)
    except (TypeError, UnicodeEncodeError):
        logging.warn("Invalid APNs token: %r", token)
        return False
    
    return (token, payload)
