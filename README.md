## Socket pooling on AppEngine ##

An efficient and scalable way to re-use outbound sockets on Google AppEngine Python.
Can be used to easily reach Apple Push Notification service and send each of your notifications as they come in while still re-using your socket connections.

To re-use sockets, we take a different approach than described here for Java (http://googlecloudplatform.blogspot.fr/2013/07/google-app-engine-takes-pain-out-of-sending-ios-push-notifications.html)
as we are not satisfied with having a predefined amount of workers to process the incoming notifications, and this for each configuration (host, certificate) we have.
We want something flexible and that scales from 0 to thousands of notifications per second without having to change any settings.

The idea is to use the fact that Socket descriptors are serializable, can be stored in memcache and shared between instances.
However for a TLS connection this means we need a pure Python implementation of it. For this purpose we use the TLSlite library and a pure Python implementation of sha1 and md5.
So we sacrifice speed here but compared to the time needed to enqueue tasks and process them later it seems worth it.


You will find two modules:

- socketPool.py managing re-using connections to a single host.
- apn.py making use of socketPool.py to implement sending notifications to Apple devices.


In tlslite we patched the tlslite.utils.compat.py to import sha1 and md5 from tlslite.pickable instead of relying on hashlib.