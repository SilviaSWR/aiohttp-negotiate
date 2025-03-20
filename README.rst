aiohttp-negotiate
=================

A mixin for supporting Negotiate authentication with aiohttp.

Usage
-----

.. code::

   from aiohttp_negotiate import NegotiateClientSession

   session = NegotiateClientSession()
   resp = await session.get('https://example.com/')


