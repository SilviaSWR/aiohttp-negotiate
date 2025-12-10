aiohttp-negotiate
=================

A mixin for supporting Negotiate authentication with aiohttp.

Usage
-----

.. code::

   from aiohttp_negotiate import NegotiateClientSession

   session = NegotiateClientSession()
   resp = await session.get('https://example.com/')

Upgrade to Python>=3.5 contribution has received funding from the Spanish government (grant EQC2021-007479-P,
funded by MCIN/AEI/10.13039/501100011033), the EU NextGeneration/PRTR (PRTR-C17.I1), and the Generalitat de Catalunya.
