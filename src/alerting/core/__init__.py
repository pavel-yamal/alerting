"""Pure trusted computing base: no I/O, no network, no database, no clock reads.

Everything in this package is a pure function of its arguments. Time arrives via an
injected ``Clock``; keys arrive as arguments. This is what makes the trust decision
testable in isolation and identical on server and client.
"""
