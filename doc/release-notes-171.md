Template Provider
-----------------

- The coinbase sigops a client announces in `CoinbaseOutputConstraints` were
  ignored: the node always reserved 400. A client whose coinbase outputs need
  more than 400 could get a template that becomes invalid once it adds them,
  in a block close to the sigops limit. This is fixed (#171).

  The fix makes Stratum Reference Implementation (SRI) roles before v1.5.0
  theoretically unsafe to use: v1.3.0 and v1.4.0 announce too few sigops for
  legacy outputs such as P2PKH, which could produce an invalid block close to
  the sigops limit. Older versions omit the field, and are now disconnected.
  Use SRI v1.5.0 or later, or any sv2-apps release.
