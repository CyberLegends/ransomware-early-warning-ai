# Contributing

Open a repository-specific issue with a synthetic example before proposing a substantial integration. Keep defensive scope, deterministic evidence, bounded tools and explicit AI fallback behavior clear.

Run `python -m unittest discover -s tests -v` and the demo before submitting a pull request. Add meaningful regression coverage when behavior or trust boundaries change. Use fictional identifiers; do not commit real endpoint logs, keys, credentials or approval records.

New vendor adapters must document schema mappings, collection coverage and normalized counter semantics. New agent tools must validate permissions outside the model and accept no arbitrary execution paths. Any live response capability needs a separate reviewed architecture and operational authorization design.
