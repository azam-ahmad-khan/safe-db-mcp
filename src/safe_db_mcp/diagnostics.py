"""Keep SQL fragments out of sqlglot's parser/generator diagnostics."""

import logging


class _PrivateParserDiagnostics(logging.Filter):
    def filter(self, record):
        record.msg = "SQL parser diagnostic suppressed (query text is private)"
        record.args = ()
        record.exc_info = record.exc_text = record.stack_info = None
        return True


# Both sqlglot's parser and generator use this logger. Install before either parses SQL.
logging.getLogger("sqlglot").addFilter(_PrivateParserDiagnostics())
