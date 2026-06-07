"""Python fixture that intentionally contains a syntax error.

Expected parse output:
  - FILE node with parse_error=True
  - No FUNCTION nodes emitted (extraction halts on error)
"""

# This function definition is deliberately malformed to trigger tree-sitter parse_error.
def broken_function(x, y
    return x + y  # missing closing paren
