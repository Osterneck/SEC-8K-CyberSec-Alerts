# Google Python Style Notes

This rough draft follows the Google Python style model where practical:

- descriptive module, class, function, and variable names
- lowercase_with_underscores for functions and variables
- CapWords classes
- module-level constants in ALL_CAPS
- import grouping: future, standard library, local package
- docstrings on public modules, classes, and functions
- Args / Returns / Attributes sections for non-trivial public interfaces
- explicit exception types and contextual re-raising at network boundaries
- type annotations on public and internal interfaces
- small functions and single-purpose modules
- no wildcard imports
- no mutable default arguments
- deterministic business rules separated from I/O
- tests named by behavior

The code avoids formatter-specific syntax so it remains compatible with future
CI enforcement using Ruff, Pyink/Black, pylint, or an internal Google-style
configuration.
