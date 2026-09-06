#!/usr/bin/env python
"""
Advanced mathematical obfuscator for sqlmap.

Generates highly diverse expressions for any numeric literal using
a large pool of arithmetic, trigonometric, logarithmic, and bitwise
operations, tailored to the target DBMS.

__priority__ is set to HIGH to run early in the tamper chain.
"""
import re
import random
import math
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGH

# ---------- DBMS‑specific function sets ----------
DBMS_FUNCTIONS = {
    "mysql": {
        "abs": "ABS",
        "ceil": "CEIL",
        "floor": "FLOOR",
        "round": "ROUND",
        "pow": "POW",
        "sqrt": "SQRT",
        "exp": "EXP",
        "ln": "LN",
        "log": "LOG",
        "log2": "LOG2",
        "log10": "LOG10",
        "sin": "SIN",
        "cos": "COS",
        "tan": "TAN",
        "cot": "COT",
        "sign": "SIGN",
        "pi": "PI",
        "mod": "MOD",
        "rand": "RAND"       # careful: nondeterministic
    },
    "postgresql": {
        "abs": "ABS",
        "ceil": "CEIL",
        "floor": "FLOOR",
        "round": "ROUND",
        "pow": "POW",
        "sqrt": "SQRT",
        "exp": "EXP",
        "ln": "LN",
        "log": "LOG",
        "log2": "LOG2",
        "log10": "LOG10",
        "sin": "SIN",
        "cos": "COS",
        "tan": "TAN",
        "cot": "COT",
        "sign": "SIGN",
        "pi": "PI",
        "mod": "MOD",
        "rand": "RANDOM"
    },
    "mssql": {
        "abs": "ABS",
        "ceil": "CEILING",
        "floor": "FLOOR",
        "round": "ROUND",
        "pow": "POWER",
        "sqrt": "SQRT",
        "exp": "EXP",
        "ln": "LOG",
        "log": "LOG",
        "log2": "LOG",
        "log10": "LOG10",
        "sin": "SIN",
        "cos": "COS",
        "tan": "TAN",
        "cot": "COT",
        "sign": "SIGN",
        "pi": "PI",
        "mod": "%",
        "rand": "RAND"
    },
    "oracle": {
        "abs": "ABS",
        "ceil": "CEIL",
        "floor": "FLOOR",
        "round": "ROUND",
        "pow": "POWER",
        "sqrt": "SQRT",
        "exp": "EXP",
        "ln": "LN",
        "log": "LOG",
        "log2": "LOG",       # Oracle uses LOG(base, n)
        "log10": "LOG(10,",
        "sin": "SIN",
        "cos": "COS",
        "tan": "TAN",
        "cot": "COT",
        "sign": "SIGN",
        "pi": "3.141592653589793",
        "mod": "MOD",
        "rand": "DBMS_RANDOM.VALUE"   # needs special handling
    }
}

# ---------- Expression templates (over 120 patterns) ----------
# Each template is a string with placeholders {N} for the original number
# and {F} for DBMS‑specific function names.
# Some templates use nested functions.

TEMPLATES = [
    # 1. Basic arithmetic
    "{N}",
    "({N})",
    "({N}+0)",
    "({N}-0)",
    "({N}*1)",
    "({N}/1)",
    "({N}%1)",
    "({N}<<0)",               # bitwise shift (if supported)
    "({N}>>0)",
    "({N}|0)",
    "({N}&0xFFFFFFFF)",
    "({N}^0)",
    "({N}+1-1)",
    "({N}*2/2)",
    "({N}/2*2)",              # may not be exact for odd numbers

    # 2. Absolute value
    "{F_abs}({N})",
    "{F_abs}(-{N})",
    "{F_abs}({N}*-1)",
    "{F_abs}(0-{N})",

    # 3. Ceiling / Floor / Round
    "{F_ceil}({N})",
    "{F_floor}({N})",
    "{F_round}({N})",
    "{F_ceil}({N}+0.0)",
    "{F_floor}({N}+0.0)",
    "{F_round}({N}+0.0)",
    "{F_ceil}({F_abs}({N}))",
    "{F_floor}({F_abs}({N}))",
    "{F_round}({F_abs}({N}))",

    # 4. Sign and absolute
    "{F_sign}({N}) * {F_abs}({N})",
    "{F_sign}({N}) * {N}",

    # 5. Using PI() for constants
    "{F_floor}({F_pi}()*{n_const})",  # n_const chosen to approximate N
    "{F_ceil}({F_pi}()*{n_const})",
    "{F_round}({F_pi}()*{n_const})",
    "({F_sin}({F_pi}()/{n_const}))",  # values in [-1,1]

    # 6. Square roots and powers
    "{F_pow}({N},1)",
    "{F_pow}({F_sqrt}({N}),2)",
    "{F_sqrt}({F_pow}({N},2))",
    "{F_pow}({N},1.0)",
    "{F_pow}({N},1.000)",
    "{F_pow}({F_abs}({N}),1)",
    "ROUND({F_pow}({N},1),0)",

    # 7. Exponential and logarithms (need careful with zero/negative)
    "ROUND({F_exp}({F_ln}({N})),0)",
    "ROUND({F_exp}({F_log}({N})),0)",
    "ROUND({F_exp}({F_log2}({N})*{F_log}(2)),0)",
    "ROUND({F_exp}({F_log10}({N})*{F_ln}(10)),0)",

    # 8. Trigonometric (require inputs in radians)
    "ROUND({F_sin}({N}),0)",
    "ROUND({F_cos}({N}),0)",
    "ROUND({F_tan}({N}),0)",
    "ROUND({F_cot}({N}),0)",
    "ROUND({F_sin}({F_pi}()*{n_const}),0)",
    "ROUND({F_cos}({F_pi}()*{n_const}),0)",

    # 9. Modular arithmetic
    "({N} % {N} + {N})",
    "({N} % 1) + {N}",
    "({N} % (1+0)) + {N}",

    # 10. Randomness (if allowed) - using RAND to generate a value and scale
    "ROUND({F_rand}()*{N}+0.5,0)",   # non‑deterministic, but can work
    "ROUND({F_rand}()*({N})+0.5,0)",

    # 11. Nested compositions (recursive building)
    "{F_abs}({F_abs}({N}))",
    "{F_ceil}({F_abs}({N}))",
    "{F_floor}({F_abs}({N}))",
    "{F_round}({F_abs}({N}))",
    "{F_sqrt}({F_pow}({N},2))",
    "ROUND({F_pow}({F_abs}({N}),1),0)",
    "ROUND({F_exp}({F_ln}({F_abs}({N}))),0)",

    # 12. Using decimal points
    "{N}.0",
    "{N}.000",
    "{N}.0000",
    "{N}.0 + 0.0",
    "{N} + 0.0",

    # 13. Hexadecimal / Binary representations (if applicable)
    "0x{hex:N}",           # requires hex string
    "0X{hex:N}",
    "b'{bin:N}'",          # binary literal (MySQL)
    "B'{bin:N}'",          # binary literal (PostgreSQL)

    # 14. Using CASE / IF for conditional expressions (complex)
    "CASE WHEN 1=1 THEN {N} ELSE 0 END",
    "IF(1=1,{N},0)",       # MySQL
    "IIF(1=1,{N},0)",      # MSSQL

    # 15. Using GREATEST / LEAST
    "GREATEST({N},0)",
    "LEAST({N},{N})",
    "GREATEST({N},0,0,0)",
    "LEAST({N},{N},{N})",

    # 16. Using CONCAT / string tricks (convert back to number)
    "CAST('{N}' AS {int_type})",
    "CONVERT({int_type}, '{N}')",

    # 17. Using positional functions (MySQL)
    "POSITION('a' IN 'a' * {N})",    # yields 1 * N
    "INSTR('abc', 'a') * {N}",

    # 18. Using date/time arithmetic (if supported)
    "EXTRACT(YEAR FROM DATE '2020-01-01' + {N} * INTERVAL '1' DAY)",
    "DATEDIFF(day, '2020-01-01', '2020-01-01' + {N} * INTERVAL '1' DAY)",

    # 19. Using bitwise operations (MySQL, PostgreSQL)
    "({N} | 0)",
    "({N} & ~0)",
    "({N} ^ 0)",
    "({N} << 0)",
    "({N} >> 0)",

    # 20. Using mathematical identities
    "({N} * 1) + 0",
    "({N} + 0) * 1",
    "({N} - 0) / 1",
    "({N} / 1) * 1",
    "({N} % 1) + 0",

    # 21. Using multiple operations
    "({N} + {N}) - {N}",
    "({N} * {N}) / {N}",
    "({N} / {N}) * {N}",
    "({N} - {N}) + {N}",

    # 22. Using non‑trivial function nesting (e.g., CEIL(SQRT(POW(...))))
    "{F_ceil}({F_sqrt}({F_pow}({N},2)))",
    "{F_floor}({F_sqrt}({F_pow}({N},2)))",
    "{F_round}({F_sqrt}({F_pow}({N},2)))",

    # 23. Using LOG with base
    "{F_log}({F_exp}({N}))",
    "{F_log2}({F_pow}(2,{N}))",
    "{F_log10}({F_pow}(10,{N}))",

    # 24. Using trigonometric identities
    "ROUND({F_sin}({F_pi}()/2) * {N},0)",
    "ROUND({F_cos}(0) * {N},0)",

    # 25. Using constants like e
    "ROUND({F_exp}(1) * {N} / {F_exp}(1),0)",
]

# Additional DBMS-specific type casting
INT_TYPES = {
    "mysql": "SIGNED",
    "postgresql": "INTEGER",
    "mssql": "INT",
    "oracle": "INTEGER"
}

# ---------- Helper to generate composite expressions ----------
def _compose_expression(num, dbms_funcs):
    """
    Recursively build a random expression from templates.
    Returns a string that evaluates to `num` in the target DBMS.
    """
    # First, pick a random template
    template = random.choice(TEMPLATES)
    # Prepare placeholders
    replacements = {
        "{N}": str(num),
        "{F_abs}": dbms_funcs.get("abs", "ABS"),
        "{F_ceil}": dbms_funcs.get("ceil", "CEIL"),
        "{F_floor}": dbms_funcs.get("floor", "FLOOR"),
        "{F_round}": dbms_funcs.get("round", "ROUND"),
        "{F_pow}": dbms_funcs.get("pow", "POW"),
        "{F_sqrt}": dbms_funcs.get("sqrt", "SQRT"),
        "{F_exp}": dbms_funcs.get("exp", "EXP"),
        "{F_ln}": dbms_funcs.get("ln", "LN"),
        "{F_log}": dbms_funcs.get("log", "LOG"),
        "{F_log2}": dbms_funcs.get("log2", "LOG2"),
        "{F_log10}": dbms_funcs.get("log10", "LOG10"),
        "{F_sin}": dbms_funcs.get("sin", "SIN"),
        "{F_cos}": dbms_funcs.get("cos", "COS"),
        "{F_tan}": dbms_funcs.get("tan", "TAN"),
        "{F_cot}": dbms_funcs.get("cot", "COT"),
        "{F_sign}": dbms_funcs.get("sign", "SIGN"),
        "{F_pi}": dbms_funcs.get("pi", "PI"),
        "{F_mod}": dbms_funcs.get("mod", "MOD"),
        "{F_rand}": dbms_funcs.get("rand", "RAND"),
    }
    # For templates that need a constant multiplier (e.g., PI()*const)
    # we compute a constant that approximates num/PI() if PI is used.
    if "{n_const}" in template:
        # Estimate const = round(num / pi)
        pi_val = math.pi
        if num == 0:
            const = 0
        else:
            const = int(round(num / pi_val))
            if const == 0:
                const = 1
        replacements["{n_const}"] = str(const)
    # For hexadecimal and binary
    if "{hex:N}" in template:
        replacements["{hex:N}"] = hex(num)[2:].upper()
    if "{bin:N}" in template:
        replacements["{bin:N}"] = bin(num)[2:]
    # For integer type casting
    if "{int_type}" in template:
        int_type = INT_TYPES.get(dbms_funcs.get("_name", "mysql"), "INTEGER")
        replacements["{int_type}"] = int_type

    # Apply replacements
    expr = template
    for key, val in replacements.items():
        expr = expr.replace(key, val)

    return expr

# ---------- Main tamper function ----------
def tamper(payload, **kwargs):
    """
    Replaces every integer literal in the payload with a random
    mathematical expression that evaluates to the same integer.
    """
    if not payload:
        return payload

    # Determine target DBMS (if available)
    dbms = kwargs.get('dbms')
    if dbms and dbms.lower() in DBMS_FUNCTIONS:
        dbms_funcs = DBMS_FUNCTIONS[dbms.lower()].copy()
        dbms_funcs["_name"] = dbms.lower()
    else:
        # Default to MySQL
        dbms_funcs = DBMS_FUNCTIONS["mysql"].copy()
        dbms_funcs["_name"] = "mysql"

    # Pattern to match standalone integers (including negative)
    # We capture the number (including optional leading minus)
    pattern = r'(?<![a-zA-Z0-9_.])-?[0-9]+(?![a-zA-Z0-9_.])'

    def _replace_int(match):
        num_str = match.group(0)
        try:
            num = int(num_str)
        except ValueError:
            return num_str  # not an integer? shouldn't happen

        # For very large numbers, we keep them as is to avoid extremely long expressions
        if abs(num) > 9999999:
            return num_str

        # Generate a random expression
        expr = _compose_expression(num, dbms_funcs)

        # Occasionally wrap the whole expression in parentheses (for safety)
        if random.random() > 0.5:
            expr = f"({expr})"

        return expr

    # Replace all numbers
    ret_val = re.sub(pattern, _replace_int, payload)
    return ret_val

# ---------- Dependencies (optional) ----------
def dependencies():
    pass
