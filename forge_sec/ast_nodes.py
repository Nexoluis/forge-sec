"""
FORGE-SEC AST Nodes
Sistema de tipos de seguridad y nodos del árbol sintáctico.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# ── Tipos de seguridad ────────────────────────────────────────────────────────

SEC_WRAPPERS = {'Tainted', 'Sanitized', 'Trusted', 'Secret', 'SqlSafe', 'HtmlSafe'}
BASE_TYPES   = {'String', 'Int', 'Float', 'Bool', 'Email', 'Password', 'Path',
                'Result', 'List', 'User', 'Pedido', 'Void'}

# Qué tipos pueden asignarse a qué sin sanitizador
FLOW_RULES: Dict[str, set] = {
    'Trusted':   {'Trusted', 'SqlSafe', 'HtmlSafe', 'Sanitized'},
    'Sanitized': {'Sanitized', 'SqlSafe', 'HtmlSafe'},
    'SqlSafe':   {'SqlSafe'},
    'HtmlSafe':  {'HtmlSafe'},
    'Tainted':   set(),   # nunca fluye sin sanitizar
    'Secret':    {'Secret'},
}

@dataclass
class SecType:
    wrapper: str   # Tainted | Trusted | Secret | ...
    inner: str     # String | Int | Email | ...

    def __str__(self): return f"{self.wrapper}<{self.inner}>"

    def can_flow_to(self, target: 'SecType') -> bool:
        return target.wrapper in FLOW_RULES.get(self.wrapper, set())

# ── Efectos ───────────────────────────────────────────────────────────────────

@dataclass
class Effect:
    domain: str   # db | fs | net | session | crypto | log
    action: str   # read | write | delete | outbound | ...

    def __str__(self): return f"{self.domain}.{self.action}"

# ── Expresiones ───────────────────────────────────────────────────────────────

@dataclass
class Expr: pass

@dataclass
class IdentExpr(Expr):
    name: str

@dataclass
class StringLit(Expr):
    value: str

@dataclass
class IntLit(Expr):
    value: int

@dataclass
class FloatLit(Expr):
    value: float

@dataclass
class BoolLit(Expr):
    value: bool

@dataclass
class FieldAccess(Expr):
    obj: Expr
    field: str

@dataclass
class IndexAccess(Expr):
    obj: Expr
    index: str

@dataclass
class CallExpr(Expr):
    func: Expr
    args: List[Expr] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SanitizeCall(Expr):
    """sanitize(expr) — convierte Tainted → Sanitized/SqlSafe"""
    arg: Expr

@dataclass
class BinOp(Expr):
    op: str    # + - * / % == != < > <= >=
    left: Expr
    right: Expr

@dataclass
class UnaryOp(Expr):
    op: str    # ! -
    operand: Expr

@dataclass
class NullCoalesce(Expr):
    """expr ?? fallback"""
    left: Expr
    right: Expr   # puede ser ReturnExpr

@dataclass
class ReturnExpr(Expr):
    """return dentro de expresión (para ?? return Error(...))"""
    value: Expr

@dataclass
class OkExpr(Expr):
    value: Expr

@dataclass
class ErrorExpr(Expr):
    message: str

@dataclass
class DictLit(Expr):
    pairs: Dict[str, Expr] = field(default_factory=dict)

# Expresiones del sistema de runtime
@dataclass
class DbFindOne(Expr):
    model: str
    where: Dict[str, Expr] = field(default_factory=dict)

@dataclass
class DbQuery(Expr):
    model: str
    where: Dict[str, Expr] = field(default_factory=dict)
    limit: Optional[int] = None

@dataclass
class CryptoVerifyHash(Expr):
    value: Expr
    hash_val: Expr

@dataclass
class CryptoHash(Expr):
    value: Expr

@dataclass
class SessionSet(Expr):
    key: str
    value: Expr

@dataclass
class SessionGet(Expr):
    key: str

@dataclass
class LogWrite(Expr):
    message: Expr

# ── Statements ────────────────────────────────────────────────────────────────

@dataclass
class Stmt: pass

@dataclass
class LetStmt(Stmt):
    name: str
    value: Expr

@dataclass
class ReturnStmt(Stmt):
    value: Expr

@dataclass
class IfStmt(Stmt):
    condition: Expr
    then_body: List[Stmt]
    else_body: Optional[List[Stmt]] = None

@dataclass
class ExprStmt(Stmt):
    expr: Expr

# ── Top-level ─────────────────────────────────────────────────────────────────

@dataclass
class InputField:
    name: str
    type_: SecType

@dataclass
class Param:
    name: str
    type_: SecType

@dataclass
class PolicyDecl:
    name: str
    args: List[Any] = field(default_factory=list)

@dataclass
class Endpoint:
    method: str                      # GET POST PUT DELETE PATCH
    path: str                        # /login
    policies: List[PolicyDecl]       # [RateLimit(5/min), ...]
    input_fields: List[InputField]   # email: Tainted<Email>, ...
    effects: List[Effect]            # [db.read, session.write]
    security_constraints: List[str]  # [sql_injection_proof, ...]
    body: List[Stmt]

@dataclass
class WebApp:
    name: str
    endpoints: List[Endpoint]

@dataclass
class FnDecl:
    name: str
    params: List[Param]
    return_type: Any   # SecType o string
    effects: List[Effect]
    is_pure: bool
    body: List[Stmt]

@dataclass
class PolicyDef:
    name: str
    rules: Dict[str, Any]

@dataclass
class Program:
    declarations: List[Any]   # WebApp | FnDecl | PolicyDef
