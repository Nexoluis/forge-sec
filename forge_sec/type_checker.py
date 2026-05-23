"""
FORGE-SEC Type Checker
Verifica las reglas de seguridad del sistema de tipos.
Errores de compilación si Tainted llega a query sin sanitizar,
Secret aparece en logs/HTTP, o efectos no declarados se usan.
"""
from typing import Dict, List, Optional, Set
from .ast_nodes import *


class TypeError(Exception):
    pass


class TypeEnv:
    """Entorno de tipos para variables locales."""
    def __init__(self, parent: Optional['TypeEnv'] = None):
        self.vars: Dict[str, SecType] = {}
        self.parent = parent

    def set(self, name: str, typ: SecType):
        self.vars[name] = typ

    def get(self, name: str) -> Optional[SecType]:
        if name in self.vars:
            return self.vars[name]
        if self.parent:
            return self.parent.get(name)
        return None


class TypeChecker:
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def error(self, msg: str):
        self.errors.append(f"❌ ERROR: {msg}")

    def warn(self, msg: str):
        self.warnings.append(f"⚠️  AVISO: {msg}")

    # ── Verificación de expresiones ───────────────────────────────────────────

    def check_expr(self, expr: Expr, env: TypeEnv,
                   declared_effects: Set[str]) -> Optional[SecType]:
        """Devuelve el SecType del resultado de la expresión, o None si no aplica."""

        if isinstance(expr, StringLit):
            return SecType('Trusted', 'String')

        if isinstance(expr, IntLit):
            return SecType('Trusted', 'Int')

        if isinstance(expr, FloatLit):
            return SecType('Trusted', 'Float')

        if isinstance(expr, BoolLit):
            return SecType('Trusted', 'Bool')

        if isinstance(expr, IdentExpr):
            t = env.get(expr.name)
            if t is None:
                # Podría ser un nombre de variable válido no tipado aún
                return SecType('Trusted', 'Unknown')
            return t

        if isinstance(expr, FieldAccess):
            # Caso especial: input.field — buscar tipo en env como "input.field"
            if isinstance(expr.obj, IdentExpr) and expr.obj.name == 'input':
                t = env.get(f"input.{expr.field}")
                if t:
                    return t
                # Si no está registrado individualmente, Tainted por defecto (origen externo)
                return SecType('Tainted', expr.field)
            obj_type = self.check_expr(expr.obj, env, declared_effects)
            if obj_type and obj_type.wrapper == 'Secret':
                return SecType('Secret', expr.field)
            if obj_type:
                return SecType(obj_type.wrapper, expr.field)
            return None

        if isinstance(expr, SanitizeCall):
            inner_type = self.check_expr(expr.arg, env, declared_effects)
            if inner_type and inner_type.wrapper == 'Secret':
                self.error("No se puede sanitizar un Secret<T> — nunca debe salir del sistema")
            # sanitize() eleva Tainted → Sanitized (y compatible con SqlSafe/HtmlSafe)
            inner_base = inner_type.inner if inner_type else 'String'
            return SecType('Sanitized', inner_base)

        if isinstance(expr, DbFindOne):
            # Verificar efecto declarado
            if 'db.read' not in declared_effects:
                self.error(f"db.findOne usado pero 'db.read' no declarado en effects")
            # Verificar que los campos where no sean Tainted directamente
            for field_name, field_expr in expr.where.items():
                ft = self.check_expr(field_expr, env, declared_effects)
                if ft and ft.wrapper == 'Tainted':
                    self.error(
                        f"Campo '{field_name}' en db.findOne es Tainted<{ft.inner}> — "
                        f"usa sanitize() antes de pasarlo a la query"
                    )
                if ft and ft.wrapper == 'Secret':
                    self.error(
                        f"Campo '{field_name}' es Secret<{ft.inner}> — "
                        f"no puede usarse en queries de base de datos"
                    )
            return SecType('Trusted', expr.model)

        if isinstance(expr, DbQuery):
            if 'db.read' not in declared_effects:
                self.error(f"db.query usado pero 'db.read' no declarado en effects")
            for field_name, field_expr in expr.where.items():
                ft = self.check_expr(field_expr, env, declared_effects)
                if ft and ft.wrapper == 'Tainted':
                    self.error(
                        f"Campo '{field_name}' en db.query es Tainted — usa sanitize()"
                    )
            return SecType('Trusted', f'List<{expr.model}>')

        if isinstance(expr, CryptoVerifyHash):
            if 'crypto.hash' not in declared_effects and 'crypto.decrypt' not in declared_effects:
                self.warn("crypto.verifyHash usado sin declarar efecto crypto.* en effects")
            # El valor puede ser Tainted (comparar contraseña de usuario está permitido)
            return SecType('Trusted', 'Bool')

        if isinstance(expr, CryptoHash):
            return SecType('Trusted', 'String')

        if isinstance(expr, SessionSet):
            if 'session.write' not in declared_effects:
                self.error(f"session.set usado pero 'session.write' no declarado en effects")
            # Nunca escribir Secret en sesión
            val_type = self.check_expr(expr.value, env, declared_effects)
            if val_type and val_type.wrapper == 'Secret':
                self.error(
                    f"No se puede escribir Secret<{val_type.inner}> en sesión — "
                    f"las sesiones son accesibles desde cliente"
                )
            return SecType('Trusted', 'Void')

        if isinstance(expr, SessionGet):
            if 'session.read' not in declared_effects:
                self.error(f"session.get usado pero 'session.read' no declarado en effects")
            return SecType('Trusted', 'String')

        if isinstance(expr, LogWrite):
            if 'log.write' not in declared_effects:
                self.error(f"log.write usado pero 'log.write' no declarado en effects")
            # Nunca logar Secret
            msg_type = self.check_expr(expr.message, env, declared_effects)
            if msg_type and msg_type.wrapper == 'Secret':
                self.error("Secret<T> no puede aparecer en log.write")
            return SecType('Trusted', 'Void')

        if isinstance(expr, OkExpr):
            inner = self.check_expr(expr.value, env, declared_effects)
            # El valor en Ok() no puede ser Secret
            if inner and inner.wrapper == 'Secret':
                self.error("Secret<T> no puede devolverse en Ok() — sería enviado al cliente")
            return SecType('Trusted', 'Result')

        if isinstance(expr, ErrorExpr):
            return SecType('Trusted', 'Result')

        if isinstance(expr, DictLit):
            for k, v in expr.pairs.items():
                vt = self.check_expr(v, env, declared_effects)
                if vt and vt.wrapper == 'Secret':
                    self.error(f"Campo '{k}' en dict es Secret<T> — no puede salir al exterior")
            return SecType('Trusted', 'Dict')

        if isinstance(expr, NullCoalesce):
            self.check_expr(expr.left, env, declared_effects)
            if isinstance(expr.right, ReturnExpr):
                self.check_expr(expr.right.value, env, declared_effects)
            else:
                self.check_expr(expr.right, env, declared_effects)
            return SecType('Trusted', 'Unknown')

        if isinstance(expr, ReturnExpr):
            return self.check_expr(expr.value, env, declared_effects)

        if isinstance(expr, BinOp):
            lt = self.check_expr(expr.left, env, declared_effects)
            rt = self.check_expr(expr.right, env, declared_effects)
            # Si alguno es Tainted, el resultado también lo es
            if lt and lt.wrapper == 'Tainted':
                return lt
            if rt and rt.wrapper == 'Tainted':
                return rt
            return SecType('Trusted', 'Unknown')

        if isinstance(expr, UnaryOp):
            return self.check_expr(expr.operand, env, declared_effects)

        if isinstance(expr, CallExpr):
            # Llamada genérica
            for arg in expr.args:
                self.check_expr(arg, env, declared_effects)
            for v in expr.kwargs.values():
                self.check_expr(v, env, declared_effects)
            return SecType('Trusted', 'Unknown')

        return None

    # ── Verificación de statements ────────────────────────────────────────────

    def check_stmt(self, stmt: Stmt, env: TypeEnv, declared_effects: Set[str]):
        if isinstance(stmt, LetStmt):
            typ = self.check_expr(stmt.value, env, declared_effects)
            if typ:
                env.set(stmt.name, typ)

        elif isinstance(stmt, ReturnStmt):
            rt = self.check_expr(stmt.value, env, declared_effects)
            if rt and rt.wrapper == 'Secret':
                self.error(f"Se intenta devolver Secret<{rt.inner}> — "
                           f"los valores secretos nunca salen al exterior")

        elif isinstance(stmt, IfStmt):
            self.check_expr(stmt.condition, env, declared_effects)
            inner_env = TypeEnv(parent=env)
            for s in stmt.then_body:
                self.check_stmt(s, inner_env, declared_effects)
            if stmt.else_body:
                else_env = TypeEnv(parent=env)
                for s in stmt.else_body:
                    self.check_stmt(s, else_env, declared_effects)

        elif isinstance(stmt, ExprStmt):
            self.check_expr(stmt.expr, env, declared_effects)

    # ── Verificación de endpoint / función ────────────────────────────────────

    def check_endpoint(self, endpoint: Endpoint, app_name: str):
        effects_set = {str(e) for e in endpoint.effects}
        env = TypeEnv()

        # Variables de input disponibles en el cuerpo
        for field in endpoint.input_fields:
            env.set(f"input.{field.name}", field.type_)
            env.set(field.name, field.type_)

        for stmt in endpoint.body:
            self.check_stmt(stmt, env, effects_set)

    def check_fn(self, fn: FnDecl):
        effects_set = {str(e) for e in fn.effects}

        if fn.is_pure and effects_set:
            self.error(f"Función '{fn.name}' declarada pure:true pero tiene effects: {effects_set}")

        env = TypeEnv()
        for param in fn.params:
            env.set(param.name, param.type_)

        for stmt in fn.body:
            self.check_stmt(stmt, env, effects_set)

    def check_program(self, program: Program):
        for decl in program.declarations:
            if isinstance(decl, WebApp):
                for endpoint in decl.endpoints:
                    self.check_endpoint(endpoint, decl.name)
            elif isinstance(decl, FnDecl):
                self.check_fn(decl)
        return len(self.errors) == 0
