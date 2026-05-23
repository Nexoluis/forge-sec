"""
FORGE-SEC Parser
Analizador sintáctico recursivo descendente.
Convierte tokens en AST.
"""
from typing import List, Optional, Dict, Any
from .lexer import Token, TT
from .ast_nodes import *


class ParseError(Exception):
    pass


class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    # ── Utilidades ────────────────────────────────────────────────────────────

    def peek(self, offset: int = 0) -> Token:
        p = self.pos + offset
        return self.tokens[p] if p < len(self.tokens) else self.tokens[-1]

    def advance(self) -> Token:
        t = self.tokens[self.pos]
        if t.type != TT.EOF:
            self.pos += 1
        return t

    def check(self, tt: TT, value: str = None) -> bool:
        t = self.peek()
        if t.type != tt:
            return False
        return value is None or t.value == value

    def match(self, tt: TT, value: str = None) -> bool:
        if self.check(tt, value):
            self.advance()
            return True
        return False

    def expect(self, tt: TT, value: str = None) -> Token:
        t = self.peek()
        if t.type != tt or (value is not None and t.value != value):
            expected = f"'{value}'" if value else tt.name
            raise ParseError(f"Línea {t.line}: esperaba {expected}, encontró '{t.value}'")
        return self.advance()

    def expect_ident(self, name: str = None) -> Token:
        return self.expect(TT.IDENT, name)

    def is_ident(self, *names: str) -> bool:
        return self.peek().type == TT.IDENT and (not names or self.peek().value in names)

    # ── Tipos ─────────────────────────────────────────────────────────────────

    def parse_sec_type(self) -> SecType:
        """Tainted<String>, Trusted<Int>, etc."""
        wrapper = self.expect(TT.IDENT).value
        if wrapper not in SEC_WRAPPERS:
            raise ParseError(f"Tipo de seguridad desconocido: {wrapper}")
        self.expect(TT.LANGLE)
        inner = self.expect(TT.IDENT).value
        self.expect(TT.RANGLE)
        return SecType(wrapper, inner)

    def parse_return_type(self) -> Any:
        """Parsea tipos de retorno: SecType, Result<X>, List<X>, IDENT"""
        name = self.expect(TT.IDENT).value
        if self.check(TT.LANGLE):
            self.advance()
            if self.check(TT.LANGLE, None) or self.peek().value in SEC_WRAPPERS:
                inner = self.parse_return_type()
            else:
                inner = self.expect(TT.IDENT).value
                # List<Pedido> etc
                if self.check(TT.LANGLE):
                    self.advance()
                    inner2 = self.expect(TT.IDENT).value
                    self.expect(TT.RANGLE)
                    inner = f"{inner}<{inner2}>"
            self.expect(TT.RANGLE)
            if name in SEC_WRAPPERS:
                return SecType(name, str(inner))
            return f"{name}<{inner}>"
        if name in SEC_WRAPPERS:
            raise ParseError(f"Tipo de seguridad {name} requiere parámetro de tipo")
        return name

    # ── Políticas ─────────────────────────────────────────────────────────────

    def parse_policy_list(self) -> List[PolicyDecl]:
        """[RateLimit(5/min), BruteForceProtection]"""
        self.expect(TT.LBRACKET)
        policies = []
        while not self.check(TT.RBRACKET):
            name = self.expect(TT.IDENT).value
            args = []
            if self.match(TT.LPAREN):
                # Parsear argumentos sencillos hasta ')'
                while not self.check(TT.RPAREN):
                    if self.check(TT.INT_LIT):
                        args.append(int(self.advance().value))
                    elif self.check(TT.FLOAT_LIT):
                        args.append(float(self.advance().value))
                    elif self.check(TT.IDENT):
                        args.append(self.advance().value)
                    elif self.check(TT.SLASH):
                        self.advance()
                    elif self.check(TT.COMMA):
                        self.advance()
                    else:
                        self.advance()
                self.expect(TT.RPAREN)
            policies.append(PolicyDecl(name, args))
            self.match(TT.COMMA)
        self.expect(TT.RBRACKET)
        return policies

    def parse_effects(self) -> List[Effect]:
        """[db.read, session.write]"""
        self.expect(TT.LBRACKET)
        effects = []
        while not self.check(TT.RBRACKET):
            domain = self.expect(TT.IDENT).value
            self.expect(TT.DOT)
            action = self.expect(TT.IDENT).value
            effects.append(Effect(domain, action))
            self.match(TT.COMMA)
        self.expect(TT.RBRACKET)
        return effects

    def parse_security_list(self) -> List[str]:
        """[sql_injection_proof, timing_attack_safe]"""
        self.expect(TT.LBRACKET)
        items = []
        while not self.check(TT.RBRACKET):
            items.append(self.expect(TT.IDENT).value)
            self.match(TT.COMMA)
        self.expect(TT.RBRACKET)
        return items

    def parse_input_fields(self) -> List[InputField]:
        """{email: Tainted<Email>, password: Tainted<Password>}"""
        self.expect(TT.LBRACE)
        fields = []
        while not self.check(TT.RBRACE):
            name = self.expect(TT.IDENT).value
            self.expect(TT.COLON)
            typ = self.parse_sec_type()
            fields.append(InputField(name, typ))
            self.match(TT.COMMA)
        self.expect(TT.RBRACE)
        return fields

    # ── Expresiones ───────────────────────────────────────────────────────────

    def parse_expr(self) -> Expr:
        """Punto de entrada para expresiones. Maneja ?? al final."""
        left = self.parse_or()
        if self.match(TT.DOUBLE_QUESTION):
            # ?? puede ir seguido de 'return expr' o de otra expresión
            if self.is_ident('return'):
                self.advance()
                right = ReturnExpr(self.parse_or())
            else:
                right = self.parse_or()
            return NullCoalesce(left, right)
        return left

    def parse_or(self) -> Expr:
        left = self.parse_and()
        while self.is_ident('or'):
            self.advance()
            right = self.parse_and()
            left = BinOp('or', left, right)
        return left

    def parse_and(self) -> Expr:
        left = self.parse_comparison()
        while self.is_ident('and'):
            self.advance()
            right = self.parse_comparison()
            left = BinOp('and', left, right)
        return left

    def parse_comparison(self) -> Expr:
        left = self.parse_add()
        ops = {TT.EQ_EQ: '==', TT.BANG_EQ: '!=',
               TT.LANGLE: '<',  TT.RANGLE: '>',
               TT.LT_EQ: '<=', TT.GT_EQ: '>='}
        if self.peek().type in ops:
            op = ops[self.advance().type]
            right = self.parse_add()
            return BinOp(op, left, right)
        return left

    def parse_add(self) -> Expr:
        left = self.parse_mul()
        while self.check(TT.PLUS) or self.check(TT.MINUS):
            op = self.advance().value
            right = self.parse_mul()
            left = BinOp(op, left, right)
        return left

    def parse_mul(self) -> Expr:
        left = self.parse_unary()
        while self.check(TT.STAR) or self.check(TT.SLASH) or self.check(TT.PERCENT):
            op = self.advance().value
            right = self.parse_unary()
            left = BinOp(op, left, right)
        return left

    def parse_unary(self) -> Expr:
        if self.check(TT.BANG):
            self.advance()
            return UnaryOp('!', self.parse_postfix())
        if self.check(TT.MINUS):
            self.advance()
            return UnaryOp('-', self.parse_postfix())
        return self.parse_postfix()

    def parse_postfix(self) -> Expr:
        expr = self.parse_primary()
        while True:
            if self.check(TT.DOT):
                self.advance()
                field_name = self.expect(TT.IDENT).value
                # Podría ser una llamada: expr.method(args)
                if self.check(TT.LPAREN):
                    args, kwargs = self.parse_call_args()
                    expr = CallExpr(FieldAccess(expr, field_name), args, kwargs)
                else:
                    expr = FieldAccess(expr, field_name)
            elif self.check(TT.LPAREN):
                args, kwargs = self.parse_call_args()
                expr = CallExpr(expr, args, kwargs)
            else:
                break
        return expr

    def parse_call_args(self):
        """Parsea (arg1, arg2, key: val, ...)"""
        self.expect(TT.LPAREN)
        args = []
        kwargs = {}
        while not self.check(TT.RPAREN):
            # Detectar keyword argument: ident ':'
            if (self.check(TT.IDENT) and
                    self.peek(1).type == TT.COLON and
                    self.peek(1).value == ':'):
                key = self.advance().value
                self.advance()  # ':'
                val = self.parse_expr()
                kwargs[key] = val
            else:
                args.append(self.parse_expr())
            self.match(TT.COMMA)
        self.expect(TT.RPAREN)
        return args, kwargs

    def parse_dict_lit(self) -> DictLit:
        """{ key: expr, key2: expr2 }"""
        self.expect(TT.LBRACE)
        pairs = {}
        while not self.check(TT.RBRACE):
            key = self.expect(TT.IDENT).value
            self.expect(TT.COLON)
            val = self.parse_expr()
            pairs[key] = val
            self.match(TT.COMMA)
        self.expect(TT.RBRACE)
        return DictLit(pairs)

    def parse_primary(self) -> Expr:
        t = self.peek()

        # Literales
        if t.type == TT.STRING_LIT:
            self.advance()
            return StringLit(t.value)
        if t.type == TT.INT_LIT:
            self.advance()
            return IntLit(int(t.value))
        if t.type == TT.FLOAT_LIT:
            self.advance()
            return FloatLit(float(t.value))
        if t.type == TT.IDENT and t.value in ('true', 'false'):
            self.advance()
            return BoolLit(t.value == 'true')

        # Dict literal { ... }
        if t.type == TT.LBRACE:
            return self.parse_dict_lit()

        # Expresión entre paréntesis
        if t.type == TT.LPAREN:
            self.advance()
            expr = self.parse_expr()
            self.expect(TT.RPAREN)
            return expr

        # Ok(...) / Error(...)
        if t.type == TT.IDENT and t.value == 'Ok':
            self.advance()
            self.expect(TT.LPAREN)
            val = self.parse_expr()
            self.expect(TT.RPAREN)
            return OkExpr(val)
        if t.type == TT.IDENT and t.value == 'Error':
            self.advance()
            self.expect(TT.LPAREN)
            msg = self.expect(TT.STRING_LIT).value
            self.expect(TT.RPAREN)
            return ErrorExpr(msg)

        # sanitize(...)
        if t.type == TT.IDENT and t.value == 'sanitize':
            self.advance()
            self.expect(TT.LPAREN)
            arg = self.parse_expr()
            self.expect(TT.RPAREN)
            return SanitizeCall(arg)

        # db.findOne(...) / db.query(...)
        if t.type == TT.IDENT and t.value == 'db':
            self.advance()
            self.expect(TT.DOT)
            method = self.expect(TT.IDENT).value
            self.expect(TT.LPAREN)
            model = self.expect(TT.IDENT).value
            self.expect(TT.COMMA)
            self.expect_ident('where')
            self.expect(TT.COLON)
            where = self.parse_dict_lit().pairs
            limit = None
            if self.check(TT.COMMA):
                self.advance()
                if self.is_ident('limit'):
                    self.advance()
                    self.expect(TT.COLON)
                    limit = int(self.expect(TT.INT_LIT).value)
            self.expect(TT.RPAREN)
            if method == 'findOne':
                return DbFindOne(model, where)
            return DbQuery(model, where, limit)

        # crypto.verifyHash(...) / crypto.hash(...)
        if t.type == TT.IDENT and t.value == 'crypto':
            self.advance()
            self.expect(TT.DOT)
            method = self.expect(TT.IDENT).value
            self.expect(TT.LPAREN)
            arg1 = self.parse_expr()
            if method == 'verifyHash':
                self.expect(TT.COMMA)
                arg2 = self.parse_expr()
                self.expect(TT.RPAREN)
                return CryptoVerifyHash(arg1, arg2)
            self.expect(TT.RPAREN)
            return CryptoHash(arg1)

        # session.set(...) / session.get(...)
        if t.type == TT.IDENT and t.value == 'session':
            self.advance()
            self.expect(TT.DOT)
            method = self.expect(TT.IDENT).value
            self.expect(TT.LPAREN)
            if method == 'set':
                key = self.expect(TT.STRING_LIT).value
                self.expect(TT.COMMA)
                val = self.parse_expr()
                self.expect(TT.RPAREN)
                return SessionSet(key, val)
            key = self.expect(TT.STRING_LIT).value
            self.expect(TT.RPAREN)
            return SessionGet(key)

        # log.write(...)
        if t.type == TT.IDENT and t.value == 'log':
            self.advance()
            self.expect(TT.DOT)
            self.expect_ident('write')
            self.expect(TT.LPAREN)
            msg = self.parse_expr()
            self.expect(TT.RPAREN)
            return LogWrite(msg)

        # Identificador genérico
        if t.type == TT.IDENT:
            self.advance()
            return IdentExpr(t.value)

        raise ParseError(f"Línea {t.line}: expresión inesperada: '{t.value}'")

    # ── Statements ────────────────────────────────────────────────────────────

    def parse_body(self) -> List[Stmt]:
        self.expect(TT.LBRACE)
        stmts = []
        while not self.check(TT.RBRACE):
            stmts.append(self.parse_stmt())
        self.expect(TT.RBRACE)
        return stmts

    def parse_stmt(self) -> Stmt:
        t = self.peek()

        if t.type == TT.IDENT and t.value == 'let':
            return self.parse_let()
        if t.type == TT.IDENT and t.value == 'return':
            return self.parse_return()
        if t.type == TT.IDENT and t.value == 'if':
            return self.parse_if()

        expr = self.parse_expr()
        self.match(TT.SEMICOLON)
        return ExprStmt(expr)

    def parse_let(self) -> LetStmt:
        self.expect_ident('let')
        name = self.expect(TT.IDENT).value
        self.expect(TT.EQUALS)
        value = self.parse_expr()
        self.match(TT.SEMICOLON)
        return LetStmt(name, value)

    def parse_return(self) -> ReturnStmt:
        self.expect_ident('return')
        value = self.parse_expr()
        self.match(TT.SEMICOLON)
        return ReturnStmt(value)

    def parse_if(self) -> IfStmt:
        self.expect_ident('if')
        condition = self.parse_expr()
        then_body = self.parse_body()
        else_body = None
        if self.is_ident('else'):
            self.advance()
            if self.is_ident('if'):
                else_body = [self.parse_if()]
            else:
                else_body = self.parse_body()
        return IfStmt(condition, then_body, else_body)

    # ── Top-level ─────────────────────────────────────────────────────────────

    def parse_endpoint(self) -> Endpoint:
        self.expect_ident('endpoint')
        method = self.expect(TT.IDENT).value
        path = self.expect(TT.URL_PATH).value

        # Anotaciones opcionales (antes del body)
        policies = []
        input_fields = []
        effects = []
        security = []

        while not self.check(TT.LBRACE):
            if not self.check(TT.IDENT):
                break
            key = self.peek().value
            if key == 'policy':
                self.advance(); self.expect(TT.COLON)
                policies = self.parse_policy_list()
            elif key == 'input':
                self.advance(); self.expect(TT.COLON)
                input_fields = self.parse_input_fields()
            elif key == 'effects':
                self.advance(); self.expect(TT.COLON)
                effects = self.parse_effects()
            elif key == 'security':
                self.advance(); self.expect(TT.COLON)
                security = self.parse_security_list()
            else:
                break

        body = self.parse_body()
        return Endpoint(method, path, policies, input_fields, effects, security, body)

    def parse_web_app(self) -> WebApp:
        self.expect_ident('web')
        self.expect_ident('app')
        name = self.expect(TT.IDENT).value
        self.expect(TT.LBRACE)
        endpoints = []
        while not self.check(TT.RBRACE):
            endpoints.append(self.parse_endpoint())
        self.expect(TT.RBRACE)
        return WebApp(name, endpoints)

    def parse_fn(self) -> FnDecl:
        self.expect_ident('fn')
        name = self.expect(TT.IDENT).value
        self.expect(TT.LPAREN)
        params = []
        while not self.check(TT.RPAREN):
            pname = self.expect(TT.IDENT).value
            self.expect(TT.COLON)
            ptype = self.parse_sec_type()
            params.append(Param(pname, ptype))
            self.match(TT.COMMA)
        self.expect(TT.RPAREN)
        self.expect(TT.ARROW)
        return_type = self.parse_return_type()

        effects = []
        is_pure = False
        while not self.check(TT.LBRACE):
            if not self.check(TT.IDENT):
                break
            key = self.peek().value
            if key == 'effects':
                self.advance(); self.expect(TT.COLON)
                effects = self.parse_effects()
            elif key == 'pure':
                self.advance(); self.expect(TT.COLON)
                is_pure = self.expect(TT.IDENT).value == 'true'
            elif key == 'security':
                self.advance(); self.expect(TT.COLON)
                self.parse_security_list()  # ignorar por ahora en funciones
            else:
                break

        body = self.parse_body()
        return FnDecl(name, params, return_type, effects, is_pure, body)

    def parse_program(self) -> Program:
        decls = []
        while not self.check(TT.EOF):
            t = self.peek()
            if t.type == TT.IDENT and t.value == 'web':
                decls.append(self.parse_web_app())
            elif t.type == TT.IDENT and t.value == 'fn':
                decls.append(self.parse_fn())
            else:
                raise ParseError(f"Línea {t.line}: declaración inesperada: '{t.value}'")
        return Program(decls)
