"""
FORGE-SEC Lexer
Tokenizador del lenguaje.
"""
from dataclasses import dataclass
from typing import List
from enum import Enum, auto


class TT(Enum):
    # Literales
    IDENT       = auto()
    STRING_LIT  = auto()
    INT_LIT     = auto()
    FLOAT_LIT   = auto()
    URL_PATH    = auto()   # /login /dashboard etc

    # Operadores compuestos
    ARROW            = auto()   # ->
    DOUBLE_QUESTION  = auto()   # ??
    EQ_EQ            = auto()   # ==
    BANG_EQ          = auto()   # !=
    LT_EQ            = auto()   # <=
    GT_EQ            = auto()   # >=

    # Símbolos simples
    LBRACE    = auto()   # {
    RBRACE    = auto()   # }
    LPAREN    = auto()   # (
    RPAREN    = auto()   # )
    LBRACKET  = auto()   # [
    RBRACKET  = auto()   # ]
    LANGLE    = auto()   # <
    RANGLE    = auto()   # >
    COLON     = auto()   # :
    COMMA     = auto()   # ,
    SEMICOLON = auto()   # ;
    DOT       = auto()   # .
    EQUALS    = auto()   # =
    BANG      = auto()   # !
    QUESTION  = auto()   # ?
    STAR      = auto()   # *
    SLASH     = auto()   # /
    PLUS      = auto()   # +
    MINUS     = auto()   # -
    PERCENT   = auto()   # %

    EOF = auto()


HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH'}


@dataclass
class Token:
    type: TT
    value: str
    line: int

    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r}, L{self.line})"


class LexerError(Exception):
    pass


class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self._after_http_method = False   # para reconocer URL paths

    def error(self, msg: str):
        raise LexerError(f"Línea {self.line}: {msg}")

    def peek(self, offset: int = 0) -> str:
        p = self.pos + offset
        return self.source[p] if p < len(self.source) else '\0'

    def advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == '\n':
            self.line += 1
        return ch

    def skip_ws_comments(self):
        while self.pos < len(self.source):
            ch = self.peek()
            if ch in ' \t\r\n':
                self.advance()
            elif ch == '/' and self.peek(1) == '/':
                while self.pos < len(self.source) and self.peek() != '\n':
                    self.advance()
            else:
                break

    def read_string(self) -> str:
        self.advance()  # opening "
        parts = []
        while self.pos < len(self.source) and self.peek() != '"':
            if self.peek() == '\\':
                self.advance()
                esc = self.advance()
                parts.append({'n': '\n', 't': '\t', '"': '"', '\\': '\\'}.get(esc, esc))
            else:
                parts.append(self.advance())
        if self.pos >= len(self.source):
            self.error("String sin cerrar")
        self.advance()  # closing "
        return ''.join(parts)

    def read_ident(self) -> str:
        start = self.pos
        while self.pos < len(self.source) and (self.peek().isalnum() or self.peek() == '_'):
            self.advance()
        return self.source[start:self.pos]

    def read_number(self):
        start = self.pos
        while self.pos < len(self.source) and self.peek().isdigit():
            self.advance()
        if self.peek() == '.' and self.peek(1).isdigit():
            self.advance()
            while self.pos < len(self.source) and self.peek().isdigit():
                self.advance()
            return self.source[start:self.pos], True
        return self.source[start:self.pos], False

    def read_url_path(self) -> str:
        start = self.pos
        while self.pos < len(self.source) and self.peek() not in ' \t\r\n\0':
            self.advance()
        return self.source[start:self.pos]

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []

        while True:
            self.skip_ws_comments()
            if self.pos >= len(self.source):
                tokens.append(Token(TT.EOF, '', self.line))
                break

            line = self.line
            ch = self.peek()

            # URL path (después de HTTP method en endpoint)
            if self._after_http_method and ch == '/':
                path = self.read_url_path()
                tokens.append(Token(TT.URL_PATH, path, line))
                self._after_http_method = False
                continue

            self._after_http_method = False

            # String literal
            if ch == '"':
                tokens.append(Token(TT.STRING_LIT, self.read_string(), line))

            # Número
            elif ch.isdigit():
                num, is_float = self.read_number()
                tokens.append(Token(TT.FLOAT_LIT if is_float else TT.INT_LIT, num, line))

            # Identificador / keyword
            elif ch.isalpha() or ch == '_':
                word = self.read_ident()
                tokens.append(Token(TT.IDENT, word, line))
                # Tras método HTTP dentro de endpoint, el siguiente token será URL
                if word in HTTP_METHODS and len(tokens) >= 2:
                    # Busca si hay un 'endpoint' reciente
                    for t in reversed(tokens[:-1]):
                        if t.type == TT.IDENT and t.value == 'endpoint':
                            self._after_http_method = True
                            break
                        if t.type not in (TT.IDENT,):
                            break

            # Operadores de dos caracteres
            elif ch == '-' and self.peek(1) == '>':
                self.advance(); self.advance()
                tokens.append(Token(TT.ARROW, '->', line))
            elif ch == '?' and self.peek(1) == '?':
                self.advance(); self.advance()
                tokens.append(Token(TT.DOUBLE_QUESTION, '??', line))
            elif ch == '=' and self.peek(1) == '=':
                self.advance(); self.advance()
                tokens.append(Token(TT.EQ_EQ, '==', line))
            elif ch == '!' and self.peek(1) == '=':
                self.advance(); self.advance()
                tokens.append(Token(TT.BANG_EQ, '!=', line))
            elif ch == '<' and self.peek(1) == '=':
                self.advance(); self.advance()
                tokens.append(Token(TT.LT_EQ, '<=', line))
            elif ch == '>' and self.peek(1) == '=':
                self.advance(); self.advance()
                tokens.append(Token(TT.GT_EQ, '>=', line))

            # Símbolos simples
            else:
                SIMPLE = {
                    '{': TT.LBRACE,  '}': TT.RBRACE,
                    '(': TT.LPAREN,  ')': TT.RPAREN,
                    '[': TT.LBRACKET, ']': TT.RBRACKET,
                    '<': TT.LANGLE,  '>': TT.RANGLE,
                    ':': TT.COLON,   ',': TT.COMMA,
                    ';': TT.SEMICOLON, '.': TT.DOT,
                    '=': TT.EQUALS,  '!': TT.BANG,
                    '?': TT.QUESTION, '*': TT.STAR,
                    '/': TT.SLASH,   '+': TT.PLUS,
                    '-': TT.MINUS,   '%': TT.PERCENT,
                }
                if ch in SIMPLE:
                    self.advance()
                    tokens.append(Token(SIMPLE[ch], ch, line))
                else:
                    self.error(f"Carácter inesperado: {ch!r}")

        return tokens
