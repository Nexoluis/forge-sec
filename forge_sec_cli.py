#!/usr/bin/env python3
"""
forge-sec CLI
Uso:
  forge-sec build login.fs --target php8.2
  forge-sec check login.fs
  forge-sec build login.fs --target php8.2 --output login.php
"""
import sys
import argparse
from pathlib import Path

from forge_sec.lexer import Lexer, LexerError
from forge_sec.parser import Parser, ParseError
from forge_sec.type_checker import TypeChecker, TypeError
from forge_sec.security_report import generate_report
from forge_sec.backends.php import PHPBackend


def cmd_build(args):
    source_path = Path(args.file)
    if not source_path.exists():
        print(f"❌ Archivo no encontrado: {args.file}", file=sys.stderr)
        sys.exit(1)

    source = source_path.read_text(encoding='utf-8')
    print(f"🔨 Compilando {source_path.name} → {args.target} ...\n")

    # 1. Lex
    try:
        tokens = Lexer(source).tokenize()
    except LexerError as e:
        print(f"❌ Error léxico: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Parse
    try:
        program = Parser(tokens).parse_program()
    except ParseError as e:
        print(f"❌ Error sintáctico: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Type check
    tc = TypeChecker()
    ok = tc.check_program(program)

    if tc.errors:
        print("❌ ERRORES DE SEGURIDAD — compilación bloqueada:")
        for err in tc.errors:
            print(f"   {err}")
        print()
        sys.exit(2)

    if tc.warnings:
        print("⚠️  Advertencias:")
        for w in tc.warnings:
            print(f"   {w}")
        print()

    # 4. Generar código
    if args.target == 'php8.2':
        backend = PHPBackend()
        code = backend.generate_program(program, source_path.name)
    elif args.target in ('python3', 'python3.12'):
        from forge_sec.backends.python3 import Python3Backend
        backend = Python3Backend()
        code = backend.generate_program(program, source_path.name)
    elif args.target in ('java21', 'java'):
        from forge_sec.backends.java21 import Java21Backend
        backend = Java21Backend()
        code = backend.generate_program(program, source_path.name)
    elif args.target in ('rust',):
        from forge_sec.backends.rust import RustBackend
        backend = RustBackend()
        code = backend.generate_program(program, source_path.name)
    else:
        print(f"❌ Target no soportado: {args.target} (disponibles: php8.2, python3, java21, rust)", file=sys.stderr)
        sys.exit(1)

    # 5. Security report
    report = generate_report(program, tc.errors, tc.warnings)

    # 6. Output
    ext = ('.php'  if 'php'    in args.target
           else '.py'   if 'python' in args.target
           else '.java' if 'java'   in args.target
           else '.rs'   if 'rust'   in args.target
           else '.out')
    output_path = Path(args.output) if args.output else source_path.with_suffix(ext)
    output_path.write_text(code, encoding='utf-8')
    print(f"✅ Código generado: {output_path}")
    print(report)

    report_path = output_path.with_name(output_path.stem + '_security_report.txt')
    report_path.write_text(report, encoding='utf-8')
    print(f"📋 Security report: {report_path}")


def cmd_check(args):
    source_path = Path(args.file)
    if not source_path.exists():
        print(f"❌ Archivo no encontrado: {args.file}", file=sys.stderr)
        sys.exit(1)

    source = source_path.read_text(encoding='utf-8')
    print(f"🔍 Verificando {source_path.name} ...\n")

    try:
        tokens = Lexer(source).tokenize()
        program = Parser(tokens).parse_program()
    except (LexerError, ParseError) as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)

    tc = TypeChecker()
    ok = tc.check_program(program)

    if tc.errors:
        for err in tc.errors:
            print(err)
        sys.exit(2)

    if tc.warnings:
        for w in tc.warnings:
            print(w)

    if ok:
        print("✅ Sin errores de seguridad")


def main():
    parser = argparse.ArgumentParser(
        prog='forge-sec',
        description='FORGE-SEC — Compilador de lenguaje de intención segura'
    )
    sub = parser.add_subparsers(dest='cmd')

    # forge-sec build
    build = sub.add_parser('build', help='Compilar a lenguaje target')
    build.add_argument('file', help='Archivo .fs fuente')
    build.add_argument('--target', default='php8.2',
                       help='Target: php8.2 (más targets próximamente)')
    build.add_argument('--output', '-o', default='', help='Archivo de salida')

    # forge-sec check
    check = sub.add_parser('check', help='Solo verificar tipos/seguridad sin generar código')
    check.add_argument('file', help='Archivo .fs fuente')

    args = parser.parse_args()

    if args.cmd == 'build':
        cmd_build(args)
    elif args.cmd == 'check':
        cmd_check(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
