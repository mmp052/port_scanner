import argparse
import errno
import json
import socket
import sys
import time
from enum import Enum

PORTAS_COMUNS = [
    7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 49, 53, 67, 68, 69, 70,
    79, 80, 88, 110, 111, 113, 123, 135, 139, 143, 161, 179, 443, 445, 465,
    500, 514, 515, 587, 631, 636, 873, 902, 990, 993, 995, 1080, 1099, 1433,
    1521, 1723, 1812, 1813, 2049, 2181, 2375, 2376, 3000, 3128, 3268, 3306,
    3389, 3690, 4000, 4443, 4444, 5000, 5060, 5061, 5432, 5672, 5900, 5984,
    5985, 5986, 6379, 6443, 6667, 7001, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9000, 9043, 9090, 9091, 9092, 9200, 9300, 9418, 9999, 10000, 11211,
    15672, 27017, 50000, 50030, 50070,
]


class Status(Enum):
    ABERTA = "aberta"
    FECHADA = "fechada"
    FILTRADA = "filtrada"
    INALCANCAVEL = "inalcancavel"
    ERRO = "erro"


_TIMEOUT_ERRNOS = [errno.ETIMEDOUT]
if hasattr(errno, "EAGAIN"):
    _TIMEOUT_ERRNOS.append(errno.EAGAIN)
_TIMEOUT_ERRNOS = tuple(_TIMEOUT_ERRNOS)


def classificar_resultado(codigo, estourou_timeout):
    if estourou_timeout:
        return Status.FILTRADA
    if codigo == 0:
        return Status.ABERTA
    if codigo in (errno.ECONNREFUSED, errno.ECONNRESET):
        return Status.FECHADA
    if codigo in _TIMEOUT_ERRNOS:
        return Status.FILTRADA
    if codigo in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        return Status.INALCANCAVEL
    return Status.ERRO


def _validar_porta(porta):
    if not 1 <= porta <= 65535:
        raise ValueError(f"porta fora de 1-65535: {porta}")


def parse_portas(spec):
    portas = []
    for token in spec.split(","):
        token = token.strip()
        if "-" in token:
            partes = token.split("-")
            if len(partes) != 2:
                raise ValueError(f"faixa malformada: {token!r}")
            try:
                inicio, fim = int(partes[0]), int(partes[1])
            except ValueError:
                raise ValueError(f"faixa nao numerica: {token!r}") from None
            _validar_porta(inicio)
            _validar_porta(fim)
            if inicio > fim:
                raise ValueError(f"faixa invertida: {token!r}")
            portas.extend(range(inicio, fim + 1))
        else:
            try:
                porta = int(token)
            except ValueError:
                raise ValueError(f"porta nao numerica: {token!r}") from None
            _validar_porta(porta)
            portas.append(porta)
    return list(dict.fromkeys(portas))


def resumo_execucao(abertas, filtradas, fechadas, inalcancavel, erros, inicio, fim):
    if abertas:
        linhas = [f"{len(abertas)} porta(s) aberta(s): {', '.join(str(p) for p in abertas)}"]
    else:
        linhas = ["0 porta(s) aberta(s)"]
    linhas.append(f"{len(filtradas)} porta(s) filtrada(s)")
    linhas.append(f"{len(fechadas)} porta(s) fechada(s)")
    linhas.append(f"{len(inalcancavel)} porta(s) inalcancavel(s)")
    linhas.append(f"{len(erros)} porta(s) em erro")
    linhas.append(f"tempo total: {fim - inicio:.1f}s")
    return "\n".join(linhas)


def escanear_porta(host, porta, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    estourou_timeout = False
    try:
        codigo = s.connect_ex((host, porta))
    except socket.timeout:
        estourou_timeout = True
        codigo = None
    finally:
        s.close()
    return classificar_resultado(codigo, estourou_timeout)


def to_csv(resultados):
    from io import StringIO

    import csv

    saida = StringIO()
    writer = csv.writer(saida, lineterminator="\n")
    writer.writerow(["porta", "status"])
    for porta, status in resultados:
        writer.writerow([porta, status.value])
    return saida.getvalue()


def to_json(resultados):
    return json.dumps(
        [{"porta": porta, "status": status.value} for porta, status in resultados],
        indent=2,
    )


def salvar_arquivo(path, resultados):
    texto = to_json(resultados) if str(path).lower().endswith(".json") else to_csv(resultados)
    with open(path, "w", encoding="utf-8") as f:
        f.write(texto)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Port scanner TCP simples")
    parser.add_argument("host", help="endereco ou nome do host alvo")
    parser.add_argument("-p", "--ports", default=None,
                        help="ex.: '22,80,443' ou '1-1024'; padrao: portas comuns")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="timeout por porta em segundos (padrao: 1.0)")
    parser.add_argument("-o", "--save", default=None,
                        help="salvar resultados por porta em arquivo (.csv ou .json)")
    args = parser.parse_args(argv)

    try:
        socket.getaddrinfo(args.host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        print(f"erro: nao foi possivel resolver o host {args.host!r}", file=sys.stderr)
        return 2

    try:
        portas = parse_portas(args.ports) if args.ports else list(PORTAS_COMUNS)
    except ValueError as e:
        print(f"erro: {e}", file=sys.stderr)
        return 2

    portas_descricao = args.ports if args.ports else "portas comuns"
    print(f"Destino: {args.host} - Portas: {portas_descricao} - Timeout: {args.timeout}s")

    abertas = []
    filtradas = []
    fechadas = []
    inalcancavel = []
    erros = []
    resultados = []
    inicio = time.monotonic()
    try:
        for porta in portas:
            try:
                status = escanear_porta(args.host, porta, args.timeout)
            except OSError:
                status = Status.ERRO
            resultados.append((porta, status))
            if status is Status.ABERTA:
                print(f"{porta}/tcp aberta")
                abertas.append(porta)
            elif status is Status.FECHADA:
                fechadas.append(porta)
            elif status is Status.FILTRADA:
                filtradas.append(porta)
            elif status is Status.INALCANCAVEL:
                inalcancavel.append(porta)
            else:
                erros.append(porta)
    except KeyboardInterrupt:
        print("interrompido pelo usuario", file=sys.stderr)
        return 130
    fim = time.monotonic()
    print(resumo_execucao(abertas, filtradas, fechadas, inalcancavel, erros, inicio, fim))
    if args.save:
        try:
            salvar_arquivo(args.save, resultados)
        except OSError as e:
            print(f"erro ao salvar resultados em {args.save}: {e}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
