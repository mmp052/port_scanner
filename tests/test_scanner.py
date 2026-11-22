import errno
import json

import scanner


def test_parse_portas_single():
    assert scanner.parse_portas("80") == [80]


def test_parse_portas_range():
    assert scanner.parse_portas("1-3") == [1, 2, 3]


def test_parse_portas_comma_list():
    assert scanner.parse_portas("22,80,443") == [22, 80, 443]


def test_parse_portas_dedupes_preserving_order():
    assert scanner.parse_portas("22,80-81,22") == [22, 80, 81]


import pytest


@pytest.mark.parametrize("spec", ["", "abc", "0", "65536"])
def test_parse_portas_invalid_single(spec):
    with pytest.raises(ValueError):
        scanner.parse_portas(spec)


def test_parse_portas_inverted_range():
    with pytest.raises(ValueError):
        scanner.parse_portas("3-1")


def test_classificar_resultado_timeout_tem_precedencia():
    assert scanner.classificar_resultado(0, True) is scanner.Status.FILTRADA


def test_classificar_resultado_sucesso():
    assert scanner.classificar_resultado(0, False) is scanner.Status.ABERTA


@pytest.mark.parametrize("codigo", [errno.ECONNREFUSED, errno.ECONNRESET])
def test_classificar_resultado_recusada(codigo):
    assert scanner.classificar_resultado(codigo, False) is scanner.Status.FECHADA


def test_classificar_resultado_etimedout():
    assert scanner.classificar_resultado(errno.ETIMEDOUT, False) is scanner.Status.FILTRADA


def test_classificar_resultado_eagain():
    assert scanner.classificar_resultado(errno.EAGAIN, False) is scanner.Status.FILTRADA


@pytest.mark.parametrize("codigo", [errno.EHOSTUNREACH, errno.ENETUNREACH])
def test_classificar_resultado_inalcancavel(codigo):
    assert scanner.classificar_resultado(codigo, False) is scanner.Status.INALCANCAVEL


@pytest.fixture
def porta_aberta():
    import socket as _socket

    servidor = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    servidor.bind(("127.0.0.1", 0))
    servidor.listen(1)
    porta = servidor.getsockname()[1]
    yield porta
    servidor.close()


def test_escanear_porta_aberta(porta_aberta):
    assert scanner.escanear_porta("127.0.0.1", porta_aberta, 1.0) is scanner.Status.ABERTA


@pytest.fixture
def porta_fechada():
    import socket as _socket

    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    yield porta


def test_escanear_porta_fechada(porta_fechada):
    assert scanner.escanear_porta("127.0.0.1", porta_fechada, 1.0) is scanner.Status.FECHADA


def test_escanear_porta_timeout(monkeypatch):
    import socket as _socket

    class FakeSocket:
        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            raise _socket.timeout

        def close(self):
            pass

    monkeypatch.setattr(scanner.socket, "socket", lambda *a, **kw: FakeSocket())
    assert scanner.escanear_porta("10.255.255.1", 80, 0.1) is scanner.Status.FILTRADA


def test_resumo_execucao_com_abertas():
    txt = scanner.resumo_execucao([22, 80], [], [], [], [], 0.0, 1.234)
    linhas = txt.splitlines()
    assert linhas[0] == "2 porta(s) aberta(s): 22, 80"
    assert "0 porta(s) filtrada(s)" in linhas
    assert "tempo total: 1.2s" in txt


def test_resumo_execucao_sem_abertas():
    txt = scanner.resumo_execucao([], [1, 2], [], [], [], 0.0, 2.0)
    assert "0 porta(s) aberta(s)" in txt.splitlines()
    assert "2 porta(s) filtrada(s)" in txt


def test_main_lista_porta_aberta(porta_aberta, capsys):
    codigo = scanner.main(["127.0.0.1", "-p", str(porta_aberta)])
    saida = capsys.readouterr().out
    assert codigo == 0
    assert f"{porta_aberta}/tcp aberta" in saida


def test_main_imprime_cabecalho(porta_aberta, capsys):
    codigo = scanner.main(["127.0.0.1", "-p", str(porta_aberta), "-t", "0.5"])
    saida = capsys.readouterr().out
    assert codigo == 0
    assert saida.splitlines()[0] == f"Destino: 127.0.0.1 - Portas: {porta_aberta} - Timeout: 0.5s"


def test_main_resumo_informa_fechadas(porta_fechada, capsys):
    codigo = scanner.main(["127.0.0.1", "-p", str(porta_fechada), "-t", "0.5"])
    saida = capsys.readouterr().out
    assert codigo == 0
    assert "1 porta(s) fechada(s)" in saida


def test_main_resumo_informa_filtradas(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "escanear_porta",
                        lambda host, porta, timeout: scanner.Status.FILTRADA)
    codigo = scanner.main(["127.0.0.1", "-p", "1-3"])
    saida = capsys.readouterr().out
    assert codigo == 0
    assert "3 porta(s) filtrada(s)" in saida


def test_main_continua_pos_erro_conexao(monkeypatch, capsys):
    chamadas = []

    def fake_escanear(host, porta, timeout):
        chamadas.append(porta)
        if porta == 1:
            raise OSError("falha simulada")
        return scanner.Status.ABERTA

    monkeypatch.setattr(scanner, "escanear_porta", fake_escanear)
    codigo = scanner.main(["127.0.0.1", "-p", "1-2", "-t", "0.1"])
    saida = capsys.readouterr().out
    assert codigo == 0
    assert chamadas == [1, 2]
    assert "2/tcp aberta" in saida


def test_main_interrompido_teclado(monkeypatch, capsys):
    def fake_escanear(host, porta, timeout):
        raise KeyboardInterrupt

    monkeypatch.setattr(scanner, "escanear_porta", fake_escanear)
    caught = False
    try:
        codigo = scanner.main(["127.0.0.1", "-p", "1-3"])
    except KeyboardInterrupt:
        caught = True
    saida = capsys.readouterr()
    assert not caught
    assert codigo == 130
    assert "interrompido" in saida.err


def test_main_host_inexistente(capsys):
    codigo = scanner.main(["host-que-nao-existe.invalid", "-p", "80", "-t", "0.1"])
    saida = capsys.readouterr()
    assert codigo == 2
    assert "nao foi possivel resolver" in saida.err


def test_main_portas_invalidas(capsys):
    codigo = scanner.main(["127.0.0.1", "-p", "99999"])
    saida = capsys.readouterr()
    assert codigo == 2
    assert "erro" in saida.err


def test_to_csv_saida():
    registros = [(22, scanner.Status.ABERTA), (80, scanner.Status.FECHADA)]
    assert scanner.to_csv(registros) == "porta,status\n22,aberta\n80,fechada\n"


def test_to_json_saida():
    registros = [(22, scanner.Status.ABERTA), (80, scanner.Status.FILTRADA)]
    assert json.loads(scanner.to_json(registros)) == [
        {"porta": 22, "status": "aberta"},
        {"porta": 80, "status": "filtrada"},
    ]


def test_salvar_arquivo_csv(tmp_path):
    out = tmp_path / "res.csv"
    scanner.salvar_arquivo(out, [(22, scanner.Status.ABERTA)])
    assert out.read_text() == "porta,status\n22,aberta\n"


def test_salvar_arquivo_json(tmp_path):
    out = tmp_path / "res.json"
    scanner.salvar_arquivo(out, [(22, scanner.Status.ABERTA)])
    assert json.loads(out.read_text()) == [{"porta": 22, "status": "aberta"}]


def test_main_salva_csv_arquivo(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(scanner, "escanear_porta",
                        lambda host, porta, timeout: scanner.Status.ABERTA)
    out = tmp_path / "res.csv"
    codigo = scanner.main(["127.0.0.1", "-p", "22,80", "-t", "0.5", "-o", str(out)])
    saida = capsys.readouterr()
    assert codigo == 0
    assert out.read_text().splitlines() == ["porta,status", "22,aberta", "80,aberta"]
    assert "22/tcp aberta" in saida.out


def test_main_salva_json_arquivo(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "escanear_porta",
                        lambda host, porta, timeout: scanner.Status.ABERTA)
    out = tmp_path / "res.json"
    codigo = scanner.main(["127.0.0.1", "-p", "22,80", "-o", str(out)])
    assert codigo == 0
    assert json.loads(out.read_text()) == [
        {"porta": 22, "status": "aberta"},
        {"porta": 80, "status": "aberta"},
    ]


def test_main_erro_ao_salvar(capsys, tmp_path):
    out = tmp_path / "nao_existe" / "res.csv"
    codigo = scanner.main(["127.0.0.1", "-p", "22", "-t", "0.5", "-o", str(out)])
    saida = capsys.readouterr()
    assert codigo == 2
    assert "erro" in saida.err
