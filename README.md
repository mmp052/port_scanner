# Port Scanner TCP

Projeto de estudo: scanner de portas TCP escrito em Python usando apenas a
biblioteca padrão `socket` — varredura de conexões completas, síncrona e
classificada por resultado.

## Requisitos para execução

- Python 3.10+. O desenvolvimento e os testes foram executados em Python 3.12.
- `pytest` (versão 8.3.4) para rodar os testes: `python3 -m pytest tests/`

## Instruções para iniciar o programa

```bash
python3 scanner.py <host> [opções]
```

`<host>`: endereço ou nome do destino (ex.: `127.0.0.1`, `scanme.nmap.org`).

## Parâmetros disponíveis

| Parâmetro | Descrição |
|---|---|
| `host` (posicional, obrigatório) | Endereço/nome do destino alvo. |
| `-p/--ports` | Portas a varrer: inteira (`22`), lista (`22,80,443`) ou intervalo (`1-1024`). Padrão: portas comuns. |
| `-t/--timeout` | Timeout por porta em segundos (padrão `1.0`). |
| `-o/--save ARQUIVO` | Salva um registro por porta (`porta` + `status`). Formato inferido pela extensão: `.csv` ou `.json`. |

## Exemplos de utilização

```bash
# Varre portas comuns de localhost
python3 scanner.py 127.0.0.1

# Varre uma faixa de portas, exibe o cabeçalho e salva resultados em CSV
python3 scanner.py 127.0.0.1 -p 1-1024 -t 0.3 -o saida.csv

# Varre portas específicas em host remoto, salva em JSON
python3 scanner.py scanme.nmap.org -p 22,80,443 -o saida.json
```

## Saída

- Um cabeçalho por execução: `Destino: <host> - Portas: <spec> - Timeout: <s>s`
-uma linha por porta aberta: `<porta>/tcp aberta`
- Um resumo final com contagem de portas: abertas, filtradas, fechadas,
  inalcançáveis e em erro, mais o tempo total decorrido.

## Melhoria implementada

Exportação de resultados per-porta em arquivo de saída (inclui a exportação JSON):

- `-o/--save ARQUIVO`: grava um registro por porta executada, com o status
  obtido (`aberta`, `fechada`, `filtrada`, `inalcancavel`, `erro`).
- Formato definido pela extensão do arquivo: `.json` → JSON indentado
  (`[{"porta": 22, "status": "aberta"}, ...]`); outra extensão (`.csv`) → CSV
  com header `porta,status`.
- `to_csv()`, `to_json()` e `salvar_arquivo()` implementados como funções
  puras e testados unitariamente.
- Tratamento de erros de I/O no arquivo de saída: mensagem comprehensiva no
  stderr e saída com código 2.

## Outros comportamentos (resumo)

- Classificação por resultado do `connect_ex()`: `0` → aberta;
  `ECONNREFUSED`/`ECONNRESET` → fechada; timeout (`socket.timeout`,
  `EAGAIN`, `ETIMEDOUT`) → filtrada; `EHOSTUNREACH`/`ENETUNREACH` →
  inalcancavel; outros → erro.
- Interrupção pelo usuário (Ctrl+C): mensagem `interrompido pelo usuário`
  no stderr e saída com código 130, sem traceback.
- Falha em uma porta não impede a varredura das demais (marcada como erro e
  contabilizada no resumo).
- Suíte de testes: 37 testes (`tests/test_scanner.py`).

## Notas importantes

- Scanner é ferramenta de duplo uso: use-o apenas em destinos
  autorizados (seu host, rede local ou serviços com âmbito correto).
- Varredura é *full connect*: o host alvo recebe as conexões completas —
  não é stealth.

## Testes

```bash
python3 -m pytest tests/
```
