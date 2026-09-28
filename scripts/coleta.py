# -*- coding: utf-8 -*-
"""
Coleta dos dados brutos do MVP (camada landing).

Baixa quatro fontes públicas e grava os arquivos exatamente como publicados,
registrando um manifesto com URL, data/hora da coleta, tamanho e hash SHA-256
de cada arquivo (base da reprodutibilidade e da linhagem dos dados).

Fontes:
  1. CISA KEV  — catálogo de vulnerabilidades exploradas ativamente (JSON)
  2. NVD/NIST  — API CVE 2.0: CVEs do KEV + CVEs publicadas em 2024 (JSON paginado)
  3. FIRST EPSS — probabilidade de exploração: snapshot atual e de 2025-01-01 (CSV.gz)
  4. MITRE CWE — catálogo de fraquezas, visão 1000 (CSV)

Pode ser usado:
  - dentro do Databricks (notebook 01_coleta), gravando no Volume do Unity Catalog;
  - localmente:  python scripts/coleta.py --destino dados/landing [--nvd-api-key CHAVE]

Só usa a biblioteca padrão do Python (urllib), para rodar em qualquer ambiente.
"""
import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

USER_AGENT = "mvp-seguranca-cibernetica/1.0 (trabalho academico UnB)"

URLS_KEV = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
URL_EPSS_ATUAL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
URL_EPSS_DATA = "https://epss.empiricalsecurity.com/epss_scores-{data}.csv.gz"
URL_CWE = "https://cwe.mitre.org/data/csv/1000.csv.zip"
URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DATA_CORTE_EPSS = "2025-01-01"        # snapshot usado na avaliação prospectiva (pergunta P3)
ANO_COORTE = 2024                     # CVEs publicadas neste ano formam a população de P3
NVD_POR_PAGINA = 2000                 # máximo permitido pela API
NVD_JANELA_MAX_DIAS = 119             # a API aceita no máximo 120 dias por consulta


# ----------------------------------------------------------------------------- utilidades
def agora_utc():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _requisitar(url, tentativas=6, espera_base=6.0, timeout=120, cabecalhos=None):
    """GET com novas tentativas e espera exponencial (a API do NVD devolve 403/503
    quando o limite de requisições é excedido)."""
    cab = {"User-Agent": USER_AGENT}
    cab.update(cabecalhos or {})
    ultimo_erro = None
    for i in range(tentativas):
        try:
            req = urllib.request.Request(url, headers=cab)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                corpo = r.read()
            if not corpo:
                raise IOError("resposta vazia")
            return corpo
        except (urllib.error.HTTPError, urllib.error.URLError, IOError, TimeoutError) as e:
            ultimo_erro = e
            codigo = getattr(e, "code", None)
            if codigo == 404:
                raise
            pausa = espera_base * (2 ** i)
            print(f"    tentativa {i + 1}/{tentativas} falhou ({e}); nova tentativa em {pausa:.0f}s")
            time.sleep(pausa)
    raise RuntimeError(f"Falha ao baixar {url}: {ultimo_erro}")


def _gravar(caminho, conteudo):
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    if caminho.startswith("/Volumes/"):
        # Volumes do Unity Catalog: gravação direta (renomear arquivos no volume é evitado)
        with open(caminho, "wb") as f:
            f.write(conteudo)
        return
    temporario = caminho + ".parcial"
    with open(temporario, "wb") as f:
        f.write(conteudo)
    os.replace(temporario, caminho)


def _registro(fonte, caminho, url, conteudo, registros=None, observacao=None):
    return {
        "fonte": fonte,
        "arquivo": os.path.basename(caminho),
        "pasta": os.path.basename(os.path.dirname(caminho)),
        "url": url,
        "coletado_em_utc": agora_utc().isoformat(),
        "bytes": len(conteudo),
        "sha256": hashlib.sha256(conteudo).hexdigest(),
        "registros": registros,
        "formato": caminho.rsplit("/", 1)[-1].split(".", 1)[-1],
        "observacao": observacao,
    }


# ----------------------------------------------------------------------------- fontes
def coletar_kev(destino):
    """Catálogo KEV completo (JSON oficial da CISA; espelho oficial no GitHub como reserva)."""
    for url in URLS_KEV:
        try:
            conteudo = _requisitar(url, tentativas=3)
            dados = json.loads(conteudo)
            break
        except Exception as e:  # tenta o próximo espelho
            print(f"    KEV indisponível em {url}: {e}")
    else:
        raise RuntimeError("Nenhuma fonte do KEV respondeu.")
    caminho = f"{destino}/kev/known_exploited_vulnerabilities.json"
    _gravar(caminho, conteudo)
    n = len(dados.get("vulnerabilities", []))
    print(f"  KEV: {n} vulnerabilidades, versão do catálogo {dados.get('catalogVersion')}")
    return [_registro("CISA KEV", caminho, url, conteudo, n,
                      f"catalogVersion={dados.get('catalogVersion')}; dateReleased={dados.get('dateReleased')}")]


def _cabecalho_epss(conteudo_gz):
    """A primeira linha do arquivo EPSS traz versão do modelo e data de referência."""
    with gzip.open(io.BytesIO(conteudo_gz), "rt", encoding="utf-8") as f:
        primeira = f.readline().strip()
        linhas = sum(1 for _ in f) - 1  # desconta a linha de cabeçalho de colunas
    return primeira, linhas


def coletar_epss(destino):
    registros = []
    for rotulo, url in [("atual", URL_EPSS_ATUAL),
                        ("corte", URL_EPSS_DATA.format(data=DATA_CORTE_EPSS))]:
        conteudo = _requisitar(url, tentativas=4)
        meta, linhas = _cabecalho_epss(conteudo)
        nome = "epss_scores_atual.csv.gz" if rotulo == "atual" else f"epss_scores_{DATA_CORTE_EPSS}.csv.gz"
        caminho = f"{destino}/epss/{nome}"
        _gravar(caminho, conteudo)
        print(f"  EPSS ({rotulo}): {linhas} CVEs — {meta}")
        registros.append(_registro("FIRST EPSS", caminho, url, conteudo, linhas, meta))
    return registros


def coletar_cwe(destino):
    """Catálogo CWE (visão 1000 — Research Concepts). O ZIP é descompactado porque o
    Spark não lê arquivos .zip diretamente; o hash registrado é o do CSV gravado."""
    conteudo_zip = _requisitar(URL_CWE, tentativas=4)
    with zipfile.ZipFile(io.BytesIO(conteudo_zip)) as z:
        nome_csv = [n for n in z.namelist() if n.lower().endswith(".csv")][0]
        conteudo = z.read(nome_csv)
    caminho = f"{destino}/cwe/cwe_1000.csv"
    _gravar(caminho, conteudo)
    import csv
    linhas = sum(1 for _ in csv.reader(io.StringIO(conteudo.decode("utf-8")))) - 1   # sem o cabeçalho
    print(f"  CWE: {linhas} fraquezas no arquivo {nome_csv}")
    return [_registro("MITRE CWE", caminho, URL_CWE, conteudo, linhas,
                      f"extraído de {nome_csv} dentro do ZIP")]


def _janelas_do_ano(ano):
    inicio = dt.date(ano, 1, 1)
    fim_ano = dt.date(ano, 12, 31)
    while inicio <= fim_ano:
        fim = min(inicio + dt.timedelta(days=NVD_JANELA_MAX_DIAS), fim_ano)
        yield inicio, fim
        inicio = fim + dt.timedelta(days=1)


def _paginar_nvd(parametros, prefixo, destino_pasta, api_key, fonte_desc):
    """Percorre todas as páginas de uma consulta à API do NVD, gravando cada página
    (JSON compactado em gzip) sem nenhuma alteração de conteúdo."""
    cab = {"apiKey": api_key} if api_key else {}
    pausa = 0.8 if api_key else 6.5   # limite: 5 req/30s sem chave; 50 req/30s com chave
    registros, inicio, total, pagina = [], 0, None, 0
    while total is None or inicio < total:
        consulta = dict(parametros, resultsPerPage=NVD_POR_PAGINA, startIndex=inicio)
        # 'hasKev' é um parâmetro sem valor na API do NVD
        qs = urllib.parse.urlencode({k: v for k, v in consulta.items() if v is not None})
        if "hasKev" in parametros:
            qs = "hasKev&" + qs
        url = f"{URL_NVD}?{qs}"
        conteudo = _requisitar(url, cabecalhos=cab)
        dados = json.loads(conteudo)
        total = dados["totalResults"]
        n = len(dados.get("vulnerabilities", []))
        caminho = f"{destino_pasta}/{prefixo}_p{pagina:03d}.json.gz"
        _gravar(caminho, gzip.compress(conteudo))
        registros.append(_registro("NVD API 2.0", caminho, url, conteudo, n, fonte_desc))
        print(f"    {prefixo} página {pagina}: {n} CVEs (índice {inicio}/{total})")
        inicio += NVD_POR_PAGINA
        pagina += 1
        time.sleep(pausa)
    return registros, total


def coletar_nvd(destino, api_key=None):
    registros = []
    print("  NVD: CVEs presentes no catálogo KEV (parâmetro hasKev)")
    r, total = _paginar_nvd({"hasKev": None}, "nvd_kev", f"{destino}/nvd/kev", api_key,
                            "CVEs com cisaExploitAdd (hasKev)")
    registros += r
    print(f"  NVD: CVEs publicadas em {ANO_COORTE} (janelas de até 120 dias)")
    for ini, fim in _janelas_do_ano(ANO_COORTE):
        params = {"pubStartDate": f"{ini.isoformat()}T00:00:00.000",
                  "pubEndDate": f"{fim.isoformat()}T23:59:59.999"}
        r, total = _paginar_nvd(params, f"nvd_pub{ANO_COORTE}_{ini:%m%d}",
                                f"{destino}/nvd/pub{ANO_COORTE}", api_key,
                                f"publicadas entre {ini} e {fim}")
        registros += r
    return registros


# ----------------------------------------------------------------------------- orquestração
FONTES = {"kev": coletar_kev, "epss": coletar_epss, "cwe": coletar_cwe, "nvd": coletar_nvd}


def coletar_tudo(destino, api_key=None, fontes=("kev", "epss", "cwe", "nvd")):
    destino = destino.rstrip("/\\").replace("\\", "/")
    os.makedirs(destino, exist_ok=True)
    caminho_manifesto = f"{destino}/_manifesto_coleta.json"
    manifesto = []
    if os.path.exists(caminho_manifesto):
        with open(caminho_manifesto, encoding="utf-8") as f:
            anteriores = json.load(f).get("arquivos", [])
        manifesto = [m for m in anteriores if m["fonte"].split()[0].lower() not in
                     {FONTES_PARA_ROTULO[x] for x in fontes}]
    inicio = time.time()
    for nome in fontes:
        print(f"[{agora_utc():%H:%M:%S}] Coletando {nome.upper()} ...")
        if nome == "nvd":
            manifesto += coletar_nvd(destino, api_key)
        else:
            manifesto += FONTES[nome](destino)
    resumo = {
        "coleta_iniciada_utc": manifesto[0]["coletado_em_utc"] if manifesto else None,
        "coleta_concluida_utc": agora_utc().isoformat(),
        "duracao_segundos": round(time.time() - inicio, 1),
        "total_arquivos": len(manifesto),
        "total_bytes": sum(m["bytes"] for m in manifesto),
        "arquivos": manifesto,
    }
    with open(caminho_manifesto, "w", encoding="utf-8") as f:
        json.dump(resumo, f, ensure_ascii=False, indent=2)
    print(f"Coleta concluída: {resumo['total_arquivos']} arquivos, "
          f"{resumo['total_bytes'] / 1e6:.1f} MB, {resumo['duracao_segundos']:.0f}s")
    return resumo


FONTES_PARA_ROTULO = {"kev": "cisa", "epss": "first", "cwe": "mitre", "nvd": "nvd"}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Coleta dos dados brutos do MVP")
    ap.add_argument("--destino", default="dados/landing")
    ap.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--fontes", default="kev,epss,cwe,nvd")
    a = ap.parse_args()
    coletar_tudo(a.destino, a.nvd_api_key, tuple(a.fontes.split(",")))
    sys.exit(0)
