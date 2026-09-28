# -*- coding: utf-8 -*-
"""
Executa os notebooks do pipeline localmente, em sequência e na mesma sessão Spark,
reproduzindo o que o Job do Databricks faz na nuvem. Usado para testar o código
antes da execução no Databricks.

    python scripts/executar_local.py            # todos os notebooks
    python scripts/executar_local.py 03 04      # apenas os indicados (exige os anteriores na sessão)

Os notebooks estão no formato "Databricks notebook source": células separadas por
'# COMMAND ----------' e células de texto prefixadas por '# MAGIC'. Aqui as células de
texto são ignoradas e as de código são executadas.
"""
import glob
import os
import sys
import time
import traceback

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PASTA_NOTEBOOKS = os.path.join(RAIZ, "notebooks")
SEPARADOR = "# COMMAND ----------"


def celulas_de_codigo(caminho):
    with open(caminho, encoding="utf-8") as f:
        texto = f.read()
    for bloco in texto.split(SEPARADOR):
        linhas = [l for l in bloco.strip("\n").splitlines()
                  if l.strip() and l.strip() != "# Databricks notebook source"]
        if not linhas or all(l.lstrip().startswith("# MAGIC") for l in linhas):
            continue
        yield bloco


def executar(caminho):
    nome = os.path.basename(caminho)
    print(f"\n{'=' * 90}\n▶ {nome}\n{'=' * 90}")
    inicio = time.time()
    escopo = {"__name__": "__main__", "__file__": caminho}
    cwd = os.getcwd()
    os.chdir(PASTA_NOTEBOOKS)   # no Databricks o diretório de trabalho é a pasta do notebook
    try:
        for i, bloco in enumerate(celulas_de_codigo(caminho), 1):
            exec(compile(bloco, f"{nome}[célula {i}]", "exec"), escopo)
    finally:
        os.chdir(cwd)
    print(f"✔ {nome} concluído em {time.time() - inicio:.1f}s")


if __name__ == "__main__":
    filtros = sys.argv[1:]
    notebooks = sorted(glob.glob(os.path.join(PASTA_NOTEBOOKS, "[0-9][0-9]_*.py")))
    if filtros:
        notebooks = [n for n in notebooks if any(os.path.basename(n).startswith(f) for f in filtros)]
    total = time.time()
    try:
        for nb in notebooks:
            executar(nb)
    except Exception:
        traceback.print_exc()
        print("\n✘ Execução interrompida por erro.")
        sys.exit(1)
    print(f"\nPipeline local concluído: {len(notebooks)} notebooks em {time.time() - total:.0f}s")
