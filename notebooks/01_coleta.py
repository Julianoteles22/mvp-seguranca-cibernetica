# Databricks notebook source
# MAGIC %md
# MAGIC # 01 · Coleta dos dados brutos (landing)
# MAGIC
# MAGIC **MVP — Priorização de vulnerabilidades com dados públicos de segurança cibernética**
# MAGIC
# MAGIC Este notebook baixa as quatro fontes do trabalho e grava os arquivos **sem nenhuma alteração**
# MAGIC no Volume `workspace.ciber_bronze.landing` do Unity Catalog. Cada arquivo é registrado em um
# MAGIC manifesto com URL, data/hora UTC da coleta, tamanho e hash SHA-256 — é isso que garante a
# MAGIC reprodutibilidade e o início da linhagem dos dados.
# MAGIC
# MAGIC | Fonte | Conteúdo | Formato | Licença |
# MAGIC |---|---|---|---|
# MAGIC | CISA KEV | Vulnerabilidades com exploração ativa confirmada | JSON | CC0 1.0 |
# MAGIC | NVD / NIST (API 2.0) | Detalhes das CVEs: datas, CVSS, CWE, status | JSON paginado (gzip) | Domínio público (governo dos EUA), com aviso obrigatório |
# MAGIC | FIRST EPSS | Probabilidade de exploração em 30 dias (snapshot atual e de 01/01/2025) | CSV.gz | Uso livre, atribuição solicitada |
# MAGIC | MITRE CWE | Catálogo de fraquezas de software (visão 1000) | CSV | Termos de uso da MITRE (uso livre com aviso de copyright) |
# MAGIC
# MAGIC > **Se a computação serverless não tiver acesso à internet**, rode localmente
# MAGIC > `python scripts/coleta.py --destino dados/landing` e envie a pasta `dados/landing`
# MAGIC > para o Volume pela interface (*Catalog → workspace → ciber_bronze → landing → Upload to this volume*),
# MAGIC > mantendo as subpastas. Este notebook detecta os arquivos e segue normalmente.

# COMMAND ----------

import os
import sys
import json

sys.path.insert(0, os.path.abspath(".."))          # raiz do repositório (pasta scripts/)
from scripts import ambiente, coleta

spark = ambiente.preparar_ambiente()
print("Ambiente:", "Databricks" if ambiente.EM_DATABRICKS else "local")
print("Destino dos arquivos brutos:", ambiente.RAIZ_LANDING if ambiente.EM_DATABRICKS
      else os.path.relpath(ambiente.RAIZ_LANDING, ambiente.RAIZ_REPO))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Parâmetros
# MAGIC * `FORCAR_COLETA`: baixa tudo de novo mesmo que o manifesto já exista.
# MAGIC * `NVD_API_KEY`: opcional. Sem chave, a API do NVD permite 5 requisições a cada 30 s
# MAGIC   (a coleta leva ~8 min); com chave gratuita, o limite sobe para 50.

# COMMAND ----------

FORCAR_COLETA = False
NVD_API_KEY = os.environ.get("NVD_API_KEY")      # não versionar chaves no repositório

manifesto_path = f"{ambiente.RAIZ_LANDING}/_manifesto_coleta.json"
if os.path.exists(manifesto_path) and not FORCAR_COLETA:
    print("Manifesto encontrado — arquivos já coletados. Pulando o download.")
else:
    try:
        coleta.coletar_tudo(ambiente.RAIZ_LANDING, NVD_API_KEY)
    except Exception as erro:
        raise RuntimeError(
            "Falha no download a partir desta computação. Rode scripts/coleta.py localmente e "
            "envie a pasta dados/landing para o Volume (instruções no topo do notebook)."
        ) from erro

# COMMAND ----------

# MAGIC %md
# MAGIC ### Manifesto da coleta
# MAGIC Registrado também como tabela `ciber_bronze.manifesto_coleta`, para que a linhagem
# MAGIC possa ser consultada por SQL.

# COMMAND ----------

with open(manifesto_path, encoding="utf-8") as f:
    manifesto = json.load(f)

import pandas as pd
df_manifesto = pd.DataFrame(manifesto["arquivos"])
df_manifesto["registros"] = df_manifesto["registros"].astype("Int64")
print(f"Coleta concluída em {manifesto['coleta_concluida_utc']} (UTC) — "
      f"{manifesto['total_arquivos']} arquivos, {manifesto['total_bytes'] / 1e6:.1f} MB")

resumo = (df_manifesto.groupby("fonte")
          .agg(arquivos=("arquivo", "count"), megabytes=("bytes", lambda b: round(b.sum() / 1e6, 1)),
               registros=("registros", "sum"), coletado_em_utc=("coletado_em_utc", "max"))
          .reset_index())
print(resumo.to_string(index=False))

from pyspark.sql import types as T
from pyspark.sql import functions as F

esquema = T.StructType([
    T.StructField("fonte", T.StringType()), T.StructField("pasta", T.StringType()),
    T.StructField("arquivo", T.StringType()), T.StructField("url", T.StringType()),
    T.StructField("coletado_em_utc", T.StringType()), T.StructField("bytes", T.LongType()),
    T.StructField("sha256", T.StringType()), T.StructField("registros", T.LongType()),
    T.StructField("formato", T.StringType()), T.StructField("observacao", T.StringType()),
])
linhas = [tuple(a.get(c.name) for c in esquema.fields) for a in manifesto["arquivos"]]
sdf = (spark.createDataFrame(linhas, esquema)
       .withColumn("coletado_em_utc", F.to_timestamp("coletado_em_utc")))
ambiente.salvar(sdf, "bronze", "manifesto_coleta",
                "Manifesto da coleta: URL, data UTC, tamanho e SHA-256 de cada arquivo bruto")
