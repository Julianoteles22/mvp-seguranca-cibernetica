# Databricks notebook source
# MAGIC %md
# MAGIC # 02 · Camada Bronze — ingestão dos arquivos brutos
# MAGIC
# MAGIC Carrega os arquivos do Volume `landing` em tabelas Delta **preservando a estrutura original**
# MAGIC (inclusive os campos aninhados do NVD). Nenhuma regra de negócio é aplicada aqui; apenas:
# MAGIC
# MAGIC * o JSON de cada fonte é "desempacotado" em uma linha por registro (`explode`);
# MAGIC * são acrescentadas colunas técnicas de linhagem: `_arquivo_origem` e `_ingerido_em`;
# MAGIC * no CSV da MITRE, os **nomes** das colunas são normalizados (espaços e hífens não são aceitos
# MAGIC   pelo Delta) — o conteúdo não é alterado.
# MAGIC
# MAGIC | Tabela | Origem | Grão |
# MAGIC |---|---|---|
# MAGIC | `ciber_bronze.kev_vulnerabilidades` | `landing/kev/*.json` | 1 linha por entrada do catálogo KEV |
# MAGIC | `ciber_bronze.nvd_cve` | `landing/nvd/kev/*.json.gz` + `landing/nvd/pub2024/*.json.gz` | 1 linha por CVE **por escopo de coleta** (uma CVE do KEV publicada em 2024 aparece duas vezes) |
# MAGIC | `ciber_bronze.epss_scores` | `landing/epss/*.csv.gz` | 1 linha por CVE por snapshot |
# MAGIC | `ciber_bronze.cwe_catalogo` | `landing/cwe/cwe_1000.csv` | 1 linha por fraqueza CWE |

# COMMAND ----------

import os
import re
import sys
import gzip

sys.path.insert(0, os.path.abspath(".."))
from scripts import ambiente
from pyspark.sql import functions as F

spark = ambiente.obter_spark()

def com_linhagem(df):
    return (df.withColumn("_arquivo_origem", F.col("_metadata.file_name"))
              .withColumn("_ingerido_em", F.current_timestamp()))

# COMMAND ----------

# MAGIC %md
# MAGIC ### CISA KEV

# COMMAND ----------

kev_bruto = spark.read.option("multiLine", True).json(ambiente.arquivos("kev", ".json"))
kev = (com_linhagem(kev_bruto.select("*", "_metadata"))
       .select("catalogVersion", "dateReleased", F.explode("vulnerabilities").alias("v"),
               "_arquivo_origem", "_ingerido_em")
       .select("catalogVersion", "dateReleased", "v.*", "_arquivo_origem", "_ingerido_em"))
ambiente.salvar(kev, "bronze", "kev_vulnerabilidades",
                "CISA KEV como publicado (JSON achatado em 1 linha por vulnerabilidade)")

# COMMAND ----------

# MAGIC %md
# MAGIC ### NVD — API CVE 2.0
# MAGIC Os dois escopos de coleta são lidos **na mesma leitura**, para que o Spark infira um único
# MAGIC esquema para os campos aninhados (métricas CVSS de versões diferentes, fraquezas, referências).

# COMMAND ----------

nvd_bruto = (spark.read.option("multiLine", True)
             .json(ambiente.arquivos("nvd/kev", ".json.gz") + ambiente.arquivos("nvd/pub2024", ".json.gz"))
             .select("*", "_metadata"))
nvd = (com_linhagem(nvd_bruto)
       .withColumn("escopo_coleta",
                   F.when(F.col("_metadata.file_path").contains("/nvd/kev/"), F.lit("kev"))
                    .otherwise(F.lit("pub2024")))
       .select(F.explode("vulnerabilities").alias("v"), "escopo_coleta", "_arquivo_origem", "_ingerido_em")
       .select("v.cve.*", "escopo_coleta", "_arquivo_origem", "_ingerido_em"))
ambiente.salvar(nvd, "bronze", "nvd_cve",
                "Registros de CVE da API do NVD, estrutura aninhada original")

# COMMAND ----------

# MAGIC %md
# MAGIC ### FIRST EPSS
# MAGIC A primeira linha de cada arquivo é um comentário com a versão do modelo e a data de referência
# MAGIC (`#model_version:...,score_date:...`). Ela é lida à parte e vira coluna.

# COMMAND ----------

def metadados_epss(caminho):
    with gzip.open(caminho, "rt", encoding="utf-8") as f:
        linha = f.readline().strip().lstrip("#")
    return dict(p.split(":", 1) for p in linha.split(","))

partes = []
for caminho in ambiente.arquivos("epss", ".csv.gz"):
    nome = os.path.basename(caminho)
    meta = metadados_epss(caminho)
    df = (spark.read.option("header", True).option("comment", "#").csv(caminho)
          .select("*", "_metadata")
          .withColumn("model_version", F.lit(meta.get("model_version")))
          .withColumn("score_date", F.lit(meta.get("score_date")))
          .withColumn("snapshot", F.lit("atual" if "atual" in nome else "corte")))
    partes.append(com_linhagem(df).drop("_metadata"))

epss = partes[0]
for p in partes[1:]:
    epss = epss.unionByName(p)
ambiente.salvar(epss, "bronze", "epss_scores",
                "Scores EPSS como publicados (texto), com versão do modelo e data de referência")

# COMMAND ----------

# MAGIC %md
# MAGIC ### MITRE CWE

# COMMAND ----------

cwe_bruto = (spark.read.option("header", True).option("multiLine", True)
             .option("escape", '"').csv(ambiente.arquivos("cwe", ".csv"))
             .select("*", "_metadata"))

def normalizar_nome(c):
    return re.sub(r"[^0-9a-z]+", "_", c.lower()).strip("_")

colunas = [c for c in cwe_bruto.columns if c != "_metadata" and not re.fullmatch(r"_c\d+", c)]
cwe = com_linhagem(cwe_bruto).select(
    *[F.col(f"`{c}`").alias(normalizar_nome(c)) for c in colunas], "_arquivo_origem", "_ingerido_em")
ambiente.salvar(cwe, "bronze", "cwe_catalogo",
                "Catálogo CWE (visão 1000) da MITRE; nomes de coluna normalizados, conteúdo original")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Conferência: volume ingerido × manifesto da coleta

# COMMAND ----------

conferencia = ambiente.sql("""
    SELECT 'CISA KEV' AS fonte, COUNT(*) AS linhas_bronze FROM {bronze.kev_vulnerabilidades}
    UNION ALL SELECT 'NVD API 2.0', COUNT(*) FROM {bronze.nvd_cve}
    UNION ALL SELECT 'FIRST EPSS', COUNT(*) FROM {bronze.epss_scores}
    UNION ALL SELECT 'MITRE CWE', COUNT(*) FROM {bronze.cwe_catalogo}
""")
manifesto = ambiente.sql("""
    SELECT fonte, SUM(registros) AS registros_manifesto FROM {bronze.manifesto_coleta} GROUP BY fonte
""")
ambiente.mostrar(conferencia.join(manifesto, "fonte", "left").orderBy("fonte"))
