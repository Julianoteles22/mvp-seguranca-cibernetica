# Databricks notebook source
# MAGIC %md
# MAGIC # 04 · Camada Gold — modelo dimensional (esquema estrela)
# MAGIC
# MAGIC Integra as quatro fontes em um **esquema estrela** com uma tabela fato no grão
# MAGIC *uma linha por CVE* e quatro dimensões.
# MAGIC
# MAGIC ```
# MAGIC                       dim_data (papéis: publicação, inclusão no KEV, prazo)
# MAGIC                                         │
# MAGIC   dim_produto ── fato_vulnerabilidade ── dim_severidade
# MAGIC                                         │
# MAGIC                                      dim_cwe
# MAGIC ```
# MAGIC
# MAGIC **Regras de integração (continuação das regras R1–R10 da Silver)**
# MAGIC
# MAGIC | # | Regra |
# MAGIC |---|---|
# MAGIC | R11 | CVEs com status `Rejected` no NVD (anuladas pelo emissor) saem da fato, exceto se estiverem no KEV |
# MAGIC | R12 | NVD e KEV são unidos por `cve_id` com *full outer join*, para que nenhuma entrada do KEV se perca mesmo se ausente no NVD |
# MAGIC | R13 | **CWE final**: CWE específica do NVD → primeira CWE declarada pela CISA no KEV → código especial do NVD (`NVD-CWE-noinfo`/`Other`) |
# MAGIC | R14 | Chaves substitutas `-1` representam "Não informado" em todas as dimensões (a fato nunca tem chave nula) |
# MAGIC | R15 | **Avaliação prospectiva (P3)**: população = CVEs publicadas em 2024, com CVSS e EPSS de 01/01/2025, que ainda **não** estavam no KEV nessa data; desfecho = entrar no KEV depois de 01/01/2025 |

# COMMAND ----------

import os
import sys

sys.path.insert(0, os.path.abspath(".."))
from scripts import ambiente
from pyspark.sql import functions as F, Window

spark = ambiente.obter_spark()
DATA_CORTE = "2025-01-01"
ANO_COORTE = 2024

kev = ambiente.tabela("silver", "kev")
nvd = ambiente.tabela("silver", "nvd_cve")
epss = ambiente.tabela("silver", "epss")
cwe = ambiente.tabela("silver", "cwe")

def com_chave(df, nome_chave, ordem):
    return df.withColumn(nome_chave, F.row_number().over(Window.orderBy(*ordem)))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Base integrada NVD + KEV + EPSS (antes das chaves substitutas)

# COMMAND ----------

# R11 — CVEs rejeitadas saem, exceto as que constam do KEV
rejeitadas_no_kev = nvd.filter(F.col("status_nvd") == "Rejected").join(kev.select("cve_id"), "cve_id", "inner")
nvd_valido = nvd.filter(F.col("status_nvd") != "Rejected").unionByName(rejeitadas_no_kev)

base = (nvd_valido.join(kev, "cve_id", "full_outer")                              # R12
        .withColumn("cwe_final", F.coalesce(                                        # R13
            F.when(~F.col("cwe_principal").startswith("NVD-CWE-"), F.col("cwe_principal")),
            F.expr("try_element_at(cwes_kev, 1)"),
            F.col("cwe_principal"))))

corte = epss.filter(F.col("snapshot") == "corte").select(
    "cve_id", F.col("epss").alias("epss_corte"), F.col("percentil").alias("percentil_epss_corte"))
atual = epss.filter(F.col("snapshot") == "atual").select(
    "cve_id", F.col("epss").alias("epss_atual"), F.col("percentil").alias("percentil_epss_atual"))
base = base.join(corte, "cve_id", "left").join(atual, "cve_id", "left")
print(f"CVEs na base integrada: {base.count():,}".replace(",", "."))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Dimensões

# COMMAND ----------

# dim_severidade — domínio fixo (limites do CVSS v3, regra R5)
dim_severidade = spark.createDataFrame(
    [(-1, "Sem pontuação", None, None, 0), (0, "Nenhuma", 0.0, 0.0, 1), (1, "Baixa", 0.1, 3.9, 2),
     (2, "Média", 4.0, 6.9, 3), (3, "Alta", 7.0, 8.9, 4), (4, "Crítica", 9.0, 10.0, 5)],
    "sk_severidade int, faixa string, score_minimo double, score_maximo double, ordem int")
ambiente.salvar(dim_severidade, "gold", "dim_severidade", "Faixas de severidade CVSS (limites do CVSS v3)")

# dim_produto — pares fornecedor/produto do KEV (o NVD não traz fornecedor sem interpretar CPEs)
dim_produto = com_chave(kev.select("fornecedor", "produto").distinct(), "sk_produto",
                        ["fornecedor", "produto"])
dim_produto = dim_produto.select("sk_produto", "fornecedor", "produto").unionByName(
    spark.createDataFrame([(-1, "Não informado", "Não informado")],
                          "sk_produto int, fornecedor string, produto string"))
ambiente.salvar(dim_produto, "gold", "dim_produto", "Fornecedores e produtos do catálogo KEV")

# dim_cwe — domínio da MITRE + IDs referenciados que não constam da visão 1000
referenciadas = base.select(F.col("cwe_final").alias("cwe_id")).where("cwe_id IS NOT NULL").distinct()
fora_da_visao = (referenciadas.join(cwe, "cwe_id", "left_anti")
                 .withColumn("nome", F.lit("Não consta na visão CWE-1000 (categoria ou ID descontinuado)"))
                 .withColumn("abstracao", F.lit("Fora da visão 1000"))
                 .withColumn("status", F.lit(None).cast("string"))
                 .withColumn("descricao", F.lit(None).cast("string")))
dim_cwe = com_chave(cwe.unionByName(fora_da_visao), "sk_cwe", ["cwe_id"]) \
    .select("sk_cwe", "cwe_id", "nome", "abstracao", "status")
dim_cwe = dim_cwe.unionByName(spark.createDataFrame(
    [(-1, "Não informado", "Nenhuma CWE informada", "Não informado", None)],
    "sk_cwe int, cwe_id string, nome string, abstracao string, status string"))
ambiente.salvar(dim_cwe, "gold", "dim_cwe", "Classes de fraqueza (CWE) com nome e nível de abstração")

# dim_data — calendário cobrindo todas as datas usadas pela fato
limites = base.select(F.least(F.min("data_publicacao"), F.min("data_inclusao_kev")).alias("ini"),
                      F.greatest(F.max("data_publicacao"), F.max("data_prazo_remediacao")).alias("fim")).first()
MESES = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto",
         "setembro", "outubro", "novembro", "dezembro"]
DIAS = ["domingo", "segunda", "terça", "quarta", "quinta", "sexta", "sábado"]
calendario = spark.sql(f"SELECT explode(sequence(DATE'{limites['ini']}', DATE'{limites['fim']}', "
                       "INTERVAL 1 DAY)) AS data")
dim_data = calendario.select(
    F.date_format("data", "yyyyMMdd").cast("int").alias("sk_data"), "data",
    F.year("data").alias("ano"), F.quarter("data").alias("trimestre"), F.month("data").alias("mes"),
    F.element_at(F.array(*[F.lit(m) for m in MESES]), F.month("data")).alias("nome_mes"),
    F.element_at(F.array(*[F.lit(d) for d in DIAS]), F.dayofweek("data")).alias("dia_semana"),
    F.dayofweek("data").isin(1, 7).alias("fim_de_semana"))
dim_data = dim_data.unionByName(spark.createDataFrame(
    [(-1, None, None, None, None, "Não informada", "Não informada", None)],
    "sk_data int, data date, ano int, trimestre int, mes int, nome_mes string, "
    "dia_semana string, fim_de_semana boolean"))
ambiente.salvar(dim_data, "gold", "dim_data",
                f"Calendário de {limites['ini']} a {limites['fim']} (papéis: publicação, inclusão no KEV, prazo)")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Tabela fato — `fato_vulnerabilidade` (grão: 1 linha por CVE)

# COMMAND ----------

def sk_data(col):
    return F.coalesce(F.date_format(col, "yyyyMMdd").cast("int"), F.lit(-1))

em_kev = F.col("data_inclusao_kev").isNotNull()
fato = (base
        .join(dim_produto, ["fornecedor", "produto"], "left")
        .join(dim_cwe.select("sk_cwe", F.col("cwe_id").alias("cwe_final")), "cwe_final", "left")
        .join(dim_severidade.select("sk_severidade", F.col("faixa").alias("faixa_severidade")),
              "faixa_severidade", "left")
        .select(
            "cve_id",
            sk_data("data_publicacao").alias("sk_data_publicacao"),
            sk_data("data_inclusao_kev").alias("sk_data_inclusao_kev"),
            sk_data("data_prazo_remediacao").alias("sk_data_prazo_kev"),
            F.coalesce("sk_produto", F.lit(-1)).alias("sk_produto"),                     # R14
            F.coalesce("sk_cwe", F.lit(-1)).alias("sk_cwe"),
            F.coalesce("sk_severidade", F.lit(-1)).alias("sk_severidade"),
            "cvss_score", "cvss_versao", "cvss_origem", "status_nvd",
            em_kev.alias("em_kev"),
            F.coalesce("uso_ransomware", F.lit(False)).alias("uso_ransomware"),
            F.coalesce("triagem_forense", F.lit(False)).alias("triagem_forense"),
            (F.year("data_publicacao") == ANO_COORTE).alias("publicada_no_ano_coorte"),
            F.datediff("data_inclusao_kev", "data_publicacao").alias("dias_publicacao_ate_kev"),
            "prazo_remediacao_dias",
            "epss_corte", "percentil_epss_corte", "epss_atual", "percentil_epss_atual",
            (em_kev & (F.col("data_inclusao_kev") > F.lit(DATA_CORTE))).alias("explorada_apos_corte"),
            ((F.year("data_publicacao") == ANO_COORTE) & F.col("cvss_score").isNotNull()     # R15
             & F.col("epss_corte").isNotNull()
             & ~(em_kev & (F.col("data_inclusao_kev") <= F.lit(DATA_CORTE)))).alias("na_populacao_p3"))
        .withColumn("publicada_no_ano_coorte", F.coalesce("publicada_no_ano_coorte", F.lit(False)))
        .withColumn("na_populacao_p3", F.coalesce("na_populacao_p3", F.lit(False))))

ambiente.salvar(fato, "gold", "fato_vulnerabilidade",
                "Fato no grão de CVE: severidade CVSS, EPSS, inclusão no KEV e prazos (R11-R15)")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Integridade referencial do esquema estrela
# MAGIC Toda chave da fato precisa existir na dimensão correspondente (resultado esperado: zero órfãs).

# COMMAND ----------

integridade = ambiente.sql("""
    SELECT 'sk_produto' AS chave, COUNT(*) AS orfas FROM {gold.fato_vulnerabilidade} f
      LEFT ANTI JOIN {gold.dim_produto} d ON f.sk_produto = d.sk_produto
    UNION ALL SELECT 'sk_cwe', COUNT(*) FROM {gold.fato_vulnerabilidade} f
      LEFT ANTI JOIN {gold.dim_cwe} d ON f.sk_cwe = d.sk_cwe
    UNION ALL SELECT 'sk_severidade', COUNT(*) FROM {gold.fato_vulnerabilidade} f
      LEFT ANTI JOIN {gold.dim_severidade} d ON f.sk_severidade = d.sk_severidade
    UNION ALL SELECT 'sk_data_publicacao', COUNT(*) FROM {gold.fato_vulnerabilidade} f
      LEFT ANTI JOIN {gold.dim_data} d ON f.sk_data_publicacao = d.sk_data
    UNION ALL SELECT 'sk_data_inclusao_kev', COUNT(*) FROM {gold.fato_vulnerabilidade} f
      LEFT ANTI JOIN {gold.dim_data} d ON f.sk_data_inclusao_kev = d.sk_data
    UNION ALL SELECT 'sk_data_prazo_kev', COUNT(*) FROM {gold.fato_vulnerabilidade} f
      LEFT ANTI JOIN {gold.dim_data} d ON f.sk_data_prazo_kev = d.sk_data
""")
ambiente.mostrar(integridade)
assert integridade.agg(F.sum("orfas")).first()[0] == 0, "Há chaves órfãs na fato!"
duplicadas = ambiente.sql("SELECT COUNT(*) - COUNT(DISTINCT cve_id) FROM {gold.fato_vulnerabilidade}").first()[0]
assert duplicadas == 0, "O grão da fato (1 linha por CVE) foi violado!"
print("Integridade referencial e grão verificados.")
