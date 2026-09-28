# Databricks notebook source
# MAGIC %md
# MAGIC # 03 · Camada Silver — limpeza, tipagem e padronização
# MAGIC
# MAGIC Transforma as tabelas Bronze em tabelas **planas, tipadas e sem duplicatas**, uma por conceito
# MAGIC (modelo *flat por conceito*, como em um Data Lake). Todas as regras de negócio aplicadas estão
# MAGIC listadas abaixo e numeradas — elas são referenciadas no Catálogo de Dados (linhagem).
# MAGIC
# MAGIC | # | Regra | Tabela |
# MAGIC |---|---|---|
# MAGIC | R1 | Identificadores de CVE em maiúsculas e sem espaços (`CVE-AAAA-NNNN…`) | todas |
# MAGIC | R2 | Espaços nas pontas de fornecedor e produto são removidos (6 fornecedores e 13 produtos no KEV vinham com espaço final, o que criaria "fornecedores" duplicados) | `kev` |
# MAGIC | R3 | Datas em texto convertidas para `DATE` (UTC); `knownRansomwareCampaignUse = 'Known'` → `uso_ransomware = true` | `kev` |
# MAGIC | R4 | **Seleção do CVSS**: v3.1 → v3.0 → v4.0 → v2.0; em cada versão, a nota do NVD (*Primary*) tem precedência sobre a do CNA (*Secondary*). A versão e a origem escolhidas ficam registradas | `nvd_cve` |
# MAGIC | R5 | **Faixa de severidade** calculada sobre a nota, com os limites do CVSS v3 (Baixa < 4, Média < 7, Alta < 9, Crítica ≥ 9), para comparar versões diferentes na mesma escala | `nvd_cve` |
# MAGIC | R6 | **CWE principal**: fraqueza *Primary* atribuída pelo NVD → *Primary* de qualquer fonte → primeira informada | `nvd_cve` |
# MAGIC | R7 | Uma CVE coletada nos dois escopos (KEV e publicadas em 2024) vira **uma** linha, com as flags `no_escopo_kev` e `no_escopo_2024` | `nvd_cve` |
# MAGIC | R8 | EPSS e percentil convertidos para `DOUBLE`; linhas fora de [0, 1] ou sem CVE válida são descartadas (e contadas) | `epss` |
# MAGIC | R9 | IDs da MITRE recebem o prefixo `CWE-`; os códigos especiais do NVD (`NVD-CWE-noinfo`, `NVD-CWE-Other`) são incluídos como membros do domínio | `cwe` |
# MAGIC | R10 | Deduplicação por chave natural, mantendo o registro mais recente | todas |

# COMMAND ----------

import os
import sys

sys.path.insert(0, os.path.abspath(".."))
from scripts import ambiente
from pyspark.sql import functions as F, Window

spark = ambiente.obter_spark()
PADRAO_CVE = r"^CVE-[0-9]{4}-[0-9]{4,}$"

def cve_padronizada(col):                                   # R1
    return F.upper(F.trim(F.col(col)))

def deduplicar(df, chave, ordem):                           # R10
    janela = Window.partitionBy(*chave).orderBy(*ordem)
    return df.withColumn("_rn", F.row_number().over(janela)).filter("_rn = 1").drop("_rn")

# COMMAND ----------

# MAGIC %md
# MAGIC ### `silver.kev` — catálogo de vulnerabilidades exploradas

# COMMAND ----------

kev_b = ambiente.tabela("bronze", "kev_vulnerabilidades")
kev = (kev_b.select(
        cve_padronizada("cveID").alias("cve_id"),
        F.trim("vendorProject").alias("fornecedor"),                               # R2
        F.trim("product").alias("produto"),                                        # R2
        F.trim("vulnerabilityName").alias("nome_vulnerabilidade"),
        F.to_date("dateAdded").alias("data_inclusao_kev"),                         # R3
        F.to_date("dueDate").alias("data_prazo_remediacao"),                       # R3
        (F.col("knownRansomwareCampaignUse") == "Known").alias("uso_ransomware"),  # R3
        (F.col("forensicTriage") == "Yes").alias("triagem_forense"),
        F.col("cwes").alias("cwes_kev"),
        F.col("shortDescription").alias("descricao"),
        F.col("requiredAction").alias("acao_requerida"),
        F.col("catalogVersion").alias("versao_catalogo"))
       .withColumn("prazo_remediacao_dias",
                   F.datediff("data_prazo_remediacao", "data_inclusao_kev")))
n_antes = kev.count()
kev = deduplicar(kev, ["cve_id"], [F.col("data_inclusao_kev").desc()])
print(f"Duplicatas removidas: {n_antes - kev.count()}")
ambiente.salvar(kev, "silver", "kev", "KEV tipado e padronizado (regras R1-R3, R10)")

# COMMAND ----------

# MAGIC %md
# MAGIC ### `silver.nvd_cve` — atributos da CVE no NVD
# MAGIC As expressões de CVSS são montadas a partir das versões **efetivamente presentes** no esquema
# MAGIC inferido, para que o notebook não quebre se uma versão não aparecer em uma coleta futura.

# COMMAND ----------

nvd_b = ambiente.tabela("bronze", "nvd_cve")
metricas_presentes = {f.name for f in nvd_b.schema["metrics"].dataType.fields}
PREFERENCIA = [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
               ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")]               # R4

candidatos = []
for campo, versao in PREFERENCIA:
    if campo not in metricas_presentes:
        continue
    for tipo in ("Primary", "Secondary"):
        m = f"try_element_at(filter(metrics.{campo}, x -> x.type = '{tipo}'), 1)"
        candidatos.append({"score": f"({m}).cvssData.baseScore", "vetor": f"({m}).cvssData.vectorString",
                           "versao": versao, "origem": "NVD" if tipo == "Primary" else "CNA"})
print("Candidatos de CVSS, em ordem de preferência:",
      [f"v{c['versao']}/{c['origem']}" for c in candidatos])

expr_score = "coalesce(" + ", ".join(f"CAST({c['score']} AS DOUBLE)" for c in candidatos) + ")"
expr_vetor = "coalesce(" + ", ".join(c["vetor"] for c in candidatos) + ")"
expr_versao = "CASE " + " ".join(f"WHEN {c['score']} IS NOT NULL THEN '{c['versao']}'" for c in candidatos) + " END"
expr_origem = "CASE " + " ".join(f"WHEN {c['score']} IS NOT NULL THEN '{c['origem']}'" for c in candidatos) + " END"

# R6 — CWE principal, em ordem de preferência
FRAQUEZA_PRIMARIA_NVD = "try_element_at(filter(weaknesses, w -> w.source = 'nvd@nist.gov' AND w.type = 'Primary'), 1)"
FRAQUEZA_PRIMARIA = "try_element_at(filter(weaknesses, w -> w.type = 'Primary'), 1)"
PRIMEIRA_FRAQUEZA = "try_element_at(weaknesses, 1)"

def codigo_cwe(fraqueza):
    return f"try_element_at(filter(({fraqueza}).description, d -> d.lang = 'en'), 1).value"

expr_cwe = "coalesce(" + ", ".join(codigo_cwe(f) for f in
                                   (FRAQUEZA_PRIMARIA_NVD, FRAQUEZA_PRIMARIA, PRIMEIRA_FRAQUEZA)) + ")"

nvd = (nvd_b
       .withColumn("cvss_score", F.expr(expr_score))
       .select(
           cve_padronizada("id").alias("cve_id"),
           F.to_date(F.substring("published", 1, 10)).alias("data_publicacao"),
           F.to_timestamp("lastModified").alias("ultima_modificacao_nvd"),
           F.col("vulnStatus").alias("status_nvd"),
           F.col("sourceIdentifier").alias("fonte_cna"),
           "cvss_score",
           F.expr(expr_versao).alias("cvss_versao"),
           F.expr(expr_origem).alias("cvss_origem"),
           F.expr(expr_vetor).alias("cvss_vetor"),
           F.when(F.col("cvss_score").isNull(), "Sem pontuação")                   # R5
            .when(F.col("cvss_score") == 0, "Nenhuma")
            .when(F.col("cvss_score") < 4, "Baixa")
            .when(F.col("cvss_score") < 7, "Média")
            .when(F.col("cvss_score") < 9, "Alta")
            .otherwise("Crítica").alias("faixa_severidade"),
           F.expr(expr_cwe).alias("cwe_principal"),
           F.expr("array_distinct(flatten(transform(weaknesses, w -> "
                  "transform(w.description, d -> d.value))))").alias("cwes_nvd"),
           F.expr("try_element_at(filter(descriptions, d -> d.lang = 'en'), 1).value").alias("descricao_en"),
           F.to_date("cisaExploitAdd").alias("data_inclusao_kev_nvd"),
           "escopo_coleta"))

flags = nvd.groupBy("cve_id").agg(                                                  # R7
    F.max(F.col("escopo_coleta") == "kev").alias("no_escopo_kev"),
    F.max(F.col("escopo_coleta") == "pub2024").alias("no_escopo_2024"))
n_antes = nvd.count()
nvd = (deduplicar(nvd, ["cve_id"], [F.col("ultima_modificacao_nvd").desc(), "escopo_coleta"])
       .drop("escopo_coleta").join(flags, "cve_id"))
print(f"Registros bronze: {n_antes:,} → CVEs únicas: {nvd.count():,}".replace(",", "."))
ambiente.salvar(nvd, "silver", "nvd_cve", "CVE do NVD com CVSS, severidade e CWE principal (R1, R4-R7, R10)")

# COMMAND ----------

# MAGIC %md
# MAGIC ### `silver.epss` — probabilidade de exploração (dois snapshots)

# COMMAND ----------

epss_b = ambiente.tabela("bronze", "epss_scores")
epss_tipado = epss_b.select(
    cve_padronizada("cve").alias("cve_id"),
    F.expr("try_cast(epss AS DOUBLE)").alias("epss"),                            # R8
    F.expr("try_cast(percentile AS DOUBLE)").alias("percentil"),
    F.to_date(F.substring("score_date", 1, 10)).alias("data_referencia"),
    F.col("model_version").alias("versao_modelo"),
    "snapshot")
validas = (F.col("cve_id").rlike(PADRAO_CVE) & F.col("epss").between(0, 1)
           & F.col("percentil").between(0, 1))
descartadas = epss_tipado.filter(~validas | validas.isNull()).count()
epss = deduplicar(epss_tipado.filter(validas), ["cve_id", "snapshot"], [F.col("epss").desc()])
print(f"Linhas descartadas por R8: {descartadas}")
ambiente.salvar(epss, "silver", "epss", "EPSS tipado, snapshots 'atual' e 'corte' (R1, R8, R10)")

# COMMAND ----------

# MAGIC %md
# MAGIC ### `silver.cwe` — domínio de fraquezas

# COMMAND ----------

cwe_b = ambiente.tabela("bronze", "cwe_catalogo")
cwe = cwe_b.select(
    F.concat(F.lit("CWE-"), F.trim("cwe_id")).alias("cwe_id"),                   # R9
    F.trim("name").alias("nome"),
    F.col("weakness_abstraction").alias("abstracao"),
    F.col("status").alias("status"),
    F.col("description").alias("descricao"))
especiais = spark.createDataFrame(
    [("NVD-CWE-noinfo", "Informação insuficiente para classificar (código do NVD)", "Especial NVD", None, None),
     ("NVD-CWE-Other", "Outra fraqueza, não listada no CWE (código do NVD)", "Especial NVD", None, None)],
    "cwe_id string, nome string, abstracao string, status string, descricao string")
cwe = deduplicar(cwe.unionByName(especiais), ["cwe_id"], ["nome"])
ambiente.salvar(cwe, "silver", "cwe", "Domínio CWE (visão 1000 da MITRE + códigos especiais do NVD) (R9)")
