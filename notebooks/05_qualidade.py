# Databricks notebook source
# MAGIC %md
# MAGIC # 05 · Análise de qualidade dos dados
# MAGIC
# MAGIC Duas visões complementares, ambas persistidas como tabelas para consulta:
# MAGIC
# MAGIC 1. **`gold.qualidade_atributos`** — perfil de **cada atributo** das tabelas Silver: nulos,
# MAGIC    valores distintos, mínimo, máximo e **violações do domínio declarado** no Catálogo de Dados.
# MAGIC 2. **`gold.qualidade_regras`** — verificações que envolvem mais de um atributo ou mais de uma
# MAGIC    fonte, organizadas pelas dimensões clássicas de qualidade: completude, unicidade,
# MAGIC    consistência, conformidade, acurácia e atualidade.
# MAGIC
# MAGIC Cada verificação informa **se o problema afeta alguma pergunta de negócio** e **como foi tratado**.

# COMMAND ----------

import os
import sys
import datetime as dt

sys.path.insert(0, os.path.abspath(".."))
from scripts import ambiente
from pyspark.sql import functions as F, types as T

spark = ambiente.obter_spark()
PADRAO_CVE = r"^CVE-[0-9]{4}-[0-9]{4,}$"
PADRAO_CWE = r"^(CWE-[0-9]+|NVD-CWE-noinfo|NVD-CWE-Other)$"
DATA_COLETA = ambiente.sql("SELECT CAST(MAX(coletado_em_utc) AS DATE) FROM {bronze.manifesto_coleta}").first()[0]
print("Data da coleta (limite superior para datas):", DATA_COLETA)

# COMMAND ----------

# MAGIC %md
# MAGIC ### 1. Perfil por atributo, com domínio declarado
# MAGIC O domínio de cada atributo é declarado aqui como uma expressão SQL que deve ser **verdadeira**
# MAGIC para todo valor não nulo. A mesma declaração aparece no Catálogo de Dados.

# COMMAND ----------

DOMINIOS = {
    "kev": {
        "cve_id": ("formato CVE-AAAA-NNNN", f"cve_id RLIKE '{PADRAO_CVE}'"),
        "fornecedor": ("texto sem espaços nas pontas", "fornecedor = trim(fornecedor) AND fornecedor <> ''"),
        "produto": ("texto sem espaços nas pontas", "produto = trim(produto) AND produto <> ''"),
        "nome_vulnerabilidade": ("texto não vazio", "length(nome_vulnerabilidade) > 0"),
        "data_inclusao_kev": ("entre 2021-11-03 (lançamento do KEV) e a data da coleta",
                              f"data_inclusao_kev BETWEEN DATE'2021-11-03' AND DATE'{DATA_COLETA}'"),
        "data_prazo_remediacao": ("a partir de 2021-11-03", "data_prazo_remediacao >= DATE'2021-11-03'"),
        "uso_ransomware": ("booleano", "uso_ransomware IN (true, false)"),
        "triagem_forense": ("booleano", "triagem_forense IN (true, false)"),
        "cwes_kev": ("lista de códigos CWE-N", f"forall(cwes_kev, c -> c RLIKE '{PADRAO_CWE}')"),
        "descricao": ("texto não vazio", "length(descricao) > 0"),
        "acao_requerida": ("texto não vazio", "length(acao_requerida) > 0"),
        "versao_catalogo": ("formato AAAA.MM.DD", r"versao_catalogo RLIKE '^[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}$'"),
        "prazo_remediacao_dias": ("0 a 365 dias", "prazo_remediacao_dias BETWEEN 0 AND 365"),
    },
    "nvd_cve": {
        "cve_id": ("formato CVE-AAAA-NNNN", f"cve_id RLIKE '{PADRAO_CVE}'"),
        "data_publicacao": ("entre 1988-01-01 e a data da coleta",
                            f"data_publicacao BETWEEN DATE'1988-01-01' AND DATE'{DATA_COLETA}'"),
        "ultima_modificacao_nvd": ("até a data da coleta",
                                   f"CAST(ultima_modificacao_nvd AS DATE) <= DATE'{DATA_COLETA}'"),
        "status_nvd": ("Received, Awaiting Analysis, Undergoing Analysis, Analyzed, Modified, Deferred, Rejected",
                       "status_nvd IN ('Received','Awaiting Analysis','Undergoing Analysis','Analyzed',"
                       "'Modified','Deferred','Rejected')"),
        "fonte_cna": ("texto não vazio", "length(fonte_cna) > 0"),
        "cvss_score": ("0,0 a 10,0", "cvss_score BETWEEN 0 AND 10"),
        "cvss_versao": ("2.0, 3.0, 3.1, 4.0", "cvss_versao IN ('2.0','3.0','3.1','4.0')"),
        "cvss_origem": ("NVD ou CNA", "cvss_origem IN ('NVD','CNA')"),
        "cvss_vetor": ("vetor CVSS", "cvss_vetor RLIKE '^(CVSS:[34]\\\\.[0-9]/)?AV:'"),
        "faixa_severidade": ("Sem pontuação, Nenhuma, Baixa, Média, Alta, Crítica",
                             "faixa_severidade IN ('Sem pontuação','Nenhuma','Baixa','Média','Alta','Crítica')"),
        "cwe_principal": ("CWE-N ou código especial do NVD", f"cwe_principal RLIKE '{PADRAO_CWE}'"),
        "cwes_nvd": ("lista de códigos CWE", f"forall(cwes_nvd, c -> c RLIKE '{PADRAO_CWE}')"),
        "descricao_en": ("texto não vazio", "length(descricao_en) > 0"),
        "data_inclusao_kev_nvd": ("a partir de 2021-11-03", "data_inclusao_kev_nvd >= DATE'2021-11-03'"),
        "no_escopo_kev": ("booleano", "no_escopo_kev IN (true, false)"),
        "no_escopo_2024": ("booleano", "no_escopo_2024 IN (true, false)"),
    },
    "epss": {
        "cve_id": ("formato CVE-AAAA-NNNN", f"cve_id RLIKE '{PADRAO_CVE}'"),
        "epss": ("probabilidade 0 a 1", "epss BETWEEN 0 AND 1"),
        "percentil": ("0 a 1", "percentil BETWEEN 0 AND 1"),
        "data_referencia": ("2025-01-01 (corte) ou dia da coleta (atual)",
                            f"data_referencia BETWEEN DATE'2025-01-01' AND DATE'{DATA_COLETA}'"),
        "versao_modelo": ("formato vAAAA.MM.DD", r"versao_modelo RLIKE '^v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}$'"),
        "snapshot": ("atual ou corte", "snapshot IN ('atual','corte')"),
    },
    "cwe": {
        "cwe_id": ("CWE-N ou código especial do NVD", f"cwe_id RLIKE '{PADRAO_CWE}'"),
        "nome": ("texto não vazio", "length(nome) > 0"),
        "abstracao": ("Pillar, Class, Base, Variant, Compound, Especial NVD",
                      "abstracao IN ('Pillar','Class','Base','Variant','Compound','Especial NVD')"),
        "status": ("Stable, Draft, Incomplete, Deprecated, Obsolete, Usable",
                   "status IN ('Stable','Draft','Incomplete','Deprecated','Obsolete','Usable')"),
        "descricao": ("texto não vazio", "length(descricao) > 0"),
    },
}


def perfil(nome_tabela, dominios):
    df = ambiente.tabela("silver", nome_tabela)
    total = df.count()
    linhas = []
    for campo in df.schema.fields:
        c = campo.name
        eh_lista = isinstance(campo.dataType, T.ArrayType)
        ordenavel = isinstance(campo.dataType, (T.NumericType, T.DateType, T.TimestampType))
        descricao_regra, regra = dominios.get(c, ("—", None))
        aggs = [F.count(F.when(F.col(c).isNull(), 1)).alias("nulos"),
                F.countDistinct(F.col(c) if not eh_lista else F.to_json(c)).alias("distintos")]
        if eh_lista:
            aggs.append(F.count(F.when(F.size(c) == 0, 1)).alias("listas_vazias"))
        if ordenavel:
            aggs += [F.min(c).cast("string").alias("minimo"), F.max(c).cast("string").alias("maximo")]
        elif not eh_lista and isinstance(campo.dataType, T.StringType):
            aggs += [F.min(F.length(c)).cast("string").alias("minimo"),
                     F.max(F.length(c)).cast("string").alias("maximo")]
        if regra:
            aggs.append(F.count(F.when(F.col(c).isNotNull() & ~F.expr(regra), 1)).alias("violacoes"))
        r = df.agg(*aggs).first().asDict()
        linhas.append({
            "tabela": f"silver.{nome_tabela}", "atributo": c, "tipo": campo.dataType.simpleString(),
            "linhas": total, "nulos": r["nulos"], "pct_nulos": round(100 * r["nulos"] / total, 2) if total else 0.0,
            "distintos": r["distintos"], "listas_vazias": r.get("listas_vazias"),
            "minimo": r.get("minimo"), "maximo": r.get("maximo"),
            "min_max_refere_se_a": "valor" if ordenavel else ("comprimento do texto" if r.get("minimo") else None),
            "dominio_declarado": descricao_regra, "violacoes_dominio": r.get("violacoes"),
        })
    return linhas


registros = []
for tabela, dominios in DOMINIOS.items():
    registros += perfil(tabela, dominios)

esquema = ("tabela string, atributo string, tipo string, linhas long, nulos long, pct_nulos double, "
           "distintos long, listas_vazias long, minimo string, maximo string, min_max_refere_se_a string, "
           "dominio_declarado string, violacoes_dominio long")
qualidade_atributos = spark.createDataFrame(
    [tuple(r[c.split()[0]] for c in esquema.split(", ")) for r in registros], esquema)
ambiente.salvar(qualidade_atributos, "gold", "qualidade_atributos",
                "Perfil de qualidade de cada atributo das tabelas Silver")
ambiente.mostrar(qualidade_atributos.select("tabela", "atributo", "pct_nulos", "distintos", "minimo",
                                            "maximo", "violacoes_dominio"), n=60)

# COMMAND ----------

# MAGIC %md
# MAGIC ### 2. Verificações entre atributos e entre fontes

# COMMAND ----------

def valor(consulta):
    return ambiente.sql(consulta).first()[0]

checagens = []
def checar(dimensao, verificacao, consulta_numerador, consulta_denominador, impacto, tratamento):
    num = valor(consulta_numerador)
    den = valor(consulta_denominador) if consulta_denominador else None
    checagens.append((dimensao, verificacao, int(num), int(den) if den is not None else None,
                      round(100 * num / den, 2) if den else None, impacto, tratamento))

KEV = "{silver.kev}"; NVD = "{silver.nvd_cve}"; EPSS = "{silver.epss}"; FATO = "{gold.fato_vulnerabilidade}"

checar("Unicidade", "CVEs repetidas no KEV",
       f"SELECT COUNT(*) - COUNT(DISTINCT cve_id) FROM {KEV}", f"SELECT COUNT(*) FROM {KEV}",
       "Nenhum", "Deduplicação por cve_id (R10); nenhuma repetição encontrada")
checar("Unicidade", "Registros repetidos no NVD entre escopos de coleta (antes da R7)",
       "SELECT COUNT(*) - COUNT(DISTINCT id) FROM {bronze.nvd_cve}", "SELECT COUNT(*) FROM {bronze.nvd_cve}",
       "Dupla contagem de CVEs do KEV publicadas em 2024", "Consolidadas em uma linha com flags de escopo (R7)")
checar("Conformidade", "Fornecedores/produtos do KEV com espaço nas pontas (bronze)",
       "SELECT COUNT(*) FROM {bronze.kev_vulnerabilidades} WHERE vendorProject <> trim(vendorProject) "
       "OR product <> trim(product)", "SELECT COUNT(*) FROM {bronze.kev_vulnerabilidades}",
       "P1: o mesmo fornecedor seria contado como dois", "trim() na Silver (R2)")
checar("Consistência", "Prazo de remediação anterior à data de inclusão no KEV",
       f"SELECT COUNT(*) FROM {KEV} WHERE data_prazo_remediacao < data_inclusao_kev",
       f"SELECT COUNT(*) FROM {KEV}", "P2/prazos", "Nenhuma ocorrência")
checar("Consistência", "Data de inclusão no KEV diverge entre CISA e NVD (cisaExploitAdd)",
       f"SELECT COUNT(*) FROM {KEV} k JOIN {NVD} n USING (cve_id) "
       "WHERE n.data_inclusao_kev_nvd IS NULL OR n.data_inclusao_kev_nvd <> k.data_inclusao_kev",
       f"SELECT COUNT(*) FROM {KEV} k JOIN {NVD} n USING (cve_id)",
       "P2", "A data oficial da CISA (KEV) é a adotada")
checar("Consistência", "CVEs da coorte 2024 cujo ano no identificador difere do ano de publicação",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024 AND "
       "CAST(substring(cve_id, 5, 4) AS INT) <> year(data_publicacao)",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024",
       "P3/P4/P5: definição da coorte", "A coorte é definida pela data de publicação no NVD, não pelo ID")
checar("Completude", "CVEs do KEV sem registro no NVD",
       f"SELECT COUNT(*) FROM {KEV} k LEFT ANTI JOIN {NVD} n USING (cve_id)", f"SELECT COUNT(*) FROM {KEV}",
       "P2 e P5 dependem da data de publicação e do CVSS do NVD", "Mantidas na fato via full outer join (R12)")
checar("Completude", "CVEs do KEV sem nenhuma nota CVSS",
       f"SELECT COUNT(*) FROM {KEV} k JOIN {NVD} n USING (cve_id) WHERE n.cvss_score IS NULL",
       f"SELECT COUNT(*) FROM {KEV}", "P5", "Classificadas como 'Sem pontuação'")
checar("Completude", "CVEs de 2024 (não rejeitadas) sem nenhuma nota CVSS",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024 AND status_nvd <> 'Rejected' AND cvss_score IS NULL",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024 AND status_nvd <> 'Rejected'",
       "P3: fora da população avaliada", "Excluídas da população de P3 (R15) e relatadas")
checar("Completude", "CVEs de 2024 (não rejeitadas) sem EPSS no snapshot de 01/01/2025",
       f"SELECT COUNT(*) FROM {NVD} n LEFT ANTI JOIN (SELECT cve_id FROM {EPSS} WHERE snapshot='corte') e "
       "USING (cve_id) WHERE n.no_escopo_2024 AND n.status_nvd <> 'Rejected'",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024 AND status_nvd <> 'Rejected'",
       "P3", "Excluídas da população de P3 (R15)")
checar("Completude", "CVEs do KEV sem CWE específica (nula ou código especial do NVD)",
       f"SELECT COUNT(*) FROM {FATO} f JOIN {{gold.dim_cwe}} d USING (sk_cwe) "
       "WHERE f.em_kev AND (d.cwe_id LIKE 'NVD-CWE-%' OR f.sk_cwe = -1)",
       f"SELECT COUNT(*) FROM {FATO} WHERE em_kev", "P4", "Reportadas como categoria própria")
checar("Conformidade", "CWE referenciada que não existe na visão 1000 da MITRE",
       "SELECT COUNT(*) FROM {gold.dim_cwe} WHERE abstracao = 'Fora da visão 1000'",
       "SELECT COUNT(*) FROM {gold.dim_cwe} WHERE sk_cwe > 0", "P4",
       "Incluídas na dimensão com nome explicativo")
checar("Acurácia", "CVEs do KEV incluídas antes da publicação no NVD (dias < 0)",
       f"SELECT COUNT(*) FROM {FATO} WHERE dias_publicacao_ate_kev < 0",
       f"SELECT COUNT(*) FROM {FATO} WHERE dias_publicacao_ate_kev IS NOT NULL",
       "P2", "Plausível (exploração conhecida antes da publicação); mantidas e discutidas")
checar("Acurácia", "Notas CVSS fora de 0-10 ou EPSS fora de 0-1",
       f"SELECT (SELECT COUNT(*) FROM {NVD} WHERE cvss_score NOT BETWEEN 0 AND 10) + "
       f"(SELECT COUNT(*) FROM {EPSS} WHERE epss NOT BETWEEN 0 AND 1)", None, "P3, P5", "Nenhuma ocorrência")
checar("Atualidade", "CVEs de 2024 ainda sem análise própria do NVD (Received/Awaiting/Undergoing/Deferred)",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024 AND status_nvd IN "
       "('Received','Awaiting Analysis','Undergoing Analysis','Deferred')",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024 AND status_nvd <> 'Rejected'",
       "P3/P5: CVSS vem do CNA, não do NVD", "Nota do CNA aceita como substituta (R4); origem registrada")
checar("Atualidade", "CVEs de 2024 cujo CVSS escolhido é do CNA (não do NVD)",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024 AND cvss_origem = 'CNA'",
       f"SELECT COUNT(*) FROM {NVD} WHERE no_escopo_2024 AND cvss_score IS NOT NULL",
       "P3/P5", "Registrada em cvss_origem; limitação discutida")

esquema_regras = ("dimensao string, verificacao string, ocorrencias long, base long, pct double, "
                  "afeta string, tratamento string")
qualidade_regras = spark.createDataFrame(checagens, esquema_regras)
ambiente.salvar(qualidade_regras, "gold", "qualidade_regras",
                "Verificações de qualidade entre atributos e entre fontes, com tratamento aplicado")
ambiente.mostrar(qualidade_regras, n=30)

# COMMAND ----------

# MAGIC %md
# MAGIC ### 3. Atualidade das fontes

# COMMAND ----------

atualidade = ambiente.sql(f"""
    SELECT 'KEV — versão do catálogo' AS item, MAX(versao_catalogo) AS valor FROM {KEV}
    UNION ALL SELECT 'KEV — inclusão mais recente', CAST(MAX(data_inclusao_kev) AS STRING) FROM {KEV}
    UNION ALL SELECT 'NVD — modificação mais recente', CAST(MAX(ultima_modificacao_nvd) AS STRING) FROM {NVD}
    UNION ALL SELECT concat('EPSS ', snapshot, ' — data de referência / modelo'),
                     concat(CAST(MAX(data_referencia) AS STRING), ' / ', MAX(versao_modelo))
              FROM {EPSS} GROUP BY snapshot
""")
ambiente.mostrar(atualidade)

resumo = qualidade_atributos.agg(F.sum("violacoes_dominio").alias("violacoes")).first()["violacoes"]
print(f"Total de violações de domínio nas tabelas Silver (após tratamento): {resumo}")
