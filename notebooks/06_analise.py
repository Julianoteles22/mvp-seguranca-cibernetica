# Databricks notebook source
# MAGIC %md
# MAGIC # 06 · Análise — respostas às perguntas de negócio
# MAGIC
# MAGIC Todas as consultas usam o esquema estrela da camada Gold. Os números impressos pelos
# MAGIC textos de interpretação são calculados a partir das consultas (não são digitados à mão),
# MAGIC para que o notebook continue correto se for reexecutado com uma coleta mais recente.
# MAGIC
# MAGIC | # | Pergunta de negócio | Decisão apoiada |
# MAGIC |---|---|---|
# MAGIC | P1 | Quais fornecedores e produtos concentram as vulnerabilidades exploradas, e a concentração aumentou ou diminuiu desde 2022? | Onde concentrar inventário e monitoramento de ativos |
# MAGIC | P2 | Quanto tempo passa entre a publicação de uma CVE e a confirmação de exploração, e esse tempo está encolhendo? | Prazo (SLA) interno de correção |
# MAGIC | P3 | Em 01/01/2025, priorizar as CVEs de 2024 por CVSS ou por EPSS teria coberto mais das vulnerabilidades exploradas depois, com o mesmo esforço? | Critério de priorização da fila de correções |
# MAGIC | P4 | Quais classes de fraqueza (CWE) predominam entre as exploradas e quais se associam a ransomware? | Foco de desenvolvimento seguro e testes |
# MAGIC | P5 | Que parcela das vulnerabilidades exploradas ficaria de fora de uma política "corrigir só as críticas"? | Política de SLA por severidade |

# COMMAND ----------

import os
import sys

sys.path.insert(0, os.path.abspath(".."))
from scripts import ambiente

import numpy as np
import pandas as pd
import matplotlib
if not ambiente.EM_DATABRICKS:
    matplotlib.use("Agg")
import matplotlib.pyplot as plt

spark = ambiente.obter_spark()
PASTA_GRAFICOS = os.path.join(ambiente.RAIZ_REPO, "evidencias", "graficos")
COR = {"principal": "#1F4E79", "destaque": "#C0392B", "neutro": "#8A94A6", "claro": "#BFD3E6",
       "verde": "#2E7D5B"}
plt.rcParams.update({"figure.dpi": 110, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.alpha": .25, "font.size": 10})

def q(consulta):
    """Consulta SQL na Gold → pandas (resultados são pequenos: dezenas de linhas)."""
    return ambiente.sql(consulta).toPandas()

def salvar_grafico(fig, nome):
    fig.tight_layout()
    if ambiente.EM_DATABRICKS:
        plt.show()
    else:
        os.makedirs(PASTA_GRAFICOS, exist_ok=True)
        fig.savefig(os.path.join(PASTA_GRAFICOS, f"{nome}.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)

def num(x, casas=1):
    """Número no padrão brasileiro: 1.234,5"""
    return f"{x:,.{casas}f}".replace(",", "X").replace(".", ",").replace("X", ".")

def pct(x, casas=1):
    """Fração (0-1) como percentual brasileiro: 12,3%"""
    return f"{num(100 * x, casas)}%"

resumo = []   # indicadores-chave de cada pergunta → tabela gold.resumo_respostas
def registrar(pergunta, indicador, valor):
    resumo.append((pergunta, indicador, str(valor)))

total_kev = q("SELECT COUNT(*) n FROM {gold.fato_vulnerabilidade} WHERE em_kev")["n"][0]
print(f"Vulnerabilidades no KEV: {total_kev}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## P1 · Concentração por fornecedor e produto

# COMMAND ----------

fornecedores = q("""
    SELECT p.fornecedor, COUNT(*) AS vulnerabilidades,
           ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct_do_kev,
           SUM(CAST(f.uso_ransomware AS INT)) AS com_ransomware
    FROM {gold.fato_vulnerabilidade} f JOIN {gold.dim_produto} p USING (sk_produto)
    WHERE f.em_kev
    GROUP BY p.fornecedor ORDER BY vulnerabilidades DESC
""")
produtos = q("""
    SELECT p.fornecedor, p.produto, COUNT(*) AS vulnerabilidades
    FROM {gold.fato_vulnerabilidade} f JOIN {gold.dim_produto} p USING (sk_produto)
    WHERE f.em_kev GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10
""")
print("Top 10 fornecedores:\n", fornecedores.head(10).to_string(index=False))
print("\nTop 10 produtos:\n", produtos.to_string(index=False))

concentracao = q("""
    WITH por_fornecedor AS (
        SELECT d.ano, p.fornecedor, COUNT(*) AS n
        FROM {gold.fato_vulnerabilidade} f
        JOIN {gold.dim_data} d ON f.sk_data_inclusao_kev = d.sk_data
        JOIN {gold.dim_produto} p USING (sk_produto)
        WHERE f.em_kev GROUP BY 1, 2),
    ranqueado AS (
        SELECT *, SUM(n) OVER (PARTITION BY ano) AS total,
               ROW_NUMBER() OVER (PARTITION BY ano ORDER BY n DESC, fornecedor) AS posicao
        FROM por_fornecedor)
    SELECT ano, MAX(total) AS inclusoes, COUNT(*) AS fornecedores_distintos,
           ROUND(SUM(POW(100.0 * n / total, 2)), 0) AS hhi,
           MAX_BY(fornecedor, n) AS lider,
           ROUND(100.0 * MAX(n) / MAX(total), 1) AS pct_lider,
           ROUND(100.0 * SUM(CASE WHEN posicao <= 5 THEN n END) / MAX(total), 1) AS pct_top5,
           ROUND(100.0 * SUM(CASE WHEN fornecedor = 'Microsoft' THEN n ELSE 0 END) / MAX(total), 1) AS pct_microsoft
    FROM ranqueado GROUP BY ano ORDER BY ano
""")
print("\nConcentração por ano de inclusão no KEV:\n", concentracao.to_string(index=False))

# COMMAND ----------

fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 4.6))
top = fornecedores.head(10).iloc[::-1]
a1.barh(top["fornecedor"], top["vulnerabilidades"], color=COR["principal"])
for y, (v, p_) in enumerate(zip(top["vulnerabilidades"], top["pct_do_kev"])):
    a1.text(v + 3, y, f"{v} ({str(p_).replace('.', ',')}%)", va="center", fontsize=8.5)
a1.set_title("Fornecedores com mais vulnerabilidades exploradas (KEV)")
a1.set_xlabel("vulnerabilidades no catálogo KEV")
a1.set_xlim(0, top["vulnerabilidades"].max() * 1.25)

c = concentracao[concentracao["ano"] >= 2022]
a2.plot(c["ano"], c["pct_top5"], "o-", color=COR["principal"], label="% dos 5 maiores fornecedores")
a2.plot(c["ano"], c["pct_microsoft"], "s--", color=COR["destaque"], label="% Microsoft")
a2.set_ylim(0, 100)
a2.set_xticks(c["ano"])
a2.set_title("Participação nas inclusões de cada ano")
a2.set_ylabel("% das inclusões do ano")
a2.legend(fontsize=8.5)
salvar_grafico(fig, "p1_concentracao_fornecedores")

c22, cfim = c.iloc[0], c.iloc[-1]
top5_geral = fornecedores.head(5)["vulnerabilidades"].sum() / total_kev
print(f"Os 5 maiores fornecedores respondem por {pct(top5_geral)} de todo o KEV; "
      f"a Microsoft sozinha, por {pct(fornecedores.iloc[0]['vulnerabilidades'] / total_kev)}.")
print(f"Participação dos 5 maiores nas inclusões do ano: {num(c22['pct_top5'])}% em {int(c22['ano'])} → "
      f"{num(cfim['pct_top5'])}% em {int(cfim['ano'])} (HHI {int(c22['hhi'])} → {int(cfim['hhi'])}).")
registrar("P1", "% do KEV nos 5 maiores fornecedores", pct(top5_geral))
registrar("P1", "Fornecedor líder", f"{fornecedores.iloc[0]['fornecedor']} ({fornecedores.iloc[0]['vulnerabilidades']})")
registrar("P1", f"% top-5 nas inclusões {int(c22['ano'])} → {int(cfim['ano'])}",
          f"{num(c22['pct_top5'])}% → {num(cfim['pct_top5'])}%")
registrar("P1", f"HHI {int(c22['ano'])} → {int(cfim['ano'])}", f"{int(c22['hhi'])} → {int(cfim['hhi'])}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## P2 · Tempo entre publicação e confirmação de exploração
# MAGIC
# MAGIC Coortes por **ano de publicação** da CVE. Dois cuidados de interpretação:
# MAGIC * CVEs publicadas antes de 2021 entraram no KEV na criação do catálogo (nov/2021), com anos
# MAGIC   de atraso que refletem a existência do catálogo e não a velocidade de exploração;
# MAGIC * **censura à direita**: para coortes recentes, só as CVEs exploradas *rapidamente* já tiveram
# MAGIC   tempo de entrar no KEV, o que puxa a mediana para baixo. Por isso a comparação justa entre
# MAGIC   coortes usa **contagens** de CVEs exploradas em até 7/30 dias, que não sofrem censura
# MAGIC   quando a coorte tem mais de 30 dias de acompanhamento.

# COMMAND ----------

tempo = q("""
    SELECT d.ano AS ano_publicacao, COUNT(*) AS exploradas,
           PERCENTILE(f.dias_publicacao_ate_kev, 0.5) AS mediana_dias,
           SUM(CASE WHEN f.dias_publicacao_ate_kev <= 0 THEN 1 ELSE 0 END) AS ate_dia_0,
           SUM(CASE WHEN f.dias_publicacao_ate_kev <= 7 THEN 1 ELSE 0 END) AS ate_7_dias,
           SUM(CASE WHEN f.dias_publicacao_ate_kev <= 30 THEN 1 ELSE 0 END) AS ate_30_dias
    FROM {gold.fato_vulnerabilidade} f JOIN {gold.dim_data} d ON f.sk_data_publicacao = d.sk_data
    WHERE f.em_kev AND d.ano >= 2018
    GROUP BY 1 ORDER BY 1
""")
tempo["pct_ate_7_dias"] = (100 * tempo["ate_7_dias"] / tempo["exploradas"]).round(1)
tempo["pct_ate_30_dias"] = (100 * tempo["ate_30_dias"] / tempo["exploradas"]).round(1)
print(tempo.to_string(index=False))

recentes = q("""
    SELECT COUNT(*) AS n, PERCENTILE(dias_publicacao_ate_kev, 0.5) AS mediana,
           AVG(CASE WHEN dias_publicacao_ate_kev <= 0 THEN 1 ELSE 0 END) AS p_dia0,
           AVG(CASE WHEN dias_publicacao_ate_kev <= 7 THEN 1 ELSE 0 END) AS p7,
           AVG(CASE WHEN dias_publicacao_ate_kev <= 30 THEN 1 ELSE 0 END) AS p30,
           PERCENTILE(prazo_remediacao_dias, 0.5) AS prazo_cisa_mediano
    FROM {gold.fato_vulnerabilidade} f JOIN {gold.dim_data} d ON f.sk_data_publicacao = d.sk_data
    WHERE f.em_kev AND d.ano BETWEEN 2022 AND 2025
""").iloc[0]

# COMMAND ----------

fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 4.4))
t = tempo[tempo["ano_publicacao"] >= 2019]
a1.bar(t["ano_publicacao"] - 0.2, t["ate_7_dias"], 0.4, color=COR["destaque"], label="exploradas em até 7 dias")
a1.bar(t["ano_publicacao"] + 0.2, t["exploradas"] - t["ate_7_dias"], 0.4, color=COR["claro"],
       label="exploradas depois de 7 dias (até a coleta)")
a1.set_xticks(t["ano_publicacao"])
a1.set_title("CVEs exploradas por ano de publicação")
a1.set_ylabel("nº de CVEs no KEV")
a1.legend(fontsize=8.5)

a2.plot(t["ano_publicacao"], t["pct_ate_7_dias"], "o-", color=COR["destaque"], label="% em até 7 dias")
a2.plot(t["ano_publicacao"], t["pct_ate_30_dias"], "s-", color=COR["principal"], label="% em até 30 dias")
a2.set_ylim(0, 100)
a2.set_xticks(t["ano_publicacao"])
a2.set_title("Velocidade: % das exploradas confirmadas logo após a publicação")
a2.set_ylabel("% das CVEs exploradas da coorte")
a2.legend(fontsize=8.5)
a2.annotate("coortes recentes: acompanhamento\nmais curto (censura à direita)",
            xy=(t["ano_publicacao"].max(), t["pct_ate_30_dias"].iloc[-1]), xytext=(2019.2, 88),
            fontsize=8, color=COR["neutro"], arrowprops=dict(arrowstyle="->", color=COR["neutro"]))
salvar_grafico(fig, "p2_tempo_ate_exploracao")

print(f"CVEs publicadas de 2022 a 2025 e exploradas: {int(recentes['n'])}. "
      f"Mediana de {recentes['mediana']:.0f} dias entre a publicação e a inclusão no KEV.")
print(f"{pct(recentes['p_dia0'])} entraram no KEV no mesmo dia da publicação ou antes (dia-zero); "
      f"{pct(recentes['p7'])} em até 7 dias; {pct(recentes['p30'])} em até 30 dias.")
print(f"Prazo mediano dado pela CISA para correção após a inclusão: {recentes['prazo_cisa_mediano']:.0f} dias.")
registrar("P2", "Mediana de dias publicação → KEV (CVEs 2022-2025)", f"{recentes['mediana']:.0f}")
registrar("P2", "% exploradas em até 7 dias (2022-2025)", pct(recentes["p7"]))
registrar("P2", "% exploradas em até 30 dias (2022-2025)", pct(recentes["p30"]))
registrar("P2", "% dia-zero (inclusão ≤ publicação)", pct(recentes["p_dia0"]))

# COMMAND ----------

# MAGIC %md
# MAGIC ## P3 · CVSS ou EPSS? Avaliação prospectiva em 01/01/2025
# MAGIC
# MAGIC **Desenho** (regra R15): a equipe olha, em 01/01/2025, para as CVEs publicadas em 2024 que ainda
# MAGIC não estavam no KEV, conhecendo apenas o CVSS e o EPSS **daquela data**. Depois, verificamos quais
# MAGIC delas entraram no KEV entre 02/01/2025 e a data da coleta. Como os scores são anteriores ao
# MAGIC desfecho, não há vazamento de informação do futuro.
# MAGIC
# MAGIC * **Cobertura** = % das vulnerabilidades exploradas depois que estavam na lista de correção;
# MAGIC * **Esforço** = % da população que precisaria ser corrigida;
# MAGIC * **Eficiência** = % da lista de correção que de fato veio a ser explorada.
# MAGIC
# MAGIC **Empates:** o CVSS tem poucos valores distintos (milhares de CVEs com nota 9,8). Escolher "as k
# MAGIC mais graves" exige desempatar, e um sorteio mudaria o resultado a cada execução. Por isso a
# MAGIC cobertura de uma lista de tamanho k é calculada pelo **valor esperado** com desempate uniforme
# MAGIC (exato, sem aleatoriedade) — o mesmo tratamento é aplicado ao EPSS.

# COMMAND ----------

pop = q("""
    SELECT cve_id, cvss_score, epss_corte, CAST(explorada_apos_corte AS INT) AS explorada
    FROM {gold.fato_vulnerabilidade} WHERE na_populacao_p3
""").sort_values("cve_id").reset_index(drop=True)   # ordem fixa → sorteios reprodutíveis em qualquer ambiente
N, POS = len(pop), int(pop["explorada"].sum())
print(f"População: {num(N, 0)} CVEs de 2024 · exploradas após 01/01/2025: {POS} (taxa-base {pct(POS / N, 2)})")

# Quantas CVEs de 2024 exploradas já estavam no KEV na data da decisão (e por isso ficam fora da população)?
ja_exploradas = q("""
    SELECT SUM(CASE WHEN d.data <= DATE'2025-01-01' THEN 1 ELSE 0 END) AS antes_do_corte, COUNT(*) AS total
    FROM {gold.fato_vulnerabilidade} f JOIN {gold.dim_data} d ON f.sk_data_inclusao_kev = d.sk_data
    WHERE f.publicada_no_ano_coorte AND f.em_kev
""").iloc[0]
print(f"Das {ja_exploradas['total']} CVEs de 2024 que entraram no KEV, {ja_exploradas['antes_do_corte']} "
      f"({pct(ja_exploradas['antes_do_corte'] / ja_exploradas['total'])}) já estavam lá em 01/01/2025.")

y = pop["explorada"].values
CVSS, EPSS = pop["cvss_score"].values, pop["epss_corte"].values

def cobertura_esperada(score, y, k):
    """Cobertura ao corrigir as k CVEs de maior score, com EMPATES resolvidos ao acaso.

    O CVSS tem poucos valores distintos (milhares de CVEs com 9,8), então "as k mais graves"
    depende de como se desempata. Em vez de um sorteio (que muda o resultado), usa-se o valor
    esperado exato: CVEs acima do valor de corte entram inteiras; do grupo empatado no corte,
    entra a fração que cabe no orçamento."""
    if k <= 0:
        return 0.0
    if k >= len(score):
        return 1.0
    corte = np.partition(score, len(score) - k)[len(score) - k]      # k-ésimo maior valor
    acima, empate = score > corte, score == corte
    vagas = k - acima.sum()
    return (y[acima].sum() + y[empate].sum() * vagas / empate.sum()) / y.sum()

k_1pct = int(0.01 * N)
nota_corte_1pct = np.partition(CVSS, N - k_1pct)[N - k_1pct]
empatadas_1pct = int((CVSS == nota_corte_1pct).sum())
print(f"O CVSS tem {len(np.unique(CVSS))} valores distintos nesta população. Para escolher as 1% mais graves "
      f"({num(k_1pct, 0)} CVEs), é preciso desempatar entre {num(empatadas_1pct, 0)} CVEs com nota "
      f"{num(nota_corte_1pct)} — o CVSS não diferencia as vulnerabilidades dentro desse grupo.")

def politica(mascara, nome):
    k = int(mascara.sum())
    capt = int(y[mascara].sum())
    return {"politica": nome, "cves_a_corrigir": k, "esforco": k / N, "cobertura": capt / POS,
            "eficiencia": capt / k if k else 0.0, "exploradas_cobertas": capt}

politicas = pd.DataFrame([
    politica(CVSS >= 9.0, "CVSS ≥ 9,0 (só críticas)"),
    politica(CVSS >= 7.0, "CVSS ≥ 7,0 (altas e críticas)"),
    politica(EPSS >= 0.10, "EPSS ≥ 0,10"),
    politica(EPSS >= 0.01, "EPSS ≥ 0,01"),
])
k_criticas = int(politicas.loc[0, "cves_a_corrigir"])
cob_epss_mesmo = cobertura_esperada(EPSS, y, k_criticas)
politicas = pd.concat([politicas, pd.DataFrame([{
    "politica": f"EPSS: top {num(k_criticas, 0)} (mesmo esforço das críticas)",
    "cves_a_corrigir": k_criticas, "esforco": k_criticas / N, "cobertura": cob_epss_mesmo,
    "eficiencia": cob_epss_mesmo * POS / k_criticas, "exploradas_cobertas": round(cob_epss_mesmo * POS, 1)}])],
    ignore_index=True)
print(politicas.assign(esforco=lambda d: (100 * d.esforco).round(1),
                       cobertura=lambda d: (100 * d.cobertura).round(1),
                       eficiencia=lambda d: (100 * d.eficiencia).round(2)).to_string(index=False))

# Cobertura por nível de esforço (orçamento fixo de correções)
niveis = [0.005, 0.01, 0.02, 0.05, 0.10, 0.20]
por_esforco = pd.DataFrame({
    "esforco": [pct(e) for e in niveis],
    "cves_corrigidas": [int(e * N) for e in niveis],
    "cobertura_CVSS": [pct(cobertura_esperada(CVSS, y, int(e * N))) for e in niveis],
    "cobertura_EPSS": [pct(cobertura_esperada(EPSS, y, int(e * N))) for e in niveis],
})
print("\nCobertura esperada com orçamento fixo:\n", por_esforco.to_string(index=False))

# COMMAND ----------

# Intervalo de confiança (bootstrap) para a diferença de cobertura com o mesmo esforço das "críticas"
rng = np.random.default_rng(42)
B = 1000
diferencas = np.empty(B)
for b in range(B):
    idx = rng.integers(0, N, N)
    yb, cvss_b, epss_b = y[idx], CVSS[idx], EPSS[idx]
    crit = cvss_b >= 9.0
    diferencas[b] = cobertura_esperada(epss_b, yb, int(crit.sum())) - yb[crit].sum() / yb.sum()
ic = np.percentile(diferencas, [2.5, 97.5])
cob_crit = politicas.loc[0, "cobertura"]
print(f"Mesmo esforço ({k_criticas} CVEs = {pct(k_criticas / N)} da população): "
      f"CVSS ≥ 9 cobre {pct(cob_crit)} × EPSS cobre {pct(cob_epss_mesmo)}.")
def pp(x):
    return ("+" if x >= 0 else "−") + num(abs(100 * x)) + " p.p."

print(f"Diferença (EPSS − CVSS): {pp(cob_epss_mesmo - cob_crit)}; "
      f"IC 95% bootstrap [{pp(ic[0])}; {pp(ic[1])}]")

# COMMAND ----------

esforcos = np.linspace(0, 0.30, 61)
curva = pd.DataFrame({"esforco": esforcos,
                      "CVSS": [cobertura_esperada(CVSS, y, int(e * N)) for e in esforcos],
                      "EPSS": [cobertura_esperada(EPSS, y, int(e * N)) for e in esforcos]})
fig, ax = plt.subplots(figsize=(9.5, 5))
ax.plot(100 * curva["esforco"], 100 * curva["EPSS"], color=COR["principal"], lw=2.2, label="ordenar por EPSS")
ax.plot(100 * curva["esforco"], 100 * curva["CVSS"], color=COR["destaque"], lw=2.2, label="ordenar por CVSS")
ax.plot([0, 30], [0, 30], "--", color=COR["neutro"], lw=1, label="ordem aleatória")
for _, r in politicas.iterrows():
    cor = COR["destaque"] if r["politica"].startswith("CVSS") else COR["principal"]
    ax.scatter(100 * r["esforco"], 100 * r["cobertura"], color=cor, zorder=5, s=35)
    if r["esforco"] <= 0.30:
        deslocamento = (6, 5) if r["politica"].startswith("EPSS ≥ 0,10") else (6, -10)
        ax.annotate(r["politica"], (100 * r["esforco"], 100 * r["cobertura"]), fontsize=7.5,
                    xytext=deslocamento, textcoords="offset points")
ax.set_xlim(0, 30); ax.set_ylim(0, 100)
ax.set_xlabel("esforço: % das CVEs de 2024 corrigidas")
ax.set_ylabel("cobertura: % das exploradas em 2025-26 já corrigidas")
ax.set_title("Priorização em 01/01/2025 — cobertura das vulnerabilidades exploradas depois")
ax.legend(loc="lower right")
salvar_grafico(fig, "p3_cvss_vs_epss")

registrar("P3", "Exploradas de 2024 já no KEV em 01/01/2025",
          f"{ja_exploradas['antes_do_corte']} de {ja_exploradas['total']} "
          f"({pct(ja_exploradas['antes_do_corte'] / ja_exploradas['total'])})")
registrar("P3", "População (CVEs 2024) / exploradas depois do corte", f"{num(N, 0)} / {POS}")
registrar("P3", "Cobertura CVSS ≥ 9 (esforço)", f"{pct(cob_crit)} ({pct(k_criticas / N)})")
registrar("P3", "Cobertura EPSS com o mesmo esforço", pct(cob_epss_mesmo))
registrar("P3", "Diferença EPSS − CVSS (IC 95%)", f"{pp(cob_epss_mesmo - cob_crit)} [{pp(ic[0])}; {pp(ic[1])}]")
registrar("P3", "Empate do CVSS na lista das 1% mais graves",
          f"{num(k_1pct, 0)} vagas para {num(empatadas_1pct, 0)} CVEs com nota {num(nota_corte_1pct)}")
registrar("P3", "Cobertura com 1% de esforço: CVSS / EPSS",
          f"{por_esforco.loc[1, 'cobertura_CVSS']} / {por_esforco.loc[1, 'cobertura_EPSS']}")
registrar("P3", "Cobertura / esforço da política CVSS ≥ 7",
          f"{pct(politicas.loc[1, 'cobertura'])} / {pct(politicas.loc[1, 'esforco'])}")
registrar("P3", "Cobertura / esforço da política EPSS ≥ 0,10",
          f"{pct(politicas.loc[2, 'cobertura'])} / {pct(politicas.loc[2, 'esforco'])}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## P4 · Classes de fraqueza (CWE) e ransomware

# COMMAND ----------

cwe_kev = q("""
    SELECT c.cwe_id, c.nome, COUNT(*) AS exploradas,
           ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct_do_kev,
           SUM(CAST(f.uso_ransomware AS INT)) AS com_ransomware,
           ROUND(100 * AVG(CAST(f.uso_ransomware AS INT)), 1) AS pct_ransomware
    FROM {gold.fato_vulnerabilidade} f JOIN {gold.dim_cwe} c USING (sk_cwe)
    WHERE f.em_kev GROUP BY 1, 2 ORDER BY exploradas DESC
""")
taxa_rw = q("SELECT AVG(CAST(uso_ransomware AS INT)) t FROM {gold.fato_vulnerabilidade} WHERE em_kev")["t"][0]
sem_cwe = cwe_kev[cwe_kev["cwe_id"].str.startswith("NVD-CWE") | (cwe_kev["cwe_id"] == "Não informado")]
print(cwe_kev.head(12).to_string(index=False))
print(f"\nTaxa geral de ransomware no KEV: {pct(taxa_rw)}; sem CWE específica: "
      f"{pct(sem_cwe['exploradas'].sum() / total_kev)}")

# Propensão à exploração por CWE: entre TODAS as CVEs publicadas em 2024, qual fração entrou no KEV?
propensao = q("""
    SELECT c.cwe_id, c.nome, COUNT(*) AS cves_2024, SUM(CAST(f.em_kev AS INT)) AS exploradas,
           ROUND(100 * AVG(CAST(f.em_kev AS INT)), 2) AS pct_exploradas
    FROM {gold.fato_vulnerabilidade} f JOIN {gold.dim_cwe} c USING (sk_cwe)
    WHERE f.publicada_no_ano_coorte AND c.cwe_id NOT LIKE 'NVD-CWE%' AND f.sk_cwe <> -1
    GROUP BY 1, 2 HAVING COUNT(*) >= 300 ORDER BY pct_exploradas DESC
""")
taxa_2024 = q("SELECT AVG(CAST(em_kev AS INT)) t FROM {gold.fato_vulnerabilidade} WHERE publicada_no_ano_coorte")["t"][0]
print(f"\nCWEs com ≥ 300 CVEs em 2024 — fração explorada (taxa geral de 2024: {pct(taxa_2024, 2)}):")
print(propensao.to_string(index=False))

# COMMAND ----------

fig, (a1, a2) = plt.subplots(1, 2, figsize=(14, 5.2))
t = cwe_kev[~cwe_kev["cwe_id"].isin(sem_cwe["cwe_id"])].head(10).iloc[::-1]
rotulos = [f"{i} · {n[:38]}{'…' if len(n) > 38 else ''}" for i, n in zip(t["cwe_id"], t["nome"])]
a1.barh(rotulos, t["exploradas"], color=COR["claro"], label="exploradas")
a1.barh(rotulos, t["com_ransomware"], color=COR["destaque"], label="usadas por ransomware")
a1.set_title("Top 10 CWEs entre as vulnerabilidades exploradas")
a1.set_xlabel("nº de vulnerabilidades no KEV")
a1.legend(fontsize=8.5, loc="lower right")
a1.tick_params(axis="y", labelsize=8)

p = propensao.head(8).iloc[::-1]
rot2 = [f"{i} · {n[:30]}{'…' if len(n) > 30 else ''}" for i, n in zip(p["cwe_id"], p["nome"])]
a2.barh(rot2, p["pct_exploradas"], color=COR["principal"])
a2.axvline(100 * taxa_2024, color=COR["neutro"], ls="--", lw=1,
            label=f"média de todas as CVEs de 2024: {num(100 * taxa_2024, 2)}%")
for yy, (v, n) in enumerate(zip(p["pct_exploradas"], p["cves_2024"])):
    a2.text(v, yy, f" {num(v, 2)}% de {num(n, 0)}", va="center", fontsize=8)
a2.set_xlim(0, p["pct_exploradas"].max() * 1.3)
a2.legend(fontsize=8, loc="lower right")
a2.set_title("Propensão à exploração por CWE (CVEs de 2024)")
a2.set_xlabel("% das CVEs da CWE que entraram no KEV")
a2.tick_params(axis="y", labelsize=8)
salvar_grafico(fig, "p4_cwe_ransomware")

lider = cwe_kev[~cwe_kev["cwe_id"].isin(sem_cwe["cwe_id"])].iloc[0]
rw = cwe_kev[(cwe_kev["exploradas"] >= 20) & ~cwe_kev["cwe_id"].isin(sem_cwe["cwe_id"])] \
    .sort_values("pct_ransomware", ascending=False).iloc[0]
xss = propensao[propensao["cwe_id"] == "CWE-79"]
registrar("P4", "CWE mais frequente no KEV",
          f"{lider['cwe_id']} ({lider['exploradas']}; {num(lider['pct_do_kev'])}%)")
registrar("P4", "CWE (n≥20) com maior % de ransomware",
          f"{rw['cwe_id']} ({num(rw['pct_ransomware'])}% vs {pct(taxa_rw)} geral)")
registrar("P4", "CWE com maior propensão à exploração em 2024 (n≥300)",
          f"{propensao.iloc[0]['cwe_id']} ({num(propensao.iloc[0]['pct_exploradas'], 2)}%)")
if len(xss):
    registrar("P4", "CWE-79 (XSS): CVEs 2024 / % exploradas",
              f"{num(xss.iloc[0]['cves_2024'], 0)} / {num(xss.iloc[0]['pct_exploradas'], 2)}%")

# COMMAND ----------

# MAGIC %md
# MAGIC ## P5 · Severidade CVSS das vulnerabilidades exploradas

# COMMAND ----------

severidade = q("""
    SELECT s.ordem, s.faixa,
           SUM(CASE WHEN f.em_kev THEN 1 ELSE 0 END) AS exploradas,
           SUM(CASE WHEN f.publicada_no_ano_coorte THEN 1 ELSE 0 END) AS cves_2024,
           SUM(CASE WHEN f.publicada_no_ano_coorte AND f.em_kev THEN 1 ELSE 0 END) AS exploradas_2024
    FROM {gold.fato_vulnerabilidade} f JOIN {gold.dim_severidade} s USING (sk_severidade)
    GROUP BY 1, 2 ORDER BY 1
""")
for c_ in ["exploradas", "cves_2024", "exploradas_2024"]:
    severidade[f"pct_{c_}"] = (100 * severidade[c_] / severidade[c_].sum()).round(1)
severidade["taxa_exploracao_2024"] = (100 * severidade["exploradas_2024"] /
                                      severidade["cves_2024"].replace(0, np.nan)).round(2)
print(severidade.to_string(index=False))

por_versao = q("""
    SELECT COALESCE(cvss_versao, 'sem nota') AS versao, COUNT(*) AS exploradas,
           ROUND(100 * AVG(CASE WHEN cvss_score >= 9 THEN 1 ELSE 0 END), 1) AS pct_criticas
    FROM {gold.fato_vulnerabilidade} WHERE em_kev GROUP BY 1 ORDER BY 2 DESC
""")
print("\nPor versão do CVSS usada:\n", por_versao.to_string(index=False))

# COMMAND ----------

s = severidade[severidade["faixa"].isin(["Baixa", "Média", "Alta", "Crítica"])].reset_index(drop=True)
x = np.arange(len(s))
fig, ax = plt.subplots(figsize=(10, 4.6))
ax.bar(x - 0.2, s["pct_cves_2024"], 0.4, color=COR["claro"], label="todas as CVEs de 2024")
ax.bar(x + 0.2, s["pct_exploradas"], 0.4, color=COR["destaque"], label="vulnerabilidades exploradas (KEV)")
for xi, (a, b) in enumerate(zip(s["pct_cves_2024"], s["pct_exploradas"])):
    ax.text(xi - 0.2, a + 0.8, f"{a:.1f}%".replace(".", ","), ha="center", fontsize=8)
    ax.text(xi + 0.2, b + 0.8, f"{b:.1f}%".replace(".", ","), ha="center", fontsize=8)
ax.set_xticks(x); ax.set_xticklabels(s["faixa"])
ax.set_ylabel("% do grupo")
ax.set_title("Distribuição por faixa de severidade CVSS")
ax.legend()
salvar_grafico(fig, "p5_severidade")

crit = severidade.set_index("faixa")
fora = 1 - crit.loc["Crítica", "exploradas"] / severidade["exploradas"].sum()
print(f"{pct(fora)} das vulnerabilidades exploradas NÃO são críticas pelo CVSS — ficariam fora de uma "
      f"política 'corrigir só as críticas'. Faixa mais comum entre as exploradas: "
      f"{severidade.sort_values('exploradas').iloc[-1]['faixa']}.")
registrar("P5", "% das exploradas fora da faixa Crítica", pct(fora))
registrar("P5", "% das exploradas na faixa Alta", f"{num(crit.loc['Alta', 'pct_exploradas'])}%")
registrar("P5", "Taxa de exploração das CVEs Críticas de 2024", f"{num(crit.loc['Crítica', 'taxa_exploracao_2024'], 2)}%")
registrar("P5", "Taxa de exploração das CVEs Altas de 2024", f"{num(crit.loc['Alta', 'taxa_exploracao_2024'], 2)}%")
registrar("P5", "Taxa de exploração das CVEs Médias de 2024", f"{num(crit.loc['Média', 'taxa_exploracao_2024'], 2)}%")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Resumo das respostas
# MAGIC Persistido em `ciber_gold.resumo_respostas` (evidência consultável por SQL).

# COMMAND ----------

tabela_resumo = spark.createDataFrame(resumo, "pergunta string, indicador string, valor string")
ambiente.salvar(tabela_resumo, "gold", "resumo_respostas", "Indicadores-chave de cada pergunta de negócio")
ambiente.mostrar(tabela_resumo, n=40)
