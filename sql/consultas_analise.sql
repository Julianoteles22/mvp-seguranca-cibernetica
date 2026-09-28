-- =====================================================================================
-- MVP — Priorização de vulnerabilidades com dados públicos de segurança cibernética
-- Consultas das perguntas de negócio, prontas para o SQL Editor do Databricks.
-- Esquema estrela: workspace.ciber_gold (fato_vulnerabilidade + dim_data, dim_produto,
-- dim_cwe, dim_severidade). Os notebooks 06_analise fazem as mesmas consultas com gráficos.
-- =====================================================================================

USE CATALOG workspace;
USE SCHEMA ciber_gold;

-- -------------------------------------------------------------------------------------
-- P1 · Quais fornecedores concentram as vulnerabilidades exploradas?
-- -------------------------------------------------------------------------------------
SELECT p.fornecedor,
       COUNT(*)                                             AS vulnerabilidades,
       ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1)     AS pct_do_kev,
       COUNT_IF(f.uso_ransomware)                           AS com_ransomware
FROM fato_vulnerabilidade f
JOIN dim_produto p USING (sk_produto)
WHERE f.em_kev
GROUP BY p.fornecedor
ORDER BY vulnerabilidades DESC
LIMIT 10;

-- P1 · A concentração aumentou ou diminuiu? (HHI e participação dos 5 maiores por ano de inclusão)
WITH por_fornecedor AS (
    SELECT d.ano, p.fornecedor, COUNT(*) AS n
    FROM fato_vulnerabilidade f
    JOIN dim_data d    ON f.sk_data_inclusao_kev = d.sk_data
    JOIN dim_produto p USING (sk_produto)
    WHERE f.em_kev
    GROUP BY d.ano, p.fornecedor),
ranqueado AS (
    SELECT *, SUM(n) OVER (PARTITION BY ano) AS total,
           ROW_NUMBER() OVER (PARTITION BY ano ORDER BY n DESC, fornecedor) AS posicao
    FROM por_fornecedor)
SELECT ano,
       MAX(total)                                                          AS inclusoes,
       ROUND(SUM(POW(100.0 * n / total, 2)), 0)                            AS hhi,
       ROUND(100.0 * SUM(CASE WHEN posicao <= 5 THEN n END) / MAX(total), 1) AS pct_top5,
       ROUND(100.0 * SUM(CASE WHEN fornecedor = 'Microsoft' THEN n ELSE 0 END) / MAX(total), 1) AS pct_microsoft
FROM ranqueado
GROUP BY ano
ORDER BY ano;

-- -------------------------------------------------------------------------------------
-- P2 · Tempo entre publicação e confirmação de exploração, por ano de publicação
-- -------------------------------------------------------------------------------------
SELECT d.ano                                        AS ano_publicacao,
       COUNT(*)                                     AS exploradas,
       PERCENTILE(f.dias_publicacao_ate_kev, 0.5)   AS mediana_dias,
       COUNT_IF(f.dias_publicacao_ate_kev <= 0)     AS ate_dia_0,
       COUNT_IF(f.dias_publicacao_ate_kev <= 7)     AS ate_7_dias,
       COUNT_IF(f.dias_publicacao_ate_kev <= 30)    AS ate_30_dias
FROM fato_vulnerabilidade f
JOIN dim_data d ON f.sk_data_publicacao = d.sk_data
WHERE f.em_kev AND d.ano >= 2018
GROUP BY d.ano
ORDER BY d.ano;

-- -------------------------------------------------------------------------------------
-- P3 · Com o mesmo esforço da política "corrigir só as críticas", quanto cada critério cobre?
-- (desempate do EPSS por hash do cve_id; o notebook usa sorteio com semente fixa, e o
--  resultado pode variar em ±1 CVE por causa disso)
-- -------------------------------------------------------------------------------------
WITH pop AS (
    SELECT cve_id, cvss_score, epss_corte, explorada_apos_corte,
           ROW_NUMBER() OVER (ORDER BY epss_corte DESC, xxhash64(cve_id)) AS posicao_epss
    FROM fato_vulnerabilidade
    WHERE na_populacao_p3),
k AS (
    SELECT COUNT_IF(cvss_score >= 9) AS n_criticas, COUNT_IF(explorada_apos_corte) AS exploradas, COUNT(*) AS populacao
    FROM pop)
SELECT k.populacao,
       k.exploradas                                                                        AS exploradas_apos_corte,
       k.n_criticas                                                                        AS cves_a_corrigir,
       ROUND(100.0 * k.n_criticas / k.populacao, 1)                                        AS esforco_pct,
       ROUND(100.0 * COUNT_IF(p.cvss_score >= 9 AND p.explorada_apos_corte) / k.exploradas, 1) AS cobertura_cvss_pct,
       ROUND(100.0 * COUNT_IF(p.posicao_epss <= k.n_criticas AND p.explorada_apos_corte) / k.exploradas, 1) AS cobertura_epss_pct
FROM pop p CROSS JOIN k
GROUP BY k.populacao, k.exploradas, k.n_criticas;

-- -------------------------------------------------------------------------------------
-- P4 · CWEs mais frequentes entre as exploradas e associação com ransomware
-- -------------------------------------------------------------------------------------
SELECT c.cwe_id, c.nome,
       COUNT(*)                                          AS exploradas,
       ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1)  AS pct_do_kev,
       COUNT_IF(f.uso_ransomware)                        AS com_ransomware,
       ROUND(100 * AVG(CAST(f.uso_ransomware AS INT)), 1) AS pct_ransomware
FROM fato_vulnerabilidade f
JOIN dim_cwe c USING (sk_cwe)
WHERE f.em_kev
GROUP BY c.cwe_id, c.nome
ORDER BY exploradas DESC
LIMIT 15;

-- P4 · Propensão à exploração: fração das CVEs de 2024 de cada CWE que entrou no KEV
SELECT c.cwe_id, c.nome,
       COUNT(*)                                     AS cves_2024,
       COUNT_IF(f.em_kev)                           AS exploradas,
       ROUND(100 * AVG(CAST(f.em_kev AS INT)), 2)   AS pct_exploradas
FROM fato_vulnerabilidade f
JOIN dim_cwe c USING (sk_cwe)
WHERE f.publicada_no_ano_coorte AND c.cwe_id NOT LIKE 'NVD-CWE%' AND f.sk_cwe <> -1
GROUP BY c.cwe_id, c.nome
HAVING COUNT(*) >= 300
ORDER BY pct_exploradas DESC;

-- -------------------------------------------------------------------------------------
-- P5 · Severidade CVSS: exploradas × todas as CVEs de 2024
-- -------------------------------------------------------------------------------------
SELECT s.faixa,
       COUNT_IF(f.em_kev)                                                      AS exploradas,
       ROUND(100 * COUNT_IF(f.em_kev) / SUM(COUNT_IF(f.em_kev)) OVER (), 1)    AS pct_exploradas,
       COUNT_IF(f.publicada_no_ano_coorte)                                     AS cves_2024,
       ROUND(100 * COUNT_IF(f.publicada_no_ano_coorte)
                 / SUM(COUNT_IF(f.publicada_no_ano_coorte)) OVER (), 1)        AS pct_cves_2024,
       ROUND(100 * COUNT_IF(f.publicada_no_ano_coorte AND f.em_kev)
                 / NULLIF(COUNT_IF(f.publicada_no_ano_coorte), 0), 2)          AS taxa_exploracao_2024
FROM fato_vulnerabilidade f
JOIN dim_severidade s USING (sk_severidade)
GROUP BY s.faixa, s.ordem
ORDER BY s.ordem;

-- -------------------------------------------------------------------------------------
-- Evidências de qualidade e linhagem
-- -------------------------------------------------------------------------------------
SELECT * FROM qualidade_regras;
SELECT * FROM resumo_respostas ORDER BY pergunta;
SELECT fonte, COUNT(*) AS arquivos, SUM(bytes) AS bytes, SUM(registros) AS registros, MAX(coletado_em_utc) AS coletado_em
FROM workspace.ciber_bronze.manifesto_coleta GROUP BY fonte;
