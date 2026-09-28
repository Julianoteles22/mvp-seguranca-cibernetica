# Capturas da execução no Databricks (Free Edition)

Capturas de tela da execução do pipeline na nuvem em 28/09/2026. Foram recortadas para mostrar
apenas a área do Databricks. Cada uma é referenciada no ponto do [README](../../README.md) que ela
sustenta.

| Arquivo | O que mostra |
|---|---|
| `01_job_execucao.png` | Job com as 6 tarefas (`coleta` … `analise`) concluídas em 7 min 15 s |
| `02_volume_landing.png` | Volume `landing` com as pastas `kev`, `nvd`, `epss`, `cwe` e o manifesto da coleta |
| `03_schemas_tabelas.png` | Schemas `ciber_bronze`, `ciber_silver`, `ciber_gold` e suas tabelas Delta |
| `04_fato_amostra.png` | Amostra de dados da `fato_vulnerabilidade` |
| `05_linhagem.png` | Grafo de linhagem da fato, gerado pelo Unity Catalog |
| `06_qualidade_regras.png` | Tabela `qualidade_regras` (16 verificações) |
| `07_p1_fornecedores.png` | P1 — fornecedores e concentração |
| `08_p2_tempo_exploracao.png` | P2 — tempo entre publicação e exploração |
| `09_p3_cvss_vs_epss.png` | P3 — cobertura × esforço, CVSS e EPSS |
| `10_p4_cwe_ransomware.png` | P4 — classes de fraqueza e ransomware |
| `11_p5_severidade.png` | P5 — severidade das exploradas × todas as CVEs |
| `12_resumo_respostas.png` | Tabela `resumo_respostas` com os indicadores-chave |
