# Evidências

## `graficos/` — resultados das perguntas de negócio
Gerados pelo notebook `06_analise` (mesmo código que roda no Databricks, onde os gráficos
aparecem nas células do notebook).

| Arquivo | Pergunta |
|---|---|
| `p1_concentracao_fornecedores.png` | P1 — fornecedores e concentração ao longo do tempo |
| `p2_tempo_ate_exploracao.png` | P2 — tempo entre publicação e exploração |
| `p3_cvss_vs_epss.png` | P3 — cobertura × esforço, CVSS versus EPSS |
| `p4_cwe_ransomware.png` | P4 — classes de fraqueza e ransomware |
| `p5_severidade.png` | P5 — severidade das exploradas × todas as CVEs |

## `execucao_local/` — testes antes da execução na nuvem
* `log_coleta.txt` — saída do robô de coleta (páginas da API do NVD, volumes, tempo).
* `log_pipeline.txt` — execução completa dos seis notebooks em Spark 4.0 local
  (`scripts/executar_local.py`), com contagens de cada tabela e resultados.

## `databricks/` — execução na nuvem (Databricks Free Edition)
Doze capturas de tela que comprovam a persistência dos dados na nuvem e a execução do pipeline
(Job, Volume, tabelas, linhagem, qualidade e resultados de P1 a P5). A lista de arquivos e o que cada
um mostra está em [`databricks/README.md`](databricks/README.md); no [README principal](../README.md)
cada captura aparece no ponto do texto que ela sustenta.
