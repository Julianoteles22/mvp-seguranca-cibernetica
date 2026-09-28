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
Capturas de tela que comprovam a persistência dos dados na nuvem e a execução do pipeline.
Nomes esperados e o que cada uma deve mostrar:

| Arquivo | O que mostrar | Onde encontrar |
|---|---|---|
| `01_volume_landing.png` | Pastas `kev/`, `nvd/`, `epss/`, `cwe/` e o `_manifesto_coleta.json` no Volume | *Catalog → workspace → ciber_bronze → Volumes → landing* |
| `02_schemas_tabelas.png` | Os três schemas e suas tabelas | *Catalog → workspace* (expandir `ciber_bronze`, `ciber_silver`, `ciber_gold`) |
| `03_job_execucao.png` | Grafo do Job com as 6 tarefas concluídas (verde) e duração | *Jobs & Pipelines → MVP Segurança Cibernética → execução* |
| `04_fato_amostra.png` | Aba *Sample Data* da `fato_vulnerabilidade` | *Catalog → ciber_gold → fato_vulnerabilidade* |
| `05_linhagem.png` | Aba *Lineage* da `fato_vulnerabilidade` (grafo bronze → silver → gold, gerado automaticamente pelo Unity Catalog) | idem, aba *Lineage* → *See lineage graph* |
| `06_qualidade.png` | Resultado de `SELECT * FROM qualidade_regras` | *SQL Editor* com `sql/consultas_analise.sql` |
| `07_p1.png` … `11_p5.png` | Resultado de cada consulta de P1 a P5 | *SQL Editor* ou células do notebook `06_analise` |
| `12_resumo_respostas.png` | `SELECT * FROM resumo_respostas` | *SQL Editor* |

Depois de salvar as imagens nesta pasta, referencie-as no README principal (seção
"Evidências da execução na nuvem").
