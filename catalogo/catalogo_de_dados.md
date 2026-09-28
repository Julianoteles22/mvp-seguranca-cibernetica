# Catálogo de Dados

> Gerado por `scripts/gerar_catalogo.py` a partir das tabelas carregadas. Coleta de referência: **2026-09-28** (UTC). Regras R1–R15: ver notebooks `03_silver` e `04_gold`.

## Como ler

* **Domínio declarado** — o que se espera do atributo (verificado automaticamente no notebook `05_qualidade`).
* **Domínio observado** — o que de fato existe nos dados carregados (mínimo–máximo, categorias ou contagem de distintos).
* **Obrigatoriedade** — se o atributo admite nulo e **o que o nulo significa**.
* **Linhagem** — campo de origem e regra de transformação aplicada.

## `gold.fato_vulnerabilidade`

Tabela fato. **Grão: uma linha por CVE.** Reúne as CVEs do catálogo KEV (todas) e as CVEs publicadas em 2024 no NVD (exceto as rejeitadas — R11).  
**Linhas:** 41.521

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `cve_id` | texto | Identificador da vulnerabilidade (dimensão degenerada / chave natural). | padrão `CVE-AAAA-NNNN…` | 41.521 valores distintos | 0,0 | Obrigatório, único. | NVD `cve.id` ⊕ KEV `cveID` (R1, R12) |
| `sk_data_publicacao` | inteiro | Chave para `dim_data` no papel *data de publicação* no NVD. | AAAAMMDD ou -1 | 20020625 a 20260927 | 0,0 | Obrigatório; -1 = sem data (CVE só no KEV). | NVD `published` → DATE UTC (R14) |
| `sk_data_inclusao_kev` | inteiro | Chave para `dim_data` no papel *data de inclusão no KEV* (confirmação de exploração ativa pela CISA). | AAAAMMDD ou -1 | -1 a 20260927 | 0,0 | Obrigatório; -1 = não está no KEV. | KEV `dateAdded` (R3, R14) |
| `sk_data_prazo_kev` | inteiro | Chave para `dim_data` no papel *prazo de correção* exigido pela CISA às agências federais dos EUA. | AAAAMMDD ou -1 | -1 a 20260930 | 0,0 | Obrigatório; -1 = não está no KEV. | KEV `dueDate` (R3, R14) |
| `sk_produto` | inteiro | Chave para `dim_produto` (fornecedor e produto afetados). | ≥ 1 ou -1 | -1 a 719 | 0,0 | Obrigatório; -1 = fora do KEV (o NVD não traz fornecedor sem interpretar CPEs). | KEV `vendorProject`, `product` (R2, R14) |
| `sk_cwe` | inteiro | Chave para `dim_cwe` (classe de fraqueza principal). | ≥ 1 ou -1 | -1 a 958 | 0,0 | Obrigatório; -1 = nenhuma CWE informada por NVD nem CISA. | NVD `weaknesses` / KEV `cwes` (R6, R13) |
| `sk_severidade` | inteiro | Chave para `dim_severidade` (faixa CVSS). | -1 a 4 | -1 a 4 | 0,0 | Obrigatório; -1 = sem nota CVSS. | Calculada de `cvss_score` (R5) |
| `cvss_score` | decimal | Nota-base CVSS escolhida pela regra de precedência R4. | 0,0 a 10,0 | 0 a 10 | 0,02 | Opcional; nulo = nenhuma nota publicada nem pelo NVD nem pelo CNA. | NVD `metrics.cvssMetricV31/V30/V40/V2[].cvssData.baseScore` (R4) |
| `cvss_versao` | texto | Versão do CVSS da nota escolhida. | 2.0, 3.0, 3.1, 4.0 | 3.0, 3.1, 4.0 | 0,02 | Nulo quando `cvss_score` é nulo. | Nome do campo de métrica de origem (R4) |
| `cvss_origem` | texto | Quem atribuiu a nota: o próprio NVD (*Primary*) ou o CNA emissor (*Secondary*). | NVD, CNA | CNA, NVD | 0,02 | Nulo quando `cvss_score` é nulo. | NVD `metrics.*[].type` (R4) |
| `status_nvd` | texto | Situação da análise da CVE no NVD na data da coleta. | Received, Awaiting Analysis, Undergoing Analysis, Analyzed, Modified, Deferred, Rejected | Analyzed, Deferred, Modified, Undergoing Analysis | 0,0 | Nulo apenas para CVE do KEV ausente do NVD. | NVD `vulnStatus` |
| `em_kev` | booleano | A CVE consta do catálogo KEV (exploração ativa confirmada). | true/false | True: 1.728, False: 39.793 | 0,0 | Obrigatório. | Existência de `dateAdded` no KEV |
| `uso_ransomware` | booleano | A CISA registra uso conhecido em campanhas de ransomware. | true/false | True: 361, False: 41.160 | 0,0 | Obrigatório; false também para CVEs fora do KEV. | KEV `knownRansomwareCampaignUse = 'Known'` (R3) |
| `triagem_forense` | booleano | A CISA recomenda triagem forense além da correção. | true/false | True: 69, False: 41.452 | 0,0 | Obrigatório; false fora do KEV. | KEV `forensicTriage = 'Yes'` |
| `publicada_no_ano_coorte` | booleano | CVE publicada no NVD em 2024 (coorte das perguntas P3–P5). | true/false | True: 39.953, False: 1.568 | 0,0 | Obrigatório. | `year(data_publicacao) = 2024` |
| `dias_publicacao_ate_kev` | inteiro | Dias entre a publicação no NVD e a inclusão no KEV. Negativo quando a exploração foi confirmada antes da publicação. | inteiro; negativo admitido | -290 a 7.191 | 95,8 | Nulo fora do KEV. | `dateAdded − published` |
| `prazo_remediacao_dias` | inteiro | Dias concedidos pela CISA para a correção, a partir da inclusão. | 0 a 365 | 1 a 184 | 95,8 | Nulo fora do KEV. | `dueDate − dateAdded` |
| `epss_corte` | decimal | Probabilidade EPSS de exploração em 30 dias, **como publicada em 01/01/2025** (modelo v2023.03.01). | 0 a 1 | 0,00042 a 0,97559 | 2,1 | Nulo = CVE sem score nessa data. | FIRST `epss_scores-2025-01-01.csv.gz` (R8) |
| `percentil_epss_corte` | decimal | Percentil do EPSS de corte entre todas as CVEs pontuadas. | 0 a 1 | 0,00308 a 1 | 2,1 | Nulo junto com `epss_corte`. | idem |
| `epss_atual` | decimal | Probabilidade EPSS na data da coleta (modelo vigente). | 0 a 1 | 0,00064 a 0,99999 | 0,0 | Nulo = CVE sem score atual. | FIRST `epss_scores-current.csv.gz` (R8) |
| `percentil_epss_atual` | decimal | Percentil do EPSS atual. | 0 a 1 | 0,0001 a 1 | 0,0 | Nulo junto com `epss_atual`. | idem |
| `explorada_apos_corte` | booleano | Entrou no KEV depois de 01/01/2025 (desfecho da P3). | true/false | True: 489, False: 41.032 | 0,0 | Obrigatório. | `dateAdded > 2025-01-01` (R15) |
| `na_populacao_p3` | booleano | Pertence à população da avaliação prospectiva da P3. | true/false | True: 39.323, False: 2.198 | 0,0 | Obrigatório. | Regra R15 |

## `gold.dim_data`

Calendário. Dimensão com três **papéis** na fato: publicação, inclusão no KEV e prazo.  
**Linhas:** 8.865

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `sk_data` | inteiro | Chave substituta no formato AAAAMMDD. | AAAAMMDD ou -1 | -1 a 20260930 | 0,0 | Obrigatório, único. | Gerada |
| `data` | data | Data do calendário. | da menor à maior data da fato | 2002-06-25 a 2026-09-30 | 0,01 | Nulo só no membro -1. | `sequence()` entre a menor e a maior data da fato |
| `ano` | inteiro | Ano. | — | 2.002 a 2.026 | 0,01 | Nulo só no membro -1. | Derivado de `data` |
| `trimestre` | inteiro | Trimestre. | 1 a 4 | 1 a 4 | 0,01 | Nulo só no membro -1. | Derivado de `data` |
| `mes` | inteiro | Mês. | 1 a 12 | 1 a 12 | 0,01 | Nulo só no membro -1. | Derivado de `data` |
| `nome_mes` | texto | Nome do mês em português. | janeiro … dezembro, Não informada | 13 valores distintos | 0,0 | Obrigatório. | Derivado |
| `dia_semana` | texto | Dia da semana em português. | domingo … sábado, Não informada | Não informada, domingo, quarta, quinta, segunda, sexta, sábado, terça | 0,0 | Obrigatório. | Derivado |
| `fim_de_semana` | booleano | Sábado ou domingo. | true/false | True: 2.532, False: 6.332 | 0,01 | Nulo só no membro -1. | Derivado |

## `gold.dim_produto`

Pares fornecedor/produto afetados, conforme nomenclatura da CISA no KEV.  
**Linhas:** 720

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `sk_produto` | inteiro | Chave substituta. | ≥ 1 ou -1 | -1 a 719 | 0,0 | Obrigatório, único. | `row_number()` ordenado |
| `fornecedor` | texto | Fornecedor ou projeto (ex.: Microsoft, Apache). | texto sem espaços nas pontas | 284 valores distintos | 0,0 | Obrigatório. | KEV `vendorProject` + `trim` (R2) |
| `produto` | texto | Produto afetado (ex.: Windows, Exchange Server). | texto sem espaços nas pontas | 691 valores distintos | 0,0 | Obrigatório. | KEV `product` + `trim` (R2) |

## `gold.dim_cwe`

Classes de fraqueza de software (Common Weakness Enumeration, MITRE).  
**Linhas:** 959

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `sk_cwe` | inteiro | Chave substituta. | ≥ 1 ou -1 | -1 a 958 | 0,0 | Obrigatório, único. | `row_number()` ordenado |
| `cwe_id` | texto | Código da fraqueza. | `CWE-N`, `NVD-CWE-noinfo`, `NVD-CWE-Other` | 959 valores distintos | 0,0 | Obrigatório. | MITRE `CWE-ID` com prefixo (R9) ⊕ IDs referenciados pelo NVD/KEV |
| `nome` | texto | Nome oficial da fraqueza (em inglês, como publicado pela MITRE). | texto | 948 valores distintos | 0,0 | Obrigatório. | MITRE `Name` |
| `abstracao` | texto | Nível na hierarquia CWE. | Pillar, Class, Base, Variant, Compound, Especial NVD, Fora da visão 1000, Não informado | Base, Class, Compound, Especial NVD, Fora da visão 1000, Não informado, Pillar, Variant | 0,0 | Obrigatório. | MITRE `Weakness Abstraction` |
| `status` | texto | Maturidade da definição na MITRE. | Stable, Draft, Incomplete, Deprecated | Draft, Incomplete, Stable | 1,6 | Nulo para códigos especiais e IDs fora da visão 1000. | MITRE `Status` |

## `gold.dim_severidade`

Faixas qualitativas de severidade com os limites do CVSS v3 (domínio fixo).  
**Linhas:** 6

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `sk_severidade` | inteiro | Chave substituta. | -1 a 4 | -1 a 4 | 0,0 | Obrigatório, único. | Domínio fixo |
| `faixa` | texto | Nome da faixa. | Sem pontuação, Nenhuma, Baixa, Média, Alta, Crítica | Alta, Baixa, Crítica, Média, Nenhuma, Sem pontuação | 0,0 | Obrigatório. | Especificação CVSS v3.1, seção 5 |
| `score_minimo` | decimal | Limite inferior da faixa. | 0,0 a 9,0 | 0 a 9 | 16,7 | Nulo para 'Sem pontuação'. | idem |
| `score_maximo` | decimal | Limite superior da faixa. | 0,0 a 10,0 | 0 a 10 | 16,7 | Nulo para 'Sem pontuação'. | idem |
| `ordem` | inteiro | Ordem de exibição. | 0 a 5 | 0 a 5 | 0,0 | Obrigatório. | Domínio fixo |

## `silver.kev`

Catálogo KEV tipado e padronizado — 1 linha por CVE.  
**Linhas:** 1.728

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `cve_id` | texto | Identificador da CVE. | padrão CVE | 1.728 valores distintos | 0,0 | Obrigatório, único. | `cveID` (R1) |
| `fornecedor` | texto | Fornecedor/projeto. | texto | 283 valores distintos | 0,0 | Obrigatório. | `vendorProject` (R2) |
| `produto` | texto | Produto. | texto | 690 valores distintos | 0,0 | Obrigatório. | `product` (R2) |
| `nome_vulnerabilidade` | texto | Nome dado pela CISA. | texto | 1.380 valores distintos | 0,0 | Obrigatório. | `vulnerabilityName` |
| `data_inclusao_kev` | data | Inclusão no catálogo. | ≥ 2021-11-03 e ≤ data da coleta | 2021-11-03 a 2026-09-27 | 0,0 | Obrigatório. | `dateAdded` (R3) |
| `data_prazo_remediacao` | data | Prazo para correção. | ≥ data de inclusão | 2021-11-17 a 2026-09-30 | 0,0 | Obrigatório. | `dueDate` (R3) |
| `uso_ransomware` | booleano | Uso conhecido por ransomware. | true/false | True: 361, False: 1.367 | 0,0 | Obrigatório. | `knownRansomwareCampaignUse` (R3) |
| `triagem_forense` | booleano | Recomendação de triagem forense. | true/false | True: 69, False: 1.659 | 0,0 | Obrigatório. | `forensicTriage` |
| `cwes_kev` | lista de texto | CWEs atribuídas pela CISA. | códigos CWE | listas com 0 a 4 itens | 0,0 | Lista pode ser vazia. | `cwes` |
| `descricao` | texto | Descrição curta. | texto | 1.640 valores distintos | 0,0 | Obrigatório. | `shortDescription` |
| `acao_requerida` | texto | Ação exigida. | texto | 46 valores distintos | 0,0 | Obrigatório. | `requiredAction` |
| `versao_catalogo` | texto | Versão do catálogo coletada. | AAAA.MM.DD | 2026.09.27 | 0,0 | Obrigatório. | `catalogVersion` |
| `prazo_remediacao_dias` | inteiro | Dias até o prazo. | 0 a 365 | 1 a 184 | 0,0 | Obrigatório. | `dueDate − dateAdded` |

## `silver.nvd_cve`

Atributos das CVEs no NVD — 1 linha por CVE (escopos KEV e 2024 consolidados, R7).  
**Linhas:** 42.272

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `cve_id` | texto | Identificador da CVE. | padrão CVE | 42.272 valores distintos | 0,0 | Obrigatório, único. | `id` (R1) |
| `data_publicacao` | data | Publicação no NVD (UTC). | 1988 a data da coleta | 2002-06-25 a 2026-09-27 | 0,0 | Obrigatório. | `published` |
| `ultima_modificacao_nvd` | timestamp | Última alteração do registro. | ≤ data da coleta | 2024-01-02 16:15:12.337000 a 2026-09-28 13:17:25.027000 | 0,0 | Obrigatório. | `lastModified` |
| `status_nvd` | texto | Situação da análise. | ver fato | Analyzed, Deferred, Modified, Rejected, Undergoing Analysis | 0,0 | Obrigatório. | `vulnStatus` |
| `fonte_cna` | texto | Organização emissora (CNA). | texto/e-mail/UUID | 316 valores distintos | 0,0 | Obrigatório. | `sourceIdentifier` |
| `cvss_score` | decimal | Nota CVSS escolhida. | 0 a 10 | 0 a 10 | 1,8 | Nulo = sem nota. | R4 |
| `cvss_versao` | texto | Versão do CVSS. | 2.0, 3.0, 3.1, 4.0 | 3.0, 3.1, 4.0 | 1,8 | Nulo = sem nota. | R4 |
| `cvss_origem` | texto | NVD ou CNA. | NVD, CNA | CNA, NVD | 1,8 | Nulo = sem nota. | R4 |
| `cvss_vetor` | texto | Vetor CVSS completo. | `CVSS:3.1/AV:…` | 1.205 valores distintos | 1,8 | Nulo = sem nota. | R4 |
| `faixa_severidade` | texto | Faixa qualitativa. | ver dim_severidade | Alta, Baixa, Crítica, Média, Nenhuma, Sem pontuação | 0,0 | Obrigatório. | R5 |
| `cwe_principal` | texto | CWE principal pelo NVD. | CWE-N ou código NVD | 468 valores distintos | 2,1 | Nulo = sem fraqueza informada. | R6 |
| `cwes_nvd` | lista de texto | Todas as CWEs informadas. | códigos CWE | listas com 0 a 7 itens | 2,1 | Nulo = sem fraqueza. | `weaknesses[].description[].value` |
| `descricao_en` | texto | Descrição em inglês. | texto | 39.858 valores distintos | 0,0 | Obrigatório. | `descriptions[lang='en']` |
| `data_inclusao_kev_nvd` | data | Inclusão no KEV segundo o NVD (conferência). | ≥ 2021-11-03 | 2021-11-03 a 2026-09-27 | 95,9 | Nulo = fora do KEV. | `cisaExploitAdd` |
| `no_escopo_kev` | booleano | Coletada pela consulta `hasKev`. | true/false | True: 1.728, False: 40.544 | 0,0 | Obrigatório. | R7 |
| `no_escopo_2024` | booleano | Coletada pela consulta de publicadas em 2024. | true/false | True: 40.704, False: 1.568 | 0,0 | Obrigatório. | R7 |

## `silver.epss`

Scores EPSS em formato longo — 1 linha por CVE por snapshot.  
**Linhas:** 651.989

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `cve_id` | texto | Identificador da CVE. | padrão CVE | 391.757 valores distintos | 0,0 | Obrigatório. | `cve` (R1) |
| `epss` | decimal | Probabilidade de exploração nos próximos 30 dias. | 0 a 1 | 0,00042 a 0,99999 | 0,0 | Obrigatório. | `epss` (R8) |
| `percentil` | decimal | Posição relativa entre todas as CVEs. | 0 a 1 | 0 a 1 | 0,0 | Obrigatório. | `percentile` (R8) |
| `data_referencia` | data | Data do score. | 2025-01-01 ou dia da coleta | 2025-01-01 a 2026-09-28 | 0,0 | Obrigatório. | Cabeçalho `score_date` |
| `versao_modelo` | texto | Versão do modelo EPSS. | vAAAA.MM.DD | v2023.03.01, v2026.06.15 | 0,0 | Obrigatório. | Cabeçalho `model_version` |
| `snapshot` | texto | Qual arquivo. | corte, atual | atual, corte | 0,0 | Obrigatório. | Nome do arquivo |

## `silver.cwe`

Domínio de fraquezas (visão 1000 da MITRE + códigos especiais do NVD).  
**Linhas:** 946

| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |
|---|---|---|---|---|---|---|---|
| `cwe_id` | texto | Código. | CWE-N ou código NVD | 946 valores distintos | 0,0 | Obrigatório, único. | `CWE-ID` (R9) |
| `nome` | texto | Nome. | texto | 946 valores distintos | 0,0 | Obrigatório. | `Name` |
| `abstracao` | texto | Nível hierárquico. | Pillar … Especial NVD | Base, Class, Compound, Especial NVD, Pillar, Variant | 0,0 | Obrigatório. | `Weakness Abstraction` |
| `status` | texto | Maturidade. | Stable, Draft, Incomplete… | Draft, Incomplete, Stable | 0,2 | Nulo para códigos NVD. | `Status` |
| `descricao` | texto | Descrição (inglês). | texto | 944 valores distintos | 0,2 | Nulo para códigos NVD. | `Description` |

## Tabelas Bronze (estrutura original das fontes)

| Tabela | Conteúdo | Observação |
|---|---|---|
| `bronze.manifesto_coleta` | URL, data UTC, bytes e SHA-256 de cada arquivo bruto | Base da linhagem |
| `bronze.kev_vulnerabilidades` | Campos do JSON da CISA, como publicados | + `_arquivo_origem`, `_ingerido_em` |
| `bronze.nvd_cve` | Objeto `cve` da API do NVD com todos os campos aninhados | + `escopo_coleta` (kev/pub2024) |
| `bronze.epss_scores` | `cve`, `epss`, `percentile` em texto | + `model_version`, `score_date`, `snapshot` |
| `bronze.cwe_catalogo` | 23 colunas do CSV da MITRE | nomes normalizados (Delta não aceita espaços) |
