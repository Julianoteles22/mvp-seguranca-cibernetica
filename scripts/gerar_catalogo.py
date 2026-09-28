# -*- coding: utf-8 -*-
"""
Gera catalogo/catalogo_de_dados.md.

As descrições, domínios declarados, obrigatoriedade e linhagem de cada atributo são mantidos
aqui (METADADOS). Os valores observados — mínimo, máximo, categorias encontradas e % de nulos —
são lidos das tabelas produzidas pelo pipeline (dados/tabelas/*.parquet, gerados na execução
local), de modo que o catálogo reflete sempre os dados efetivamente carregados.

    python scripts/gerar_catalogo.py
"""
import json
import os

import pandas as pd

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TABELAS = os.path.join(RAIZ, "dados", "tabelas")
SAIDA = os.path.join(RAIZ, "catalogo", "catalogo_de_dados.md")

# (nome, tipo, descrição, domínio declarado, obrigatoriedade / significado do nulo, linhagem)
METADADOS = {
    "gold.fato_vulnerabilidade": {
        "descricao": "Tabela fato. **Grão: uma linha por CVE.** Reúne as CVEs do catálogo KEV (todas) e as "
                     "CVEs publicadas em 2024 no NVD (exceto as rejeitadas — R11).",
        "colunas": [
            ("cve_id", "texto", "Identificador da vulnerabilidade (dimensão degenerada / chave natural).",
             "padrão `CVE-AAAA-NNNN…`", "Obrigatório, único.", "NVD `cve.id` ⊕ KEV `cveID` (R1, R12)"),
            ("sk_data_publicacao", "inteiro", "Chave para `dim_data` no papel *data de publicação* no NVD.",
             "AAAAMMDD ou -1", "Obrigatório; -1 = sem data (CVE só no KEV).", "NVD `published` → DATE UTC (R14)"),
            ("sk_data_inclusao_kev", "inteiro", "Chave para `dim_data` no papel *data de inclusão no KEV* "
             "(confirmação de exploração ativa pela CISA).", "AAAAMMDD ou -1",
             "Obrigatório; -1 = não está no KEV.", "KEV `dateAdded` (R3, R14)"),
            ("sk_data_prazo_kev", "inteiro", "Chave para `dim_data` no papel *prazo de correção* exigido pela CISA "
             "às agências federais dos EUA.", "AAAAMMDD ou -1", "Obrigatório; -1 = não está no KEV.",
             "KEV `dueDate` (R3, R14)"),
            ("sk_produto", "inteiro", "Chave para `dim_produto` (fornecedor e produto afetados).",
             "≥ 1 ou -1", "Obrigatório; -1 = fora do KEV (o NVD não traz fornecedor sem interpretar CPEs).",
             "KEV `vendorProject`, `product` (R2, R14)"),
            ("sk_cwe", "inteiro", "Chave para `dim_cwe` (classe de fraqueza principal).", "≥ 1 ou -1",
             "Obrigatório; -1 = nenhuma CWE informada por NVD nem CISA.", "NVD `weaknesses` / KEV `cwes` (R6, R13)"),
            ("sk_severidade", "inteiro", "Chave para `dim_severidade` (faixa CVSS).", "-1 a 4",
             "Obrigatório; -1 = sem nota CVSS.", "Calculada de `cvss_score` (R5)"),
            ("cvss_score", "decimal", "Nota-base CVSS escolhida pela regra de precedência R4.", "0,0 a 10,0",
             "Opcional; nulo = nenhuma nota publicada nem pelo NVD nem pelo CNA.",
             "NVD `metrics.cvssMetricV31/V30/V40/V2[].cvssData.baseScore` (R4)"),
            ("cvss_versao", "texto", "Versão do CVSS da nota escolhida.", "2.0, 3.0, 3.1, 4.0",
             "Nulo quando `cvss_score` é nulo.", "Nome do campo de métrica de origem (R4)"),
            ("cvss_origem", "texto", "Quem atribuiu a nota: o próprio NVD (*Primary*) ou o CNA emissor (*Secondary*).",
             "NVD, CNA", "Nulo quando `cvss_score` é nulo.", "NVD `metrics.*[].type` (R4)"),
            ("status_nvd", "texto", "Situação da análise da CVE no NVD na data da coleta.",
             "Received, Awaiting Analysis, Undergoing Analysis, Analyzed, Modified, Deferred, Rejected",
             "Nulo apenas para CVE do KEV ausente do NVD.", "NVD `vulnStatus`"),
            ("em_kev", "booleano", "A CVE consta do catálogo KEV (exploração ativa confirmada).", "true/false",
             "Obrigatório.", "Existência de `dateAdded` no KEV"),
            ("uso_ransomware", "booleano", "A CISA registra uso conhecido em campanhas de ransomware.", "true/false",
             "Obrigatório; false também para CVEs fora do KEV.", "KEV `knownRansomwareCampaignUse = 'Known'` (R3)"),
            ("triagem_forense", "booleano", "A CISA recomenda triagem forense além da correção.", "true/false",
             "Obrigatório; false fora do KEV.", "KEV `forensicTriage = 'Yes'`"),
            ("publicada_no_ano_coorte", "booleano", "CVE publicada no NVD em 2024 (coorte das perguntas P3–P5).",
             "true/false", "Obrigatório.", "`year(data_publicacao) = 2024`"),
            ("dias_publicacao_ate_kev", "inteiro", "Dias entre a publicação no NVD e a inclusão no KEV. Negativo "
             "quando a exploração foi confirmada antes da publicação.", "inteiro; negativo admitido",
             "Nulo fora do KEV.", "`dateAdded − published`"),
            ("prazo_remediacao_dias", "inteiro", "Dias concedidos pela CISA para a correção, a partir da inclusão.",
             "0 a 365", "Nulo fora do KEV.", "`dueDate − dateAdded`"),
            ("epss_corte", "decimal", "Probabilidade EPSS de exploração em 30 dias, **como publicada em 01/01/2025** "
             "(modelo v2023.03.01).", "0 a 1", "Nulo = CVE sem score nessa data.",
             "FIRST `epss_scores-2025-01-01.csv.gz` (R8)"),
            ("percentil_epss_corte", "decimal", "Percentil do EPSS de corte entre todas as CVEs pontuadas.", "0 a 1",
             "Nulo junto com `epss_corte`.", "idem"),
            ("epss_atual", "decimal", "Probabilidade EPSS na data da coleta (modelo vigente).", "0 a 1",
             "Nulo = CVE sem score atual.", "FIRST `epss_scores-current.csv.gz` (R8)"),
            ("percentil_epss_atual", "decimal", "Percentil do EPSS atual.", "0 a 1", "Nulo junto com `epss_atual`.", "idem"),
            ("explorada_apos_corte", "booleano", "Entrou no KEV depois de 01/01/2025 (desfecho da P3).", "true/false",
             "Obrigatório.", "`dateAdded > 2025-01-01` (R15)"),
            ("na_populacao_p3", "booleano", "Pertence à população da avaliação prospectiva da P3.", "true/false",
             "Obrigatório.", "Regra R15"),
        ],
    },
    "gold.dim_data": {
        "descricao": "Calendário. Dimensão com três **papéis** na fato: publicação, inclusão no KEV e prazo.",
        "colunas": [
            ("sk_data", "inteiro", "Chave substituta no formato AAAAMMDD.", "AAAAMMDD ou -1", "Obrigatório, único.", "Gerada"),
            ("data", "data", "Data do calendário.", "da menor à maior data da fato", "Nulo só no membro -1.",
             "`sequence()` entre a menor e a maior data da fato"),
            ("ano", "inteiro", "Ano.", "—", "Nulo só no membro -1.", "Derivado de `data`"),
            ("trimestre", "inteiro", "Trimestre.", "1 a 4", "Nulo só no membro -1.", "Derivado de `data`"),
            ("mes", "inteiro", "Mês.", "1 a 12", "Nulo só no membro -1.", "Derivado de `data`"),
            ("nome_mes", "texto", "Nome do mês em português.", "janeiro … dezembro, Não informada", "Obrigatório.", "Derivado"),
            ("dia_semana", "texto", "Dia da semana em português.", "domingo … sábado, Não informada", "Obrigatório.", "Derivado"),
            ("fim_de_semana", "booleano", "Sábado ou domingo.", "true/false", "Nulo só no membro -1.", "Derivado"),
        ],
    },
    "gold.dim_produto": {
        "descricao": "Pares fornecedor/produto afetados, conforme nomenclatura da CISA no KEV.",
        "colunas": [
            ("sk_produto", "inteiro", "Chave substituta.", "≥ 1 ou -1", "Obrigatório, único.", "`row_number()` ordenado"),
            ("fornecedor", "texto", "Fornecedor ou projeto (ex.: Microsoft, Apache).", "texto sem espaços nas pontas",
             "Obrigatório.", "KEV `vendorProject` + `trim` (R2)"),
            ("produto", "texto", "Produto afetado (ex.: Windows, Exchange Server).", "texto sem espaços nas pontas",
             "Obrigatório.", "KEV `product` + `trim` (R2)"),
        ],
    },
    "gold.dim_cwe": {
        "descricao": "Classes de fraqueza de software (Common Weakness Enumeration, MITRE).",
        "colunas": [
            ("sk_cwe", "inteiro", "Chave substituta.", "≥ 1 ou -1", "Obrigatório, único.", "`row_number()` ordenado"),
            ("cwe_id", "texto", "Código da fraqueza.", "`CWE-N`, `NVD-CWE-noinfo`, `NVD-CWE-Other`",
             "Obrigatório.", "MITRE `CWE-ID` com prefixo (R9) ⊕ IDs referenciados pelo NVD/KEV"),
            ("nome", "texto", "Nome oficial da fraqueza (em inglês, como publicado pela MITRE).", "texto",
             "Obrigatório.", "MITRE `Name`"),
            ("abstracao", "texto", "Nível na hierarquia CWE.",
             "Pillar, Class, Base, Variant, Compound, Especial NVD, Fora da visão 1000, Não informado",
             "Obrigatório.", "MITRE `Weakness Abstraction`"),
            ("status", "texto", "Maturidade da definição na MITRE.", "Stable, Draft, Incomplete, Deprecated",
             "Nulo para códigos especiais e IDs fora da visão 1000.", "MITRE `Status`"),
        ],
    },
    "gold.dim_severidade": {
        "descricao": "Faixas qualitativas de severidade com os limites do CVSS v3 (domínio fixo).",
        "colunas": [
            ("sk_severidade", "inteiro", "Chave substituta.", "-1 a 4", "Obrigatório, único.", "Domínio fixo"),
            ("faixa", "texto", "Nome da faixa.", "Sem pontuação, Nenhuma, Baixa, Média, Alta, Crítica", "Obrigatório.",
             "Especificação CVSS v3.1, seção 5"),
            ("score_minimo", "decimal", "Limite inferior da faixa.", "0,0 a 9,0", "Nulo para 'Sem pontuação'.", "idem"),
            ("score_maximo", "decimal", "Limite superior da faixa.", "0,0 a 10,0", "Nulo para 'Sem pontuação'.", "idem"),
            ("ordem", "inteiro", "Ordem de exibição.", "0 a 5", "Obrigatório.", "Domínio fixo"),
        ],
    },
    "silver.kev": {
        "descricao": "Catálogo KEV tipado e padronizado — 1 linha por CVE.",
        "colunas": [
            ("cve_id", "texto", "Identificador da CVE.", "padrão CVE", "Obrigatório, único.", "`cveID` (R1)"),
            ("fornecedor", "texto", "Fornecedor/projeto.", "texto", "Obrigatório.", "`vendorProject` (R2)"),
            ("produto", "texto", "Produto.", "texto", "Obrigatório.", "`product` (R2)"),
            ("nome_vulnerabilidade", "texto", "Nome dado pela CISA.", "texto", "Obrigatório.", "`vulnerabilityName`"),
            ("data_inclusao_kev", "data", "Inclusão no catálogo.", "≥ 2021-11-03 e ≤ data da coleta", "Obrigatório.", "`dateAdded` (R3)"),
            ("data_prazo_remediacao", "data", "Prazo para correção.", "≥ data de inclusão", "Obrigatório.", "`dueDate` (R3)"),
            ("uso_ransomware", "booleano", "Uso conhecido por ransomware.", "true/false", "Obrigatório.",
             "`knownRansomwareCampaignUse` (R3)"),
            ("triagem_forense", "booleano", "Recomendação de triagem forense.", "true/false", "Obrigatório.", "`forensicTriage`"),
            ("cwes_kev", "lista de texto", "CWEs atribuídas pela CISA.", "códigos CWE", "Lista pode ser vazia.", "`cwes`"),
            ("descricao", "texto", "Descrição curta.", "texto", "Obrigatório.", "`shortDescription`"),
            ("acao_requerida", "texto", "Ação exigida.", "texto", "Obrigatório.", "`requiredAction`"),
            ("versao_catalogo", "texto", "Versão do catálogo coletada.", "AAAA.MM.DD", "Obrigatório.", "`catalogVersion`"),
            ("prazo_remediacao_dias", "inteiro", "Dias até o prazo.", "0 a 365", "Obrigatório.", "`dueDate − dateAdded`"),
        ],
    },
    "silver.nvd_cve": {
        "descricao": "Atributos das CVEs no NVD — 1 linha por CVE (escopos KEV e 2024 consolidados, R7).",
        "colunas": [
            ("cve_id", "texto", "Identificador da CVE.", "padrão CVE", "Obrigatório, único.", "`id` (R1)"),
            ("data_publicacao", "data", "Publicação no NVD (UTC).", "1988 a data da coleta", "Obrigatório.", "`published`"),
            ("ultima_modificacao_nvd", "timestamp", "Última alteração do registro.", "≤ data da coleta", "Obrigatório.", "`lastModified`"),
            ("status_nvd", "texto", "Situação da análise.", "ver fato", "Obrigatório.", "`vulnStatus`"),
            ("fonte_cna", "texto", "Organização emissora (CNA).", "texto/e-mail/UUID", "Obrigatório.", "`sourceIdentifier`"),
            ("cvss_score", "decimal", "Nota CVSS escolhida.", "0 a 10", "Nulo = sem nota.", "R4"),
            ("cvss_versao", "texto", "Versão do CVSS.", "2.0, 3.0, 3.1, 4.0", "Nulo = sem nota.", "R4"),
            ("cvss_origem", "texto", "NVD ou CNA.", "NVD, CNA", "Nulo = sem nota.", "R4"),
            ("cvss_vetor", "texto", "Vetor CVSS completo.", "`CVSS:3.1/AV:…`", "Nulo = sem nota.", "R4"),
            ("faixa_severidade", "texto", "Faixa qualitativa.", "ver dim_severidade", "Obrigatório.", "R5"),
            ("cwe_principal", "texto", "CWE principal pelo NVD.", "CWE-N ou código NVD", "Nulo = sem fraqueza informada.", "R6"),
            ("cwes_nvd", "lista de texto", "Todas as CWEs informadas.", "códigos CWE", "Nulo = sem fraqueza.", "`weaknesses[].description[].value`"),
            ("descricao_en", "texto", "Descrição em inglês.", "texto", "Obrigatório.", "`descriptions[lang='en']`"),
            ("data_inclusao_kev_nvd", "data", "Inclusão no KEV segundo o NVD (conferência).", "≥ 2021-11-03",
             "Nulo = fora do KEV.", "`cisaExploitAdd`"),
            ("no_escopo_kev", "booleano", "Coletada pela consulta `hasKev`.", "true/false", "Obrigatório.", "R7"),
            ("no_escopo_2024", "booleano", "Coletada pela consulta de publicadas em 2024.", "true/false", "Obrigatório.", "R7"),
        ],
    },
    "silver.epss": {
        "descricao": "Scores EPSS em formato longo — 1 linha por CVE por snapshot.",
        "colunas": [
            ("cve_id", "texto", "Identificador da CVE.", "padrão CVE", "Obrigatório.", "`cve` (R1)"),
            ("epss", "decimal", "Probabilidade de exploração nos próximos 30 dias.", "0 a 1", "Obrigatório.", "`epss` (R8)"),
            ("percentil", "decimal", "Posição relativa entre todas as CVEs.", "0 a 1", "Obrigatório.", "`percentile` (R8)"),
            ("data_referencia", "data", "Data do score.", "2025-01-01 ou dia da coleta", "Obrigatório.", "Cabeçalho `score_date`"),
            ("versao_modelo", "texto", "Versão do modelo EPSS.", "vAAAA.MM.DD", "Obrigatório.", "Cabeçalho `model_version`"),
            ("snapshot", "texto", "Qual arquivo.", "corte, atual", "Obrigatório.", "Nome do arquivo"),
        ],
    },
    "silver.cwe": {
        "descricao": "Domínio de fraquezas (visão 1000 da MITRE + códigos especiais do NVD).",
        "colunas": [
            ("cwe_id", "texto", "Código.", "CWE-N ou código NVD", "Obrigatório, único.", "`CWE-ID` (R9)"),
            ("nome", "texto", "Nome.", "texto", "Obrigatório.", "`Name`"),
            ("abstracao", "texto", "Nível hierárquico.", "Pillar … Especial NVD", "Obrigatório.", "`Weakness Abstraction`"),
            ("status", "texto", "Maturidade.", "Stable, Draft, Incomplete…", "Nulo para códigos NVD.", "`Status`"),
            ("descricao", "texto", "Descrição (inglês).", "texto", "Nulo para códigos NVD.", "`Description`"),
        ],
    },
}


def observado(serie, nome=""):
    """Resumo do domínio observado de uma coluna."""
    s = serie.dropna()
    if nome.startswith("sk_data") and len(s):           # chaves AAAAMMDD: sem separador de milhar
        return f"{int(s.min())} a {int(s.max())}"
    if len(s) == 0:
        return "—"
    if s.map(lambda v: isinstance(v, (list, tuple)) or hasattr(v, "__len__") and not isinstance(v, str)).all():
        return f"listas com 0 a {int(s.map(len).max())} itens"
    if pd.api.types.is_bool_dtype(s) or set(map(str, s.unique())) <= {"True", "False"}:
        return ", ".join(f"{v}: {int((s == v).sum()):,}".replace(",", ".") for v in sorted(s.unique(), reverse=True))
    if pd.api.types.is_numeric_dtype(s):
        fmt = (lambda v: f"{v:,.0f}") if pd.api.types.is_integer_dtype(s) else (lambda v: f"{v:,.5g}")
        return f"{fmt(s.min())} a {fmt(s.max())}".replace(",", "X").replace(".", ",").replace("X", ".")
    try:
        if pd.api.types.is_datetime64_any_dtype(s) or hasattr(s.iloc[0], "isoformat"):
            return f"{min(s)} a {max(s)}"
    except TypeError:
        pass
    distintos = s.astype(str).unique()
    if len(distintos) <= 8:
        return ", ".join(sorted(distintos))
    return f"{len(distintos):,} valores distintos".replace(",", ".")


def gerar():
    manifesto = json.load(open(os.path.join(RAIZ, "dados", "landing", "_manifesto_coleta.json"), encoding="utf-8"))
    partes = [
        "# Catálogo de Dados\n",
        "> Gerado por `scripts/gerar_catalogo.py` a partir das tabelas carregadas. "
        f"Coleta de referência: **{manifesto['coleta_concluida_utc'][:10]}** (UTC). "
        "Regras R1–R15: ver notebooks `03_silver` e `04_gold`.\n",
        "## Como ler\n",
        "* **Domínio declarado** — o que se espera do atributo (verificado automaticamente no notebook `05_qualidade`).",
        "* **Domínio observado** — o que de fato existe nos dados carregados (mínimo–máximo, categorias ou contagem de distintos).",
        "* **Obrigatoriedade** — se o atributo admite nulo e **o que o nulo significa**.",
        "* **Linhagem** — campo de origem e regra de transformação aplicada.\n",
    ]
    for tabela, meta in METADADOS.items():
        camada, nome = tabela.split(".")
        arquivo = os.path.join(TABELAS, camada, f"{nome}.parquet")
        df = pd.read_parquet(arquivo) if os.path.exists(arquivo) else None
        n = len(df) if df is not None else "—"
        partes.append(f"## `{tabela}`\n")
        linhas_txt = f"{n:,}".replace(",", ".") if df is not None else "—"
        partes.append(f"{meta['descricao']}  \n**Linhas:** {linhas_txt}\n")
        partes.append("| Atributo | Tipo | Descrição | Domínio declarado | Domínio observado | % nulos | Obrigatoriedade | Linhagem |")
        partes.append("|---|---|---|---|---|---|---|---|")
        for col, tipo, desc, dom, obrig, lin in meta["colunas"]:
            if df is not None and col in df.columns:
                obs = observado(df[col], col)
                p_nulos = 100 * df[col].isna().mean()
                casas = 2 if 0 < p_nulos < 0.1 else 1
                nulos = f"{p_nulos:.{casas}f}".replace(".", ",")
            else:
                obs, nulos = "—", "—"
            partes.append(f"| `{col}` | {tipo} | {desc} | {dom} | {obs} | {nulos} | {obrig} | {lin} |")
        partes.append("")

    partes.append("## Tabelas Bronze (estrutura original das fontes)\n")
    partes.append("| Tabela | Conteúdo | Observação |\n|---|---|---|")
    partes.append("| `bronze.manifesto_coleta` | URL, data UTC, bytes e SHA-256 de cada arquivo bruto | Base da linhagem |")
    partes.append("| `bronze.kev_vulnerabilidades` | Campos do JSON da CISA, como publicados | + `_arquivo_origem`, `_ingerido_em` |")
    partes.append("| `bronze.nvd_cve` | Objeto `cve` da API do NVD com todos os campos aninhados | + `escopo_coleta` (kev/pub2024) |")
    partes.append("| `bronze.epss_scores` | `cve`, `epss`, `percentile` em texto | + `model_version`, `score_date`, `snapshot` |")
    partes.append("| `bronze.cwe_catalogo` | 23 colunas do CSV da MITRE | nomes normalizados (Delta não aceita espaços) |\n")

    with open(SAIDA, "w", encoding="utf-8") as f:
        f.write("\n".join(partes))
    print(f"Catálogo gerado: {SAIDA}")


if __name__ == "__main__":
    gerar()
