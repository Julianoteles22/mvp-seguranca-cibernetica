# Modelo de dados

## Arquitetura em camadas (medalhão) e linhagem

```mermaid
flowchart LR
    subgraph fontes ["Fontes públicas"]
        KEV["CISA KEV<br/>JSON"]
        NVD["NVD API 2.0<br/>JSON paginado"]
        EPSS["FIRST EPSS<br/>CSV.gz"]
        CWE["MITRE CWE<br/>CSV"]
    end
    subgraph landing ["Volume landing"]
        L[("arquivos brutos<br/>+ manifesto SHA-256")]
    end
    subgraph bronze ["ciber_bronze · estrutura original"]
        B1["kev_vulnerabilidades"]
        B2["nvd_cve"]
        B3["epss_scores"]
        B4["cwe_catalogo"]
        B5["manifesto_coleta"]
    end
    subgraph silver ["ciber_silver · flat por conceito"]
        S1["kev"]
        S2["nvd_cve"]
        S3["epss"]
        S4["cwe"]
    end
    subgraph gold ["ciber_gold · esquema estrela"]
        F[["fato_vulnerabilidade"]]
        D1["dim_data"]
        D2["dim_produto"]
        D3["dim_cwe"]
        D4["dim_severidade"]
        Q["qualidade_atributos<br/>qualidade_regras<br/>resumo_respostas"]
    end
    KEV --> L
    NVD --> L
    EPSS --> L
    CWE --> L
    L --> B1
    L --> B2
    L --> B3
    L --> B4
    L --> B5
    B1 -->|"R1–R3"| S1
    B2 -->|"R1, R4–R7"| S2
    B3 -->|"R1, R8"| S3
    B4 -->|"R9"| S4
    S1 -->|"R11–R13"| F
    S2 -->|"R11–R13"| F
    S3 -->|"R15"| F
    S1 --> D2
    S4 --> D3
    S1 --> D1
    S2 --> D1
    D4 --> F
    F --> Q
```

| Camada | Modelo | Carga | Propósito |
|---|---|---|---|
| landing | arquivos, como publicados | download (robô de coleta) | reprodutibilidade: bytes originais + hash |
| bronze | *flat* por fonte, estrutura original (inclusive aninhada) | leitura dos arquivos + colunas de linhagem | reprocessar sem baixar de novo |
| silver | *flat* por conceito (Data Lake), tipado e deduplicado | regras R1–R10 | base limpa e reutilizável |
| gold | **esquema estrela** (Data Warehouse) | regras R11–R15 | consultas analíticas das perguntas P1–P5 |

Todas as tabelas são sobrescritas a cada execução (carga completa e idempotente): o volume é
pequeno (≈ 42 mil CVEs) e isso elimina problemas de carga incremental num MVP.

## Esquema estrela (camada gold)

```mermaid
erDiagram
    fato_vulnerabilidade }o--|| dim_data : "sk_data_publicacao"
    fato_vulnerabilidade }o--|| dim_data : "sk_data_inclusao_kev"
    fato_vulnerabilidade }o--|| dim_data : "sk_data_prazo_kev"
    fato_vulnerabilidade }o--|| dim_produto : "sk_produto"
    fato_vulnerabilidade }o--|| dim_cwe : "sk_cwe"
    fato_vulnerabilidade }o--|| dim_severidade : "sk_severidade"

    fato_vulnerabilidade {
        string cve_id "chave natural (degenerada)"
        int sk_data_publicacao FK
        int sk_data_inclusao_kev FK
        int sk_data_prazo_kev FK
        int sk_produto FK
        int sk_cwe FK
        int sk_severidade FK
        double cvss_score
        string cvss_versao
        string cvss_origem
        string status_nvd
        boolean em_kev
        boolean uso_ransomware
        boolean triagem_forense
        boolean publicada_no_ano_coorte
        int dias_publicacao_ate_kev
        int prazo_remediacao_dias
        double epss_corte
        double percentil_epss_corte
        double epss_atual
        double percentil_epss_atual
        boolean explorada_apos_corte
        boolean na_populacao_p3
    }
    dim_data {
        int sk_data PK "AAAAMMDD"
        date data
        int ano
        int trimestre
        int mes
        string nome_mes
        string dia_semana
        boolean fim_de_semana
    }
    dim_produto {
        int sk_produto PK
        string fornecedor
        string produto
    }
    dim_cwe {
        int sk_cwe PK
        string cwe_id
        string nome
        string abstracao
        string status
    }
    dim_severidade {
        int sk_severidade PK
        string faixa
        double score_minimo
        double score_maximo
        int ordem
    }
```

### Decisões de modelagem

* **Grão da fato: uma linha por CVE.** Todas as perguntas são sobre vulnerabilidades individuais;
  um grão mais fino (CVE × produto afetado) exigiria interpretar CPEs do NVD e multiplicaria
  linhas sem ganho para P1–P5.
* **`dim_data` com três papéis** (*role-playing dimension*): publicação, inclusão no KEV e prazo
  de correção compartilham o mesmo calendário.
* **Membro `-1` em todas as dimensões** (R14): CVEs fora do KEV não têm fornecedor/produto nem
  datas de KEV; em vez de chave nula, apontam para "Não informado". A fato nunca tem chave nula,
  o que é verificado automaticamente no notebook `04_gold` (zero chaves órfãs).
* **EPSS como medida da fato, e não como dimensão**: é um valor contínuo com dois instantes
  (corte e atual), guardados como colunas — o formato mais simples para comparar os dois.
* **Esquema estrela, e não snowflake**: as dimensões são pequenas (≤ 9 mil linhas) e
  desnormalizá-las simplifica as consultas sem custo relevante de armazenamento.

O detalhamento de cada atributo (tipo, domínio, nulos e linhagem) está no
[Catálogo de Dados](catalogo_de_dados.md).
