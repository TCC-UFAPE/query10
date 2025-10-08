# Query10 - Análise de Vulnerabilidades e Commits

Sistema de análise de vulnerabilidades de segurança utilizando a API do Vulnerability History Project (VHP) e GitHub API.

## 📋 Descrição

Este projeto realiza análise detalhada de vulnerabilidades de software documentadas no VHP, incluindo análise de commits do GitHub relacionados às correções de segurança. Focado especialmente no projeto **SystemD**.

## 🚀 Funcionalidades

### Tarefa 1 & 2: Contagem de Vulnerabilidades por Projeto
- Conta vulnerabilidades totais documentadas por projeto
- Identifica vulnerabilidades curadas (com descrição)
- Gera: `1_2_vulnerabilidades_por_projeto.xlsx`

### Tarefa 3 & 4: Análise por Tipo e Lição
- Agrupa vulnerabilidades por tipo (tags)
- Agrupa por lições aprendidas
- Gera: `3_vulnerabilidades_por_tipo.xlsx` e `4_vulnerabilidades_por_licao.xlsx`

### Tarefa 5: Análise de Texto da Documentação
- Analisa descrições e erros documentados
- Conta caracteres e palavras (tokens)
- Gera: `5_analise_texto_documentacao.xlsx`

### Tarefa 6: Análise de Commits do GitHub (SystemD) ⭐ **NOVA**
Análise detalhada dos commits relacionados às vulnerabilidades do SystemD:

#### 📊 Dados Coletados:
- **Informações do Commit:**
  - Hash SHA-1 completo (40 caracteres)
  - Data do commit
  - Mensagem do commit
  - CVE relacionado
  - Repositório GitHub

- **Métricas de Código:**
  - Total de arquivos modificados
  - Linhas adicionadas (+)
  - Linhas deletadas (-)
  - Total de linhas modificadas
  - Total de tokens (palavras no diff)

- **Detalhes dos Arquivos:** ✨
  - Nome de cada arquivo modificado
  - **Tamanho do arquivo em bytes** (via GitHub Contents API)
  - Linhas adicionadas por arquivo
  - Linhas deletadas por arquivo
  - Status (modified, added, deleted, renamed)

#### 🔄 Processo de Coleta:

```
1. Busca vulnerabilidades do SystemD na API VHP
2. Extrai hashes de commits dos eventos (fix/vcc)
3. Para cada commit:
   └─ GET /repos/{owner}/{repo}/commits/{hash}
      ├─ Coleta: stats, files[], commit info
      └─ Para cada arquivo em files[]:
         └─ GET {contents_url}
            └─ Coleta: size (tamanho em bytes)
```

#### 📈 Estatísticas Geradas:
- Total de tokens analisados
- Total de linhas modificadas (adições + deleções)
- Total de arquivos modificados
- Tamanho total dos arquivos (bytes e MB)
- Médias por commit (tokens, linhas, arquivos, bytes)

**Arquivo gerado:** `6_analise_tokens_commits_systemd_github.xlsx`

## ⚙️ Configuração

### Pré-requisitos
```bash
pip install requests pandas openpyxl
```

### GitHub Token
O script usa a variável de ambiente `GITHUB_TOKEN` para autenticar as requisições ao GitHub (não é necessário editar o arquivo fonte).

1. Acesse: https://github.com/settings/tokens
2. Gere um token com permissões de leitura de repositórios públicos (repo: public_repo ou apenas public access)
3. Configure a variável de ambiente:

Windows (PowerShell):
```powershell
setx GITHUB_TOKEN "seu_token_aqui"
# Feche e reabra o terminal para que a variável entre em vigor
```

Linux/macOS:
```bash
export GITHUB_TOKEN="seu_token_aqui"
```

Depois de configurada, rode o script normalmente:
```bash
python query10.py
```

**Rate Limits:**
- Sem token: 60 requisições/hora
- Com token: 5000 requisições/hora ✅

## 🎯 Uso

Execute o script principal:
```bash
python query10.py
```

### Ativando/Desativando Tarefas

No final do arquivo `query10.py`, comente/descomente as tarefas desejadas:

```python
if __name__ == "__main__":
    all_vulnerabilities, all_tags_map, project_to_repo = get_all_data()
    
    if all_vulnerabilities and all_tags_map:
        # run_task_1_and_2(all_vulnerabilities)
        # run_task_3_and_4(all_vulnerabilities, all_tags_map)
        # run_task_5_text_analysis(all_vulnerabilities)
        run_task_6_commit_analysis(all_vulnerabilities, project_to_repo)  # ✅ Ativa
```

## 📁 Arquivos Gerados

| Arquivo | Descrição |
|---------|-----------|
| `1_2_vulnerabilidades_por_projeto.xlsx` | Contagem por projeto |
| `3_vulnerabilidades_por_tipo.xlsx` | Agrupamento por tags |
| `4_vulnerabilidades_por_licao.xlsx` | Agrupamento por lições |
| `5_analise_texto_documentacao.xlsx` | Análise textual |
| `6_analise_tokens_commits_systemd_github.xlsx` | **Análise detalhada de commits do SystemD** |

## 📊 Exemplo de Dados - Tarefa 6

### Estrutura do Excel Gerado:

| Projeto | CVE | Commit Hash | Data | Arquivos | Adições | Deleções | Tokens | Tamanho Total (bytes) | Arquivos Modificados |
|---------|-----|-------------|------|----------|---------|----------|--------|-----------------------|---------------------|
| systemd | CVE-2018-XXXX | a6aadf4... | 2018-08-08 | 2 | 11 | 5 | 350 | 45678 | journald-syslog.c (15000 bytes, +3/-3), test-journal-syslog.c (8500 bytes, +8/-2) |

## ⚠️ Considerações Importantes

### Performance
- **Tempo estimado** (SystemD com 276 commits): 5-10 minutos
- Pausas automáticas para respeitar rate limit
- 0.1s entre requisições de `contents_url`
- 0.5s a cada 10 commits processados

### Rate Limit
Para 276 commits com média de 2 arquivos cada:
- **Requisições necessárias:** ~828 (276 commits + 552 arquivos)
- **Com token:** Bem dentro do limite de 5000/hora ✅

### Tratamento de Erros
- Commits não encontrados (404): Contabilizados mas não processados
- Falha em `contents_url`: Arquivo marcado com size=0, processamento continua
- Timeouts: Registrados no log, commit pulado

## 🔍 APIs Utilizadas

- **VHP API:** https://vulnerabilityhistory.org/api
  - `/vulnerabilities`: Lista todas as vulnerabilidades
  - `/vulnerabilities/{cve}/events`: Eventos de cada CVE
  - `/tags`: Mapeamento de tags
  - `/projects`: Informações dos projetos

- **GitHub API:** https://api.github.com
  - `/repos/{owner}/{repo}/commits/{sha}`: Detalhes do commit
  - `/repos/{owner}/{repo}/contents/{path}?ref={sha}`: Tamanho dos arquivos

## 📝 Logs e Debug

O script exibe logs detalhados durante a execução:
- Projetos mapeados para GitHub
- Verificação do repositório SystemD
- Progresso de processamento (a cada 25 commits)
- Sucessos vs Erros
- Estatísticas finais completas

**Debug mode:** Os primeiros 3 commits são processados em modo debug, mostrando:
- URL da requisição
- Status code
- Rate limit remaining
- Número de arquivos processados

## 🛠️ Estrutura do Código

```
query10.py
├── get_all_data()                           # Busca dados das APIs
├── get_commit_hashes_from_vulnerabilities() # Extrai hashes dos eventos
├── get_github_commit_data()                 # Busca dados do commit no GitHub
├── count_tokens_from_github_commit()        # Analisa arquivos e busca tamanhos
└── run_task_6_commit_analysis()             # Orquestra análise completa
```

## 📚 Documentação Adicional

- `LEIA-ME.md`: Documentação em português
- `LEIA-ME-SYSTEMD.md`: Guia específico para análise do SystemD
- `DEBUG_GUIDE.md`: Guia de solução de problemas

## 🤝 Contribuindo

Este projeto faz parte de um TCC (Trabalho de Conclusão de Curso) da UFAPE.

## 📄 Licença

[Incluir informações de licença se aplicável]

---

**Desenvolvido para análise de vulnerabilidades de segurança em software open source.** 