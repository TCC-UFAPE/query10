import os
import requests
import pandas as pd
import time
import re

BASE_URL = "https://vulnerabilityhistory.org/api"
GITHUB_API_BASE = "https://api.github.com"
GITHUB_TOKEN = "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"

def get_github_headers():
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'vuln-history-script/1.0'
    }
    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
    return headers


def request_with_retries(session, method, url, headers=None, timeout=30, max_retries=3, backoff_factor=0.5):
    """Faz uma requisição com retries exponenciais simples em erros de rede e 5xx.
    Retorna o objeto Response ou lança requests.exceptions.RequestException.
    """
    attempt = 0
    while True:
        try:
            resp = session.request(method, url, headers=headers, timeout=timeout)
            if 500 <= resp.status_code < 600 and attempt < max_retries:
                attempt += 1
                sleep_time = backoff_factor * (2 ** (attempt - 1))
                time.sleep(sleep_time)
                continue
            return resp
        except requests.exceptions.RequestException:
            if attempt >= max_retries:
                raise
            attempt += 1
            sleep_time = backoff_factor * (2 ** (attempt - 1))
            time.sleep(sleep_time)
            continue


def get_all_data():
    print("Iniciando busca de dados da API (isso pode levar um momento)...")
    try:
        session = requests.Session()
        
        print("Buscando todas as vulnerabilidades...")
        vuln_response = session.get(f"{BASE_URL}/vulnerabilities?limit=100000", timeout=180)
        vuln_response.raise_for_status()
        vulnerabilities = vuln_response.json()
        print(f"-> Encontradas {len(vulnerabilities)} vulnerabilidades.")
        
        print("Buscando mapa de tags...")
        tags_response = session.get(f"{BASE_URL}/tags?map=true", timeout=30)
        tags_response.raise_for_status()
        tags_map = tags_response.json()
        print(f"-> Encontradas {len(tags_map)} tags.")
        
        print("Buscando informações dos projetos...")
        projects_response = session.get(f"{BASE_URL}/projects", timeout=30)
        projects_response.raise_for_status()
        projects = projects_response.json()
        print(f"-> Encontrados {len(projects)} projetos.")
        
        # Criar mapeamento de projeto -> repositório GitHub
        project_to_repo = {}
        for project in projects:
            project_name = project.get('name', '')
            git_url_prefix = project.get('git_commit_url_prefix', '')
            
            # Extrair owner/repo da URL do GitHub (ex: https://github.com/django/django/commit/ -> django/django)
            github_match = re.search(r'github\.com/([^/]+/[^/]+)/', git_url_prefix)
            if github_match:
                repo_full_name = github_match.group(1)
                project_to_repo[project_name] = repo_full_name
        
        print(f"-> Mapeados {len(project_to_repo)} projetos para repositórios GitHub.")
        
        # Debug: mostrar projetos mapeados
        if project_to_repo:
            print(f"   Projetos com GitHub:")
            for proj_name, repo in sorted(project_to_repo.items()):
                print(f"     - {proj_name}: {repo}")

        return vulnerabilities, tags_map, project_to_repo

    except requests.exceptions.RequestException as e:
        print(f"\n--- ERRO FATAL AO BUSCAR DADOS DA API: {e} ---")
        return None, None, None
    
def get_commit_hashes_from_vulnerabilities(vulnerabilities, session):
    """Extrai todas as hashes de commits das vulnerabilidades através dos eventos"""
    print("\n--- Extraindo hashes de commits das vulnerabilidades ---")
    commit_hashes = set()
    vuln_to_commits = {}
    hash_lengths = {}  # Para debug: verificar tamanhos de hash
    
    for idx, vuln in enumerate(vulnerabilities):
        cve = vuln.get('cve', 'N/A')
        project_name = vuln.get('project_name', 'N/A')
        
        if (idx + 1) % 100 == 0:
            print(f"   Processando vulnerabilidade {idx + 1}/{len(vulnerabilities)}...")
        
        try:
            # Buscar eventos da vulnerabilidade
            events_response = session.get(f"{BASE_URL}/vulnerabilities/{cve}/events", timeout=30)
            events_response.raise_for_status()
            events = events_response.json()
            
            for event in events:
                # Verificar se é um evento de fix ou vcc
                event_type = event.get('event_type', '')
                if event_type in ['fix', 'vcc']:
                    # Extrair commit hash da descrição
                    description = event.get('description', '')
                    
                    # O commit hash geralmente está no link no formato /commits/{hash}
                    # Ajustado para capturar hashes SHA-1 completos (40 caracteres)
                    commit_match = re.search(r'/commits/([a-f0-9]{40})', description)
                    if commit_match:
                        commit_hash = commit_match.group(1)
                        commit_hashes.add(commit_hash)
                        
                        hash_len = len(commit_hash)
                        hash_lengths[hash_len] = hash_lengths.get(hash_len, 0) + 1
                        
                        if cve not in vuln_to_commits:
                            vuln_to_commits[cve] = {'project': project_name, 'commits': []}
                        vuln_to_commits[cve]['commits'].append(commit_hash)
            
            if (idx + 1) % 20 == 0:
                time.sleep(0.3)
                
        except requests.exceptions.RequestException as e:
            print(f"   [AVISO] Erro ao buscar eventos para {cve}: {e}")
            continue
    
    print(f"-> Encontradas {len(commit_hashes)} hashes únicas de commits.")
    if hash_lengths:
        print(f"   Tamanhos de hash encontrados: {hash_lengths}")
    return list(commit_hashes), vuln_to_commits

def get_github_commit_data(repo_full_name, commit_hash, session, debug=False):
    """Busca dados completos do commit no GitHub via API REST"""
    try:
        headers = get_github_headers()
        
        url = f"{GITHUB_API_BASE}/repos/{repo_full_name}/commits/{commit_hash}"
        
        if debug:
            print(f"\n   [DEBUG] Testando commit:")
            print(f"   URL: {url}")
            print(f"   Repo: {repo_full_name}")
            print(f"   Hash: {commit_hash}")
        
        response = request_with_retries(session, 'GET', url, headers=headers, timeout=30)

        remaining = response.headers.get('X-RateLimit-Remaining', 'N/A')
        
        if debug:
            print(f"   Status: {response.status_code}")
            print(f"   Rate Limit: {remaining}")

        if response.status_code == 401:
            # Token inválido/expirado ou formato inválido
            if GITHUB_TOKEN:
                print("   [ERRO] 401 Unauthorized: o token do GitHub parece inválido ou expirado. Verifique a variável de ambiente GITHUB_TOKEN.")
            else:
                print("   [ERRO] 401 Unauthorized: requisição sem token. Tente exportar GITHUB_TOKEN para aumentar limites/evitar bloqueios.")
            return None
        
        if response.status_code == 404:
            # Commit não encontrado - comum para commits antigos ou repositórios migrados
            if debug:
                print(f"   Erro: Commit não encontrado (404)")
            return None
        elif response.status_code == 403:
            # Pode ser rate limit ou acesso proibido
            print(f"   [AVISO] 403 Forbidden ou rate limit. Restantes: {remaining}. Se estiver autenticado, verifique escopos do token.")
            return None
        elif response.status_code == 422:
            # Commit hash inválido
            if debug:
                print(f"   Erro: Hash inválido (422)")
            return None

        response.raise_for_status()
        data = response.json()

        # Verificar se o retorno tem a estrutura esperada
        if 'commit' not in data:
            print(f"   [AVISO] Resposta inesperada para {commit_hash[:8]}: falta campo 'commit'")
            return None

        if debug:
            print(f"   ✓ Sucesso! Arquivos: {len(data.get('files', []))}")

        return data

    except requests.exceptions.Timeout:
        print(f"   [AVISO] Timeout ao buscar commit {commit_hash[:8]}")
        return None
    except requests.exceptions.RequestException as e:
        # Mostrar apenas primeiros 8 caracteres do hash para não poluir o log
        if debug:
            print(f"   [ERRO] {str(e)}")
        return None

def count_tokens_from_github_commit(commit_data, session):
    """Conta tokens (palavras) de todos os arquivos modificados no commit e obtém o tamanho via contents_url"""
    if not commit_data:
        return 0, 0, 0, 0, []
    
    # Usar stats para obter totais (mais confiável)
    stats = commit_data.get('stats', {})
    total_additions = stats.get('additions', 0)
    total_deletions = stats.get('deletions', 0)
    
    total_tokens = 0
    files = commit_data.get('files', [])
    total_files = len(files)
    file_details = []  # Lista para armazenar detalhes dos arquivos
    
    headers = get_github_headers()
    
    for file_info in files:
        # Extrair informações que já vêm na resposta do commit
        filename = file_info.get('filename', 'N/A')
        additions = file_info.get('additions', 0)
        deletions = file_info.get('deletions', 0)
        changes = file_info.get('changes', 0)
        status = file_info.get('status', 'N/A')
        
        # Buscar o tamanho do arquivo via contents_url
        contents_url = file_info.get('contents_url', '')
        file_size = 0
        
        if contents_url:
            try:
                contents_response = request_with_retries(session, 'GET', contents_url, headers=headers, timeout=10)
                if contents_response.status_code == 200:
                    contents_data = contents_response.json()
                    file_size = contents_data.get('size', 0)
                time.sleep(0.1)  # Pequena pausa entre requisições
            except:
                pass  # Se falhar, mantém size=0
        
        file_details.append({
            'filename': filename,
            'additions': additions,
            'deletions': deletions,
            'changes': changes,
            'status': status,
            'size': file_size
        })
        
        # Contar tokens no patch (diff)
        patch = file_info.get('patch', '')
        if patch:
            # Contar palavras/tokens no diff
            lines = patch.split('\n')
            for line in lines:
                # Ignorar linhas de cabeçalho do diff e linhas vazias
                if line and not line.startswith('@@') and not line.startswith('diff'):
                    # Remover primeiro caractere (+, -, espaço) se existir
                    clean_line = line[1:] if line and line[0] in ['+', '-', ' '] else line
                    # Contar palavras na linha
                    words = clean_line.split()
                    total_tokens += len(words)
    
    return total_additions, total_deletions, total_tokens, total_files, file_details


def fetch_contents_sizes_from_commit(commit_data, session, save_path=None):
    """Percorre commit_data['files'], coleta os valores de contents_url, faz GET em cada
    contents_url usando a mesma estratégia de headers e retries, e contabiliza o campo `size`.

    Args:
        commit_data (dict): JSON retornado pela API de commit do GitHub.
        session (requests.Session): sessão para realizar as requisições.
        save_path (str|None): caminho opcional para salvar um JSON com o mapeamento {contents_url: size}.

    Returns:
        tuple: (list_of_urls, mapping_url_to_size, total_size_bytes)
    """
    if not commit_data:
        return [], {}, 0

    files = commit_data.get('files', [])
    headers = get_github_headers()

    urls = []
    sizes = {}
    total = 0

    for f in files:
        url = f.get('contents_url')
        if not url:
            continue
        urls.append(url)
        try:
            resp = request_with_retries(session, 'GET', url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                size = data.get('size', 0) if isinstance(data, dict) else 0
            else:
                size = 0
        except Exception:
            size = 0

        sizes[url] = size
        total += size
        # pequena pausa para não sobrecarregar
        time.sleep(0.05)

    if save_path:
        try:
            import json
            with open(save_path, 'w', encoding='utf-8') as fh:
                json.dump({'urls': urls, 'sizes': sizes, 'total': total}, fh, indent=2)
        except Exception:
            pass

    return urls, sizes, total

def run_task_6_commit_analysis(vulnerabilities, project_to_repo):
    print("\n--- Iniciando Tarefa 6: Análise de Tokens dos Commits via API do GitHub ---")
    print("   [FILTRO ATIVO] Processando apenas commits do projeto SYSTEMD")
    
    session = requests.Session()
    
    systemd_vulns = [v for v in vulnerabilities if v.get('project_name', '').lower() == 'systemd' and (v.get('description') or '').strip()]
    print(f"   Vulnerabilidades do systemd: {len(systemd_vulns)} de {len(vulnerabilities)} totais")
    
    if not systemd_vulns:
        print("-> Nenhuma vulnerabilidade do systemd encontrada.")
        return
    
    # Verificar repositório mapeado para systemd
    systemd_repo = project_to_repo.get('systemd')
    print(f"   Repositório GitHub do systemd: {systemd_repo if systemd_repo else 'NÃO MAPEADO!'}")
    
    # Extrair hashes de commits apenas do systemd
    commit_hashes, vuln_to_commits = get_commit_hashes_from_vulnerabilities(systemd_vulns, session)
    
    if not commit_hashes:
        print("-> Nenhum commit encontrado nas vulnerabilidades do systemd.")
        return
    
    # Buscar detalhes dos commits no GitHub
    print(f"\nBuscando detalhes de {len(commit_hashes)} commits do systemd no GitHub...")
    print(f"   GitHub Token configurado: Rate limit de 5000 requisições/hora.")
    
    commit_data = []
    github_api_errors = 0
    commits_sem_repo = 0
    commits_sucesso = 0
    
    for idx, commit_hash in enumerate(commit_hashes):
        if (idx + 1) % 25 == 0:
            print(f"   Processando commit {idx + 1}/{len(commit_hashes)}... (Sucessos: {commits_sucesso}, Erros: {github_api_errors})")
        
        # Encontrar qual CVE e projeto este commit pertence
        cve_related = 'N/A'
        project_related = 'N/A'
        for cve, info in vuln_to_commits.items():
            if commit_hash in info['commits']:
                cve_related = cve
                project_related = info['project']
                break
        
        # Obter repositório GitHub do projeto
        repo_full_name = project_to_repo.get(project_related)

        if not repo_full_name:
            commits_sem_repo += 1
            # Mostrar exemplo breve nos primeiros commits para debug local
            if idx < 3:
                print(f"   [DEBUG] Commit {idx+1}: Projeto '{project_related}' sem repositório mapeado")
            continue

        # Buscar dados do commit no GitHub (processar todos sem modo debug)
        github_commit = get_github_commit_data(repo_full_name, commit_hash, session, debug=False)
        
        if github_commit and 'commit' in github_commit:
            # Contar tokens do diff e obter detalhes dos arquivos (incluindo tamanho via contents_url)
            additions, deletions, tokens, total_files, file_details = count_tokens_from_github_commit(github_commit, session)

            # Buscar sizes reais via contents_url e salvar mapeamento em JSON
            try:
                import os, json
                os.makedirs('commit_contents', exist_ok=True)
                urls, sizes_map, total_size_via_contents = fetch_contents_sizes_from_commit(github_commit, session)
                # criar pasta por CVE e salvar arquivo com nome do hash
                cve_safe = re.sub(r'[^A-Za-z0-9_.-]', '_', cve_related)
                dir_path = os.path.join('commit_contents', cve_safe)
                os.makedirs(dir_path, exist_ok=True)
                out_path = os.path.join(dir_path, f"{commit_hash}.json")
                with open(out_path, 'w', encoding='utf-8') as fh:
                    json.dump({
                        'commit': commit_hash,
                        'project': project_related,
                        'cve': cve_related,
                        'urls': urls,
                        'sizes': sizes_map,
                        'total_size': total_size_via_contents
                    }, fh, indent=2)
            except Exception:
                total_size_via_contents = sum(f['size'] for f in file_details)
            
            # Obter informações do commit
            commit_info = github_commit.get('commit', {})
            message = commit_info.get('message', '')
            author_info = commit_info.get('author', {})
            date = author_info.get('date', 'N/A')
            
            # Calcular tamanho total dos arquivos (usar o valor via contents_url quando disponível)
            total_file_size = total_size_via_contents if 'total_size_via_contents' in locals() else sum(f['size'] for f in file_details)
            
            # Formatar detalhes dos arquivos com tamanho
            files_summary = ', '.join([
                f"{f['filename']} ({f['size']} bytes, +{f['additions']}/-{f['deletions']})" 
                for f in file_details[:3]
            ])
            if len(file_details) > 3:
                files_summary += f" ... e mais {len(file_details) - 3} arquivos"
            
            commit_data.append({
                'Projeto': project_related,
                'CVE': cve_related,
                'Repositório GitHub': repo_full_name,
                'Commit Hash': commit_hash,
                'Data do Commit': date,
                'Total de Arquivos': total_files,
                'Total de Adições (Linhas)': additions,
                'Total de Deleções (Linhas)': deletions,
                'Total de Linhas Modificadas': additions + deletions,
                'Total de Tokens (Palavras no Diff)': tokens,
                'Tamanho Total dos Arquivos (bytes)': total_file_size,
                'Arquivos Modificados': files_summary,
                'Mensagem do Commit': message[:150]
            })
            commits_sucesso += 1
        else:
            github_api_errors += 1
        
        # Pausa para respeitar rate limit do GitHub (com token: ~1.4 req/segundo)
        if (idx + 1) % 10 == 0:
            time.sleep(0.5)
    
    # Relatório final
    print(f"\n--- Relatório de Processamento (SYSTEMD) ---")
    print(f"   Total de commits únicos do systemd: {len(commit_hashes)}")
    print(f"   Commits sem repositório GitHub: {commits_sem_repo}")
    print(f"   Commits processados com sucesso: {commits_sucesso}")
    print(f"   Commits com erro na API: {github_api_errors}")
    
    if commits_sucesso > 0:
        # Estatísticas adicionais
        total_tokens = sum(c['Total de Tokens (Palavras no Diff)'] for c in commit_data)
        total_lines = sum(c['Total de Linhas Modificadas'] for c in commit_data)
        total_files = sum(c['Total de Arquivos'] for c in commit_data)
        total_additions = sum(c['Total de Adições (Linhas)'] for c in commit_data)
        total_deletions = sum(c['Total de Deleções (Linhas)'] for c in commit_data)
        total_bytes = sum(c['Tamanho Total dos Arquivos (bytes)'] for c in commit_data)
        
        print(f"\n--- Estatísticas do SystemD ---")
        print(f"   Total de tokens analisados: {total_tokens:,}")
        print(f"   Total de linhas modificadas: {total_lines:,}")
        print(f"   Total de linhas adicionadas: {total_additions:,}")
        print(f"   Total de linhas deletadas: {total_deletions:,}")
        print(f"   Total de arquivos modificados: {total_files:,}")
        print(f"   Tamanho total dos arquivos: {total_bytes:,} bytes ({total_bytes/(1024*1024):.2f} MB)")
        print(f"   Média de tokens por commit: {total_tokens/commits_sucesso:.1f}")
        print(f"   Média de linhas por commit: {total_lines/commits_sucesso:.1f}")
        print(f"   Média de arquivos por commit: {total_files/commits_sucesso:.1f}")
        print(f"   Média de bytes por commit: {total_bytes/commits_sucesso:,.0f}")
    
    if len(commit_data) == 0:
        print(f"\n   [ALERTA] Nenhum commit foi processado com sucesso!")
        print(f"   Possíveis causas:")
        print(f"   - Commits não encontrados nos repositórios GitHub (404)")
        print(f"   - Hashes de commits incompletos ou inválidos")
        print(f"   - Rate limit excedido (verifique seu token)")
        print(f"   - Repositórios não mapeados corretamente")
    
    df = pd.DataFrame(commit_data)
    filename = "6_analise_tokens_commits_systemd_github.xlsx"
    df.to_excel(filename, index=False)
    print(f"\n-> Arquivo '{filename}' gerado com {len(commit_data)} commits do systemd analisados.")

if __name__ == "__main__":
    if not GITHUB_TOKEN:
        print("\n[ERRO] Variável de ambiente GITHUB_TOKEN não definida!")
        print("   O script precisa de um token para acessar a API do GitHub com limites maiores.")
        print("   Defina a variável e tente novamente.")
    else:
        print("Token do GitHub encontrado. Iniciando script...")
        all_vulnerabilities, all_tags_map, project_to_repo = get_all_data()
    
        if all_vulnerabilities and all_tags_map:
            run_task_6_commit_analysis(all_vulnerabilities, project_to_repo)
            print("\n[SUCESSO] Todas as tarefas foram concluídas!")
        else:
            print("\n[ERRO] Não foi possível obter os dados da API. O script não pode continuar.")
