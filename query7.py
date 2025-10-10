import requests
import pandas as pd
import time

BASE_URL = "https://vulnerabilityhistory.org/api"

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

        return vulnerabilities, tags_map

    except requests.exceptions.RequestException as e:
        print(f"\n--- ERRO FATAL AO BUSCAR DADOS DA API: {e} ---")
        return None, None

def run_task_1_and_2(vulnerabilities):
    print("\n--- Iniciando Tarefa 1 & 2: Contagem de Vulnerabilidades por Projeto ---")
    
    project_counts = {}
    for vuln in vulnerabilities:
        project_name = vuln.get('project_name', 'N/A')
        
        if project_name not in project_counts:
            project_counts[project_name] = {
                'Projeto': project_name,
                'Vulnerabilidades Totais Documentadas': 0,
                'Vulnerabilidades Curadas': 0
            }
        
        project_counts[project_name]['Vulnerabilidades Totais Documentadas'] += 1
        
        if vuln.get('description'):
            project_counts[project_name]['Vulnerabilidades Curadas'] += 1
            
    df = pd.DataFrame(list(project_counts.values()))
    filename = "1_2_vulnerabilidades_por_projeto.xlsx"
    df.to_excel(filename, index=False)
    print(f"-> Sucesso! Arquivo '{filename}' gerado.")

def run_task_3_and_4(vulnerabilities, tags_map):
    print("\n--- Iniciando Tarefa 3 & 4: Vulnerabilidades por Tipo e por Lição ---")

    types_by_project = {}
    lessons_by_project = {}

    for vuln in vulnerabilities:
        project_name = vuln.get('project_name', 'N/A')
        
        if project_name not in types_by_project:
            types_by_project[project_name] = {}
        if project_name not in lessons_by_project:
            lessons_by_project[project_name] = {}
            
        tag_ids = [str(tag['id']) for tag in vuln.get('tag_json', [])]
        
        for tag_id in tag_ids:
            tag_info = tags_map.get(tag_id)
            if tag_info:
                tag_name = tag_info.get('name', 'Tag Desconhecida')
                
                types_by_project[project_name][tag_name] = types_by_project[project_name].get(tag_name, 0) + 1
                
                if tag_name.startswith('Lesson:'):
                    lesson_name = tag_name.replace('Lesson: ', '').strip()
                    lessons_by_project[project_name][lesson_name] = lessons_by_project[project_name].get(lesson_name, 0) + 1

    df_types = pd.DataFrame.from_dict(types_by_project, orient='index').fillna(0).astype(int)
    df_types = df_types.rename_axis('Projeto').reset_index()
    filename_types = "3_vulnerabilidades_por_tipo.xlsx"
    df_types.to_excel(filename_types, index=False)
    print(f"-> Sucesso! Arquivo '{filename_types}' gerado.")
    
    df_lessons = pd.DataFrame.from_dict(lessons_by_project, orient='index').fillna(0).astype(int)
    df_lessons = df_lessons.rename_axis('Projeto').reset_index()
    filename_lessons = "4_vulnerabilidades_por_licao.xlsx"
    df_lessons.to_excel(filename_lessons, index=False)
    print(f"-> Sucesso! Arquivo '{filename_lessons}' gerado.")

def run_task_5_text_analysis(corpus_data):
    print("\n--- Iniciando Tarefa 5: Análise de Texto da Documentação ---")
    
    text_data = []
    for item in corpus_data:
        description = item.get('description', '') or ''
        mistakes = item.get('mistakes', '') or ''
        
        full_text = (description.strip() + " " + mistakes.strip()).strip()
        
        if full_text:
            text_data.append({
                'Projeto': item.get('project_name', 'N/A'),
                'CVE': item.get('cve', 'N/A'),
                'Caracteres Totais': len(full_text),
                'Palavras Totais (Tokens)': len(full_text.split())
            })
            
    df = pd.DataFrame(text_data)
    filename = "5_analise_texto_documentacao.xlsx"
    df.to_excel(filename, index=False)
    print(f"-> Sucesso! Arquivo '{filename}' gerado.")


if __name__ == "__main__":
    all_vulnerabilities, all_tags_map = get_all_data()
    
    if all_vulnerabilities and all_tags_map:
        run_task_1_and_2(all_vulnerabilities)
        time.sleep(1)
        run_task_3_and_4(all_vulnerabilities, all_tags_map)
        time.sleep(1)
        run_task_5_text_analysis(all_vulnerabilities)
        
        print("\n[SUCESSO] Todas as tarefas foram concluidas!")
    else:
        print("\n[ERRO] Nao foi possivel obter os dados da API. O script nao pode continuar.")