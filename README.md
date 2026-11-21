# Advanced-network-fingerprinter
# 🛡️ Advanced Network Recon &amp; Asset Fingerprinter 
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green) 
![Category]([suspicious link removed])

## 📌 Visão Geral do Projeto 
- O Advanced Network Recon &amp; Asset Fingerprinter\*\* é uma ferramenta desenvolvida em Python 3 para automação de auditorias de conectividade, varreduras concorrentes de portas TCP e fingerprinting de serviços de rede. 
Desenvolvida para atuar na fase de \*\*Reconhecimento Ativo\*\* em auditorias de segurança e na \*\*Gestão de Ativos Expostos\*\* em equipes defensivas (Blue Team/SOC), a ferramenta realiza varredura de portas via arquitetura multi-threaded (\`Queue\` + \`threading\`), faz a leitura automatizada de banners de resposta e exporta relatórios auditáveis em \*\*JSON\*\* e \*\*Markdown\*\*. 

## 🚀 Funcionalidades Principais 
- Varredura Concorrente de Alto Desempenho\*\*: Processamento acelerado por \*multithreading\* com gerenciamento de filas \*thread-safe\* (\`queue.Queue\`) para evitar condições de corrida. -
- Fingerprinting &amp; Banner Grabbing\*\*: Leitura automatizada de cabeçalhos de serviços (HTTP, SSH, FTP, SMTP) para identificação preliminar de software e versões. - \*\*Tratamento de Exceções &amp; CLI Rígido\*\*: Interface de linha de comando baseada em \`argparse\`, com suporte a timeouts configuráveis e resolução automatizada de DNS.
- Exportação Estruturada de Relatórios\*\*: Geração automatizada de relatórios em formato JSON (para consumo por SIEM/APIs) e tabelas formatadas em Markdown.

## 📐 Alinhamento com o Framework NIST CSF 2.0 

Esta ferramenta apoia diretamente a função \*\*Identificar (Identify - ID)\*\* do \*NIST Cybersecurity Framework 2.0\*, atendendo às diretrizes da categoria \*\*Gestão de Ativos (Asset Management - ID.AM)\*\* ao automatizar o inventário dinâmico de portas e serviços expostos na infraestrutura.

## 💻 Como Executar

Pré-requisitos - Python 3.10 ou superior (Utiliza exclusivamente a biblioteca padrão do Python). Instalação e Execução \`\`\`bash # Clonar o repositório git clone [suspicious link removed] cd advanced-network-fingerprinter

# Exemplo 1:
Varredura padrão de portas comuns no localhost python3 recon\_fingerprinter.py -t 127.0.0.1 -p 1-1024 -T 100 
# Exemplo 2:
Varredura de portas específicas com exportação JSON python3 recon\_fingerprinter.py -t scanme.nmap.org -p 21,22,80,443,8080 -o json
