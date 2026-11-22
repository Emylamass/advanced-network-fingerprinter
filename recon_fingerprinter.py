#!/usr/bin/env python3
"""
Ferramenta: Advanced Network Recon & Asset Fingerprinter
Descrição: Scanner de portas TCP multi-threaded com captura de banners e exportação de dados em JSON e Markdown.
Autor: Emilly Lamas
Uso: python3 recon_fingerprinter.py -t <ALVO> -p <PORTAS> -T <THREADS> -o <FORMATO>
"""

import socket
import threading
import argparse
import sys
import json
from queue import Queue
from datetime import datetime

# Mapeamento de serviços comuns para fallback de identificação
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

open_results = []
port_queue = Queue()
print_lock = threading.Lock()

def grab_banner(target_ip, port, timeout=2.0):
    """Realiza a captura de banner do serviço em execução na porta aberta."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        
        # Envia probe HTTP para portas web comuns ou probe genérico para outros serviços
        if port in (80, 8080, 8443):
            sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: NetworkScanner/1.0\r\n\r\n")
        else:
            sock.send(b"\r\n")
            
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()
        return banner if banner else "Sem banner de resposta"
    except Exception:
        return "Conexão estabelecida sem emissão de banner"

def worker_scan(target_ip, timeout):
    """Worker thread que consome portas da fila e verifica status de conexão."""
    while not port_queue.empty():
        port = port_queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            # connect_ex retorna 0 quando a conexão TCP é bem-sucedida
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            if result == 0:
                service_name = COMMON_SERVICES.get(port, "Desconhecido")
                banner_info = grab_banner(target_ip, port, timeout)
                
                asset_data = {
                    "port": port,
                    "protocol": "TCP",
                    "status": "OPEN",
                    "inferred_service": service_name,
                    "banner": banner_info
                }
                
                with print_lock:
                    open_results.append(asset_data)
                    print(f"[+] Porta {port:<5}/TCP | Serviço: {service_name:<12} | Banner: {banner_info[:50]}")
        except socket.error:
            pass
        finally:
            port_queue.task_done()

def export_reports(target, duration, output_format):
    """Gera arquivos de relatório estruturados em JSON e/ou Markdown."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_base = f"recon_{target.replace('.', '_')}_{timestamp}"
    
    summary_data = {
        "target": target,
        "scan_timestamp": datetime.now().isoformat(),
        "total_open_ports": len(open_results),
        "assets": open_results
    }
    
    if output_format in ("json", "both"):
        json_file = f"{report_base}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=4, ensure_ascii=False)
        print(f"[*] Relatório JSON exportado: {json_file}")
        
    if output_format in ("markdown", "both"):
        md_file = f"{report_base}.md"
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(f"# 🛡️ Relatório de Inventário de Ativos — {target}\n\n")
            f.write(f"- **Data da Varredura**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **Total de Portas Abertas**: {len(open_results)}\n\n")
            f.write("## 🔍 Detalhamento das Portas e Serviços Identificados\n\n")
            f.write("| Porta | Protocolo | Status | Serviço Presumido | Banner do Serviço |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- |\n")
            for item in sorted(open_results, key=lambda x: x["port"]):
                f.write(f"| {item['port']} | {item['protocol']} | {item['status']} | {item['inferred_service']} | `{item['banner']}` |\n")
        print(f"[*] Relatório Markdown exportado: {md_file}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Recon & Asset Fingerprinter")
    parser.add_argument("-t", "--target", required=True, help="IP ou Hostname do alvo")
    parser.add_argument("-p", "--ports", default="1-1024", help="Faixa de portas (ex: 1-1024) ou lista (ex: 22,80,443)")
    parser.add_argument("-T", "--threads", type=int, default=50, help="Número de threads concorrentes (Padrão: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout de conexão em segundos (Padrão: 1.0)")
    parser.add_argument("-o", "--output", choices=["json", "markdown", "both"], default="both", help="Formato de exportação do relatório")
    
    args = parser.parse_args()
    
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Erro: Não foi possível resolver o hostname '{args.target}'.")
        sys.exit(1)
        
    # Processamento do argumento de portas
    if "-" in args.ports:
        start_p, end_p = map(int, args.ports.split("-"))
        ports = list(range(start_p, end_p + 1))
    else:
        ports = [int(p.strip()) for p in args.ports.split(",")]
        
    for p in ports:
        port_queue.put(p)
        
    print("=" * 70)
    print(f"[*] Iniciando Auditoria Concorrente em: {args.target} ({target_ip})")
    print(f"[*] Portas a verificar: {len(ports)} | Threads ativas: {args.threads}")
    print(f"[*] Horário de Início: {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 70)
    
    start_time = datetime.now()
    
    threads = []
    num_threads = min(args.threads, len(ports))
    for _ in range(num_threads):
        t = threading.Thread(target=worker_scan, args=(target_ip, args.timeout), daemon=True)
        t.start()
        threads.append(t)
        
    port_queue.join()
    duration = (datetime.now() - start_time).total_seconds()
    
    print("=" * 70)
    print(f"[*] Varredura Concluída em {duration:.2f} segundos.")
    print(f"[*] Total de portas ativas encontradas: {len(open_results)}")
    print("=" * 70)
    
    if open_results:
        export_reports(args.target, duration, args.output)

if __name__ == "__main__":
    main()
