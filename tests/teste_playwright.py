import os
import time
import json
import urllib.request
from playwright.sync_api import sync_playwright

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
LOG_FILE_PATH = os.path.join(PROJECT_ROOT, "backend", "logs", "access_logs.json")

def is_server_running(url="http://localhost:8000/api/health"):
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            return response.status == 200
    except Exception:
        return False

def get_latest_log():
    if os.path.exists(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if lines:
                    try:
                        return json.loads(lines[-1])
                    except Exception:
                        pass
            with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
                logs = json.load(f)
                if logs and isinstance(logs, list):
                    return logs[-1]
        except Exception:
            pass
    return None

def run_test():
    import sys
    target_arg = sys.argv[1] if len(sys.argv) > 1 else None

    if target_arg:
        target_url = target_arg
        print(f"🌐 Conectando ao Servidor via parâmetro: {target_url}")
    elif is_server_running():
        target_url = "http://localhost:8000"
        print("🌐 Conectando ao Servidor de Avaliação de Risco: http://localhost:8000")
    else:
        target_url = "file://" + os.path.join(PROJECT_ROOT, "frontend", "index.html")
        print("⚠️ Servidor não detectado em localhost:8000. Abrindo arquivo local via file://")
        print("   (Dica: execute 'python backend/server.py' para a avaliação multicamadas completa)")

    print("=" * 65)
    print("Iniciando teste de automação com Playwright (Tentativa de Evasão/Burlar)")
    print("=" * 65)

    with sync_playwright() as p:
        # Browser configuration with common flags used by bots to conceal automation
        browser = p.chromium.launch(
            headless=False,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage"
            ]
        )

        # Context simulating regular user
        context = browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            viewport={"width": 1366, "height": 768},
            locale="pt-BR",
            timezone_id="America/Sao_Paulo"
        )

        # Simulated stealth evasion (masking browser properties)
        context.add_init_script("""
            try {
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                    configurable: true
                });
            } catch (e) {}

            try {
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                    configurable: true
                });
            } catch (e) {}

            try {
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['pt-BR', 'pt', 'en-US'],
                    configurable: true
                });
            } catch (e) {}
        """)

        page = context.new_page()

        print(f"\nAcessando: {target_url}")
        page.goto(target_url)

        # Wait for detector analysis to execute
        time.sleep(2)

        # Run evaluation (which queries server)
        resultado = page.evaluate("async () => typeof detectBot === 'function' ? await detectBot() : null")

        print("\n" + "-" * 55)
        print("RESPOSTA DA API PARA O CLIENTE (ZERO-KNOWLEDGE):")
        print("-" * 55)
        if resultado:
            if resultado.get("isBot"):
                print("❌ VEREDITO DO SERVIDOR: 🤖 BOT / AUTOMAÇÃO DETECTADA")
                print(f"🛑 Ação:                 {resultado.get('action', 'BLOCK')}")
                print(f"🔑 Session ID:           {resultado.get('sessionId')}")
            else:
                print("✅ VEREDITO DO SERVIDOR: 👤 ACESSO HUMANO LEGÍTIMO")
                print(f"🟢 Ação:                 {resultado.get('action', 'ALLOW')}")
        else:
            print("Não foi possível obter a resposta do servidor.")

        # Inspect JSON access log saved by server
        print("\n" + "-" * 55)
        print("REGISTRO DE AUDITORIA INTERNO NO ARQUIVO logs/access_logs.json:")
        print("-" * 55)
        latest_log = get_latest_log()
        if latest_log:
            eval_data = latest_log.get("evaluation", {})
            print(f"📄 Arquivo: {LOG_FILE_PATH}")
            print(f"🕒 Timestamp do Log: {latest_log.get('timestamp')}")
            print(f"🌐 IP do Cliente:    {latest_log.get('client_ip')}")
            print(f"🚨 Total de Categorias com Anomalia: {eval_data.get('total_categories_triggered')}")
            print("\n📋 Evidências Registradas Internamente no Log JSON:")
            for reason in eval_data.get("reasons", []):
                print(f"   • {reason}")
        else:
            print("Nenhum log encontrado ainda.")

        print("-" * 55)
        print("\nO navegador ficará aberto por 5 segundos para inspeção visual...")
        time.sleep(5)

        browser.close()
        print("Navegador fechado com sucesso.")

if __name__ == "__main__":
    run_test()
