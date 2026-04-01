import os, requests, yaml, glob, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = os.getenv('SPLUNK_HOST')
TOKEN = os.getenv('SPLUNK_TOKEN')
TG_TOKEN = os.getenv('TELEGRAM_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

# Принудительно сохраняем в приложение 'search', чтобы ты видел их в интерфейсе
URL = f"https://{HOST}:8089/servicesNS/admin/search/saved/searches?output_mode=json"

def deploy():
    # Ищем файлы именно в твоей папке detections
    rule_path = "owasptop10-splunk-content/detections/**/*.yml"
    files = glob.glob(rule_path, recursive=True)
    
    print(f"--- Найдено файлов: {len(files)}")
    
    for rule_file in files:
        with open(rule_file, 'r', encoding='utf-8') as f:
            try:
                content = yaml.safe_load(f)
            except Exception as e:
                print(f"!!! Ошибка чтения YAML {rule_file}: {e}")
                continue

        # ПРЯМОЕ СООТВЕТСТВИЕ ТВОЕЙ СТРУКТУРЕ
        name = content.get('name')
        query = content.get('search') # Твой YAML использует именно 'search'
        description = content.get('description', 'OWASP Rule')

        if not name or not query:
            print(f"[-] Пропуск {rule_file}: нет имени или поиска")
            continue

        print(f"[+] Деплой правила: {name}")
        
        headers = {"Authorization": f"Bearer {TOKEN}"}
        data = {
            "name": name,
            "search": query.strip(), # Убираем лишние пробелы из-за символа '|'
            "description": description,
            "is_scheduled": 1,
            "cron_schedule": "*/5 * * * *",
            "actions": "webhook",
            "action.webhook.uri": f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage?chat_id={CHAT_ID}&text=SOC_ALERT: {name} detected!"
        }

        try:
            res = requests.post(URL, headers=headers, data=data, verify=False, timeout=10)
            if res.status_code == 201:
                print(f"    Успешно создано.")
            elif res.status_code == 409:
                print(f"    Уже существует.")
            else:
                print(f"    Ошибка {res.status_code}: {res.text}")
        except Exception as e:
            print(f"    Ошибка связи: {e}")

if __name__ == "__main__":
    deploy()
