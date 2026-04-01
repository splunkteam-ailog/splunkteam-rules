import os
import requests
import yaml
import glob
import urllib3

# Отключаем предупреждения о самоподписанном сертификате
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = os.getenv('SPLUNK_HOST')
TOKEN = os.getenv('SPLUNK_TOKEN')
TG_TOKEN = os.getenv('TELEGRAM_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

URL = f"https://{HOST}:8089/servicesNS/admin/search/saved/searches?output_mode=json"

def deploy():
    # ИСПРАВЛЕНИЕ 1: Правильный путь к твоим правилам
    path_to_rules = "owasptop10-splunk-content/detections/**/*.yml"
    found_files = glob.glob(path_to_rules, recursive=True)
    
    if not found_files:
        print(f"ВНИМАНИЕ: Файлы правил не найдены по пути {path_to_rules}")
        return

    for rule_file in found_files:
        # ИСПРАВЛЕНИЕ 2: Явная кодировка utf-8
        with open(rule_file, 'r', encoding='utf-8') as f:
            try:
                rule = yaml.safe_load(f)
            except yaml.YAMLError as exc:
                print(f"Ошибка чтения YAML в файле {rule_file}: {exc}")
                continue
        
        # ИСПРАВЛЕНИЕ 3: Безопасное извлечение ключей (.get)
        if not rule:
            continue
            
        name = rule.get('name')
        search_query = rule.get('search_query') # Убедись, что в твоем YAML ключ называется именно так, а не 'search'
        description = rule.get('description', 'No description provided')

        if not name or not search_query:
            print(f"Пропуск файла {rule_file}: отсутствует 'name' или 'search_query'")
            continue
            
        print(f"Деплой правила: {name}")
        
        headers = {"Authorization": f"Bearer {TOKEN}"}
        
        data = {
            "name": name,
            "search": search_query,
            "description": f"OWASP Rule from GitHub: {description}",
            "is_scheduled": 1,
            "cron_schedule": "*/5 * * * *", 
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": 0,
            "actions": "webhook",
            "action.webhook.enable_whitelist": "1",
            "action.webhook.uri": f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage?chat_id={CHAT_ID}&text=SOC_ALERT:_*$name$*_Detected!%0ACheck_Splunk_immediately."
        }
        
        try:
            response = requests.post(URL, headers=headers, data=data, verify=False, timeout=10)
            
            if response.status_code == 201:
                print(f"--- Успешно: {name} создано.")
            elif response.status_code == 409:
                print(f"--- Инфо: {name} уже существует (пропускаем).")
            else:
                print(f"--- Ошибка {response.status_code}: {response.text}")
        except Exception as e:
            print(f"--- Критическая ошибка связи: {e}")

if __name__ == "__main__":
    deploy()
