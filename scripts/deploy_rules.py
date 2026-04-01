import os
import requests
import yaml
import glob
import urllib3

# Отключаем предупреждения о самоподписанном сертификате (чтобы лог был чистым)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Правильно достаем данные из секретов GitHub (используем ИМЕНА секретов)
HOST = os.getenv('SPLUNK_HOST')
TOKEN = os.getenv('SPLUNK_TOKEN')
TG_TOKEN = os.getenv('TELEGRAM_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

# Ссылка на API
URL = f"https://{HOST}:8089/servicesNS/admin/search/saved/searches?output_mode=json"

def deploy():
    for rule_file in glob.glob("owasptop10-splunk-content/detections/**/*.yml", recursive=True):
        with open(rule_file, 'r') as f:
            rule = yaml.safe_load(f)
        
        print(f"Деплой правила: {rule['name']}")
        
        headers = {"Authorization": f"Bearer {TOKEN}"}
        
        # Формируем данные для Splunk
        data = {
            "name": rule['name'],
            "search": rule['search_query'],
            "description": f"OWASP Rule from GitHub: {rule['description']}",
            "is_scheduled": 1,
            "cron_schedule": "*/5 * * * *", 
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": 0,
            "actions": "webhook", # Включаем вебхук
            "action.webhook.enable_whitelist": "1",
            # Используем переменные для Telegram
            "action.webhook.uri": f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage?chat_id={CHAT_ID}&text=SOC_ALERT:_*$name$*_Detected!%0ACheck_Splunk_immediately."
        }
        
        try:
            response = requests.post(URL, headers=headers, data=data, verify=False, timeout=10)
            
            if response.status_code == 201:
                print(f"--- Успешно: {rule['name']} создано.")
            elif response.status_code == 409:
                print(f"--- Инфо: {rule['name']} уже существует (пропускаем).")
            else:
                print(f"--- Ошибка {response.status_code}: {response.text}")
        except Exception as e:
            print(f"--- Критическая ошибка связи: {e}")

if __name__ == "__main__":
    deploy()
