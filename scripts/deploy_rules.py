import os
import requests
import yaml
import glob

# Данные из секретов GitHub
HOST = os.getenv('SPLUNK_HOST')
TOKEN = os.getenv('SPLUNK_TOKEN')
# Порт 8089 — стандарт для API Splunk
URL = f"https://{HOST}:8089/servicesNS/admin/search/saved/searches?output_mode=json"

def deploy():
    # Ищем все .yml файлы в папке rules
    for rule_file in glob.glob("rules/**/*.yml", recursive=True):
        with open(rule_file, 'r') as f:
            rule = yaml.safe_load(f)
        
        print(f"Деплой правила: {rule['name']}")
        
        headers = {"Authorization": f"Bearer {TOKEN}"}
        data = {
            "name": rule['name'],
            "search": rule['search_query'],
            "description": f"OWASP Rule from GitHub: {rule['description']}",
            "is_scheduled": 1,
            "cron_schedule": "*/5 * * * *", # Проверка каждые 5 минут
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": 0,
            "actions": "summary_index" # Или 'email', если настроена почта
        }
        
        # verify=False нужен, если на Splunk нет платного SSL сертификата
        response = requests.post(URL, headers=headers, data=data, verify=False)
        
        if response.status_code in [201, 409]: # 201 - создано, 409 - уже существует
            print(f"--- Успешно: {rule['name']}")
        else:
            print(f"--- Ошибка {response.status_code}: {response.text}")

if __name__ == "__main__":
    deploy()
