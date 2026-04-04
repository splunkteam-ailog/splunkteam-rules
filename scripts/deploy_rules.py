import os, requests, yaml, glob, urllib3
from urllib.parse import quote_plus
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = os.getenv('SPLUNK_HOST')
TOKEN = os.getenv('SPLUNK_TOKEN')
TG_TOKEN = os.getenv('TELEGRAM_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

URL = f"https://{HOST}:8089/servicesNS/nobody/search/saved/searches"

def delete_if_exists(name, headers):
    del_url = f"https://{HOST}:8089/servicesNS/nobody/search/saved/searches/{requests.utils.quote(name, safe='')}"
    res = requests.delete(del_url, headers=headers, verify=False, timeout=10)
    if res.status_code == 200:
        print(f"    🗑️ Удалён старый: {name}")

def deploy():
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

        name = content.get('name')
        query = content.get('search')
        description = content.get('description', 'OWASP Rule')

        if not name or not query:
            print(f"[-] Пропуск {rule_file}: нет имени или поиска")
            continue

        print(f"[+] Деплой правила: {name}")

        headers = {"Authorization": f"Bearer {TOKEN}"}
        delete_if_exists(name, headers)

        # Уникальный текст для каждого алерта
        tg_text = quote_plus(f"🚨 SPLUNK ALERT: {name} TRIGGERED")
        tg_url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage?chat_id={CHAT_ID}&text={tg_text}"

        data = {
            "name": name,
            "search": query.strip(),
            "description": description,
            # --- Расписание ---
            "is_scheduled": "1",
            "cron_schedule": "*/5 * * * *",
            "dispatch.earliest_time": "-15m",
            "dispatch.latest_time": "now",
            # --- Триггер ---
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.expires": "24h",
            "alert.severity": "3",
            # --- Троттлинг отключён ---
            "alert.suppress": "0",
            "alert.suppress.period": "0",
            "alert.track": "1",
            # --- Webhook ---
            "actions": "webhook",
            "action.webhook": "1",
            "action.webhook.param.url": tg_url,
        }

        try:
            res = requests.post(
                f"{URL}?output_mode=json",
                headers=headers,
                data=data,
                verify=False,
                timeout=10
            )
            if res.status_code == 201:
                print(f"    ✅ Создан как ALERT: {name}")
            elif res.status_code == 409:
                print(f"    ⚠️ Конфликт имён — удаление не сработало")
            else:
                print(f"    ❌ Ошибка {res.status_code}: {res.text}")
        except Exception as e:
            print(f"    ❌ Ошибка связи: {e}")

if __name__ == "__main__":
    deploy()
