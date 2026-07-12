import os
import re
import requests
import logging
from datetime import datetime
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential
import psycopg2
import time

load_dotenv()

TOKEN = os.getenv("YC_TOKEN")
FOLDER_ID = os.getenv("FOLDER_ID")
CLOUD_ID = os.getenv("CLOUD_ID")

logging.basicConfig(level=logging.WARNING, format='%(message)s')


def connect_db():
    time.sleep(5)
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            connect_timeout=5
        )
        print("Подключение к БД установлено")
        return conn
    except Exception as e:
        print(f"БД недоступна: {e}. Сканер работает без записи в БД.")
        return None


def save_scan_result(conn, vm_name, open_ports, sa_role_cloud, sa_role_folder,
                     snapshot_status, snapshot_encrypted, imdsv2_status,
                     public_ip, os_status):
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id SERIAL PRIMARY KEY,
                vm_name TEXT,
                open_ports TEXT,
                sa_role_cloud TEXT,
                sa_role_folder TEXT,
                snapshot_status TEXT,
                snapshot_encrypted BOOLEAN,
                imdsv2_status TEXT,
                public_ip BOOLEAN,
                os_status TEXT,
                checked_at TIMESTAMP DEFAULT NOW()
            );
        """)
        cur.execute("""
            INSERT INTO scan_results (vm_name, open_ports, sa_role_cloud, sa_role_folder,
                                      snapshot_status, snapshot_encrypted, imdsv2_status,
                                      public_ip, os_status)

            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (vm_name, open_ports, sa_role_cloud, sa_role_folder,
              snapshot_status, snapshot_encrypted, imdsv2_status,
              public_ip, os_status))

        conn.commit()
        cur.close()
        print(f"Результаты для {vm_name} сохранены в БД")
    except Exception as e:
        print(f"Ошибка сохранения в БД: {e}")


def yc_get(url, params=None):
    headers = {"Authorization": f"Bearer {TOKEN}"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"API request failed: {e}")
        raise


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def yc_get_retry(url, params=None):
    return yc_get(url, params)


def get_all_pages(url, params, key):
    items = []
    tok = None
    while True:
        if tok:
            params["pageToken"] = tok
        data = yc_get_retry(url, params)
        items += data.get(key, [])
        tok = data.get("nextPageToken")
        if not tok:
            break
    return items


def folder_bindings_get(f_id):
    u = f"https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders/{f_id}:listAccessBindings"
    return get_all_pages(u, {}, "accessBindings")


def cloud_bindings_get(c_id):
    u = f"https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds/{c_id}:listAccessBindings"
    return get_all_pages(u, {}, "accessBindings")


def compute_get(f_id):
    u = "https://compute.api.cloud.yandex.net/compute/v1/instances"
    return get_all_pages(u, {"folderId": f_id}, "instances")


def snapshot_get(f_id):
    u = "https://compute.api.cloud.yandex.net/compute/v1/snapshots"
    return get_all_pages(u, {"folderId": f_id}, "snapshots")


def security_group_get(f_id):
    u = "https://vpc.api.cloud.yandex.net/vpc/v1/securityGroups"
    return get_all_pages(u, {"folderId": f_id}, "securityGroups")


def get_all_images(f_id):
    imgs = {}
    u = "https://compute.api.cloud.yandex.net/compute/v1/images"
    for i in get_all_pages(u, {"folderId": f_id}, "images"):
        imgs[i["id"]] = i
    for i in get_all_pages(u, {"folderId": "standard-images"}, "images"):
        imgs[i["id"]] = i
    return imgs


def is_outdated_os(img):
    if not img:
        return False
    pid = img.get("product_ids", [])
    pat = ["ubuntu-16", "ubuntu-18", "centos-7", "windows-2012", "windows-2016"]
    for p in pid:
        if any(x in p.lower() for x in pat):
            return True
    return False


folder_bindings = folder_bindings_get(FOLDER_ID)
cloud_bindings = cloud_bindings_get(CLOUD_ID)
compute = compute_get(FOLDER_ID)
snapshot = snapshot_get(FOLDER_ID)
security_group = security_group_get(FOLDER_ID)
images_cache = get_all_images(FOLDER_ID)

dangerous_ports = {"SSH": 22, "RDP": 3389, "PostgreSQL": 5432, "MySQL": 3306, "MongoDB": 27017, "Redis": 6379}


def checks_pub_ip(i):
    ips = []
    for n in i.get("networkInterfaces", []):
        ip = n.get("primaryV4Address", {}).get("oneToOneNat", {}).get("address")
        if ip:
            ips.append(ip)
    if ips:
        print(f"Публичные IP: {ips}")
    else:
        print("Публичных IP нет")


def checks_security_group(sg_ids, sg_all):
    ports_open = {n: False for n in dangerous_ports}
    all_open = False
    for sid in sg_ids:
        sg = None
        for s in sg_all:
            if s.get("id") == sid:
                sg = s
                break
        if not sg:
            continue

        for r in sg.get("rules", []):
            if r.get("direction") != "INGRESS":
                continue

            cidrs = r.get("cidrBlocks", {}).get("v4CidrBlocks", [])
            if "0.0.0.0/0" not in cidrs:
                continue

            ports = r.get("ports", {})
            fv = ports.get("fromPort")
            tv = ports.get("toPort")
            if fv is None and tv is None:
                all_open = True
                continue
            if fv == "1" and tv == "65535":
                all_open = True
                continue
            try:
                fp = int(fv or 0)
                tp = int(tv or 0)
            except Exception:
                continue
            for name, p in dangerous_ports.items():
                if fp == p or tp == p:
                    ports_open[name] = True
                elif fp and tp and fp <= p <= tp:
                    ports_open[name] = True

    for name, op in ports_open.items():
        if op:
            print(f"  Порт {name}: ОТКРЫТ")
        else:
            print(f"  Порт {name}: закрыт")
    if all_open:
        print("  Широкие правила портов: ЕСТЬ (весь диапазон 1-65535)")
    else:
        print("  Широких правил портов: нет")
    return [name for name, op in ports_open.items() if op], all_open


def checks_snapshot(snaps, vm):
    disks = []
    boot = vm.get("bootDisk", {}).get("diskId")
    if boot:
        disks.append(boot)
    for sd in vm.get("secondaryDisks", []):
        if sd.get("diskId"):
            disks.append(sd.get("diskId"))

    snapshot_found = False
    snapshot_ok = False
    snapshot_encrypted = False

    for d in disks:
        for s in snaps:
            if s.get("sourceDiskId") == d:
                snapshot_found = True

                st = s.get("status")
                cr = s.get("createdAt")

                if st == "READY":
                    snapshot_ok = True

                if s.get("kmsKeyId"):
                    snapshot_encrypted = True

                if st != "READY":
                    print(f"  Снапшот: статус {st}")
                else:
                    print("  Снапшот: ГОТОВ")
                try:
                    d1 = datetime.fromisoformat(cr.replace('Z', '+00:00'))
                    days = (datetime.now() - d1.replace(tzinfo=None)).days

                    if days > 30:
                        print(f"  Снапшот: старый ({days} дней)")
                    else:
                        print(f"  Снапшот: свежий ({days} дней)")

                except Exception:
                    print("  Снапшот: ошибка расчета даты")

                if s.get("kmsKeyId"):
                    print("  Снапшот: ЗАШИФРОВАН")
                else:
                    print("  Снапшот: НЕ ЗАШИФРОВАН")

        if not snapshot_found:
            print(f"  Снапшотов для диска {d}: НЕТ")
    if not snapshot_found:
        return "НЕТ", False
    elif snapshot_ok:
        return "ГОТОВ", snapshot_encrypted
    else:
        return "НЕ ГОТОВ", snapshot_encrypted


def checks_bindings(level, name, sid, out):
    for b in level:
        if b.get("subject", {}).get("id") == sid:
            out.append(b.get("roleId"))
    if out:
        print(f"  Роли SA на уровне {name}: {', '.join(out)}")
    else:
        print(f"  Ролей SA на уровне {name}: нет")


def check_userdata(vm):
    ud = vm.get("metadata", {}).get("user-data", "")
    if not ud:
        print("  User-data: пусто")
        return

    pat = ["password", "token", "secret", "api_key", "BEGIN RSA PRIVATE KEY"]
    for p in pat:
        if re.search(p, ud, re.IGNORECASE):
            print(f"  User-data: ОБНАРУЖЕН СЕКРЕТ! ({p})")
            return
    print("  User-data: секретов не найдено")


def check_imdsv2(vm):
    m = vm.get("metadataOptions", {}).get("metadataMode")
    if m == "ENABLED":
        print("  IMDSv2: ВКЛЮЧЕНА")
        return "ВКЛЮЧЕНА"
    else:
        print(f"  IMDSv2: НЕ ВКЛЮЧЕНА (режим: {m})")
        return f"НЕ ВКЛЮЧЕНА ({m})"


def check_disk_type(vm):
    t = vm.get("bootDisk", {}).get("typeId")
    if t == "network-ssd":
        print("  Загрузочный диск: SSD")
    elif t == "network-hdd":
        print("  Загрузочный диск: HDD (рекомендуется заменить на SSD)")
    else:
        print(f"  Загрузочный диск: тип {t}")


def check_egress(sg_ids, sg_all):
    for sid in sg_ids:
        for sg in sg_all:
            if sg.get("id") == sid:
                for r in sg.get("rules", []):
                    if r.get("direction") == "EGRESS":
                        cidrs = r.get("cidrBlocks", {}).get("v4CidrBlocks", [])
                        if "0.0.0.0/0" in cidrs:
                            print(f"  EGRESS правило с 0.0.0.0/0 в группе {sid}: ЕСТЬ")
                            return

    print("  EGRESS правила с 0.0.0.0/0: нет")


def checks_compute():
    db_conn = connect_db()

    print("\n" + "=" * 60)
    print("НАЧАЛО ПРОВЕРКИ БЕЗОПАСНОСТИ ОБЛАКА")
    print("=" * 60)

    for vm in compute:
        name = vm.get("name")
        sid = vm.get("serviceAccountId")
        print(f"\n--- ВМ: {name} ---")

        c_ips = []
        f_ips = []
        open_ports_list = []
        snapshot_status = "НЕТ"
        snapshot_encrypted = False
        imdsv2_status = "НЕ ВКЛЮЧЕНА (None)"
        has_public_ip = False
        os_status = "актуальная"

        if sid:
            print(f"  Сервисный аккаунт: {sid}")
            checks_bindings(cloud_bindings, "облака", sid, c_ips)
            checks_bindings(folder_bindings, "папки", sid, f_ips)
        else:
            print("  Сервисный аккаунт: НЕ ПРИВЯЗАН")

        nets = vm.get("networkInterfaces", [])
        if nets:
            checks_pub_ip(vm)
            for n in nets:
                ip = n.get("primaryV4Address", {}).get("oneToOneNat", {}).get("address")
                if ip:
                    has_public_ip = True
            sg_ids = nets[0].get("securityGroupIds", [])
            if sg_ids:
                print(f"  Привязанные Security Groups: {', '.join(sg_ids)}")
                open_ports_list, _ = checks_security_group(sg_ids, security_group)
                check_egress(sg_ids, security_group)
            else:
                print("  Security Groups: НЕ ПРИВЯЗАНЫ")
        else:
            print("  Сетевые интерфейсы: ОТСУТСТВУЮТ")

        snapshot_status, snapshot_encrypted = checks_snapshot(snapshot, vm)
        check_userdata(vm)
        imdsv2_status = check_imdsv2(vm)
        check_disk_type(vm)

        img_id = vm.get("imageId")
        if img_id:
            img = images_cache.get(img_id)
            if is_outdated_os(img):
                print("  ОС: УСТАРЕВШАЯ (нет обновлений безопасности)")
                os_status = "УСТАРЕВШАЯ"
            else:
                print("  ОС: актуальная")
        else:
            print("  ОС: создана из диска (образ не определён)")

        print("-" * 40)

        # ЗАПИСЬ В БД 
        save_scan_result(
            db_conn,
            name,
            ", ".join(open_ports_list) if open_ports_list else "none",
            ", ".join(c_ips) if c_ips else "none",
            ", ".join(f_ips) if f_ips else "none",
            snapshot_status,
            snapshot_encrypted,
            imdsv2_status,
            has_public_ip,
            os_status
        )

    if db_conn:
        db_conn.close()
        print("Подключение к БД закрыто")


def main():
    checks_compute()
    print("\n" + "=" * 60)
    print("ПРОВЕРКА ЗАВЕРШЕНА")
    print("=" * 60)


if __name__ == "__main__":
    main()
