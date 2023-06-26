import random
from datetime import datetime

from pymispwarninglists import WarningLists

start_time = datetime.now()

warning_lists = WarningLists(slow_search=True)
warning_lists.warninglists = {
    name: warning_list
    for name, warning_list in warning_lists.warninglists.items()
    if warning_list.type == "cidr"
}

print(f"Loaded {len(warning_lists)} warning lists in {datetime.now() - start_time}")

random_ip_v4 = [f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(100)]

start_time = datetime.now()

for ip in random_ip_v4:
    warning_lists.search(ip)

print(f"Searched for {len(random_ip_v4)} IPs in {len(warning_lists)} lists in {datetime.now() - start_time}")
