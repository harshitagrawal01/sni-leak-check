"""Run the ECH check across a list of domains and report adoption.

Usage: python3 survey.py domains.txt
Prints a summary and the handful that actually publish ECH.
"""
import concurrent.futures
import sys

sys.path.insert(0, "app")
from ech import check


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "domains.txt"
    domains = [d.strip() for d in open(path) if d.strip() and not d.startswith("#")]
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for d, r in zip(domains, ex.map(check, domains)):
            results[d] = r

    ok = [d for d, r in results.items() if r.get("ech_published")]
    err = [d for d, r in results.items() if r.get("error")]
    checked = len(domains) - len(err)
    print(f"checked {checked} domains ({len(err)} lookup errors)")
    print(f"publish ECH: {len(ok)} ({len(ok) / max(checked,1) * 100:.1f}%)")
    print(f"leak the hostname: {checked - len(ok)}")
    print()
    print("the ones that publish ECH:")
    for d in ok:
        print(f"  {d:32} cover={results[d]['ech']['public_name']}")


if __name__ == "__main__":
    main()
