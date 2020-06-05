# crunch-results.py

import json
import os


def main():
    folders = [file for file in os.listdir(os.getcwd()) if os.path.isdir(file)]
    folders.remove('.git')

    results = {
        'projects': {
            'santa-tracker': [],
            'plaid': [],
            'uamp': [],
            'iosched': [],
            'sunflower': [],
            'k9mail': [],
            'proton-mail-android': [],
            'duckduckgo': [],
            'signal': [],
            'corona-warn-app': [],
            'immuni-app': [],
            'freeotp': [],
            'haven': [],
            'mozilla-lockwise': [],
            'wireguard': [],
            'termux': [],
            'connectbot': [],
            'kickstarter': [],
            'wordpress': [],
            'wikipedia': [],
            'wire': [],
        },
        'cves': []
    }

    for project in folders:
        target = f"./{project}/gradle-bodyguard-report.json"

        if os.path.exists(target):
            with open(target) as reader:
                report = json.load(reader)

                for issue in report['issues']:
                    collected = results['projects'][project]
                    cve = issue['cve']

                    if cve not in collected:
                        collected.append(cve)

                    if cve not in results['cves']:
                        results['cves'].append(cve)

                reader.close()

    results['cves'] = sorted(results['cves'])

    with open('aggregated-results.json', 'w') as writer:
        writer.write(json.dumps(results, indent=2, sort_keys=True))
        writer.close()


if __name__ == '__main__':
    main()
