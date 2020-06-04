# cruncher.py

import json
import os


def main():
    folders = [file for file in os.listdir(os.getcwd()) if os.path.isdir(file)]
    folders.remove('.git')

    safe = []
    impacted = {}

    for project in folders:
        target = f"./{project}/gradle-bodyguard-report.json"

        if os.path.exists(target):
            with open(target) as file:
                report = json.load(file)

                for issue in report['issues']:
                    if issue['cve'] in impacted.keys() and project not in impacted[issue['cve']]:
                        impacted[issue['cve']].append(project)
                    else:
                        impacted[issue['cve']] = [project]
        else:
            safe.append(project)

    results = {
        'impacted':impacted,
        'safe':safe
    }

    with open('compiled-results.json','w') as writer:
        writer.write(json.dumps(results, indent=2, sort_keys=True))
        writer.close()


if __name__ == '__main__':
    main()
