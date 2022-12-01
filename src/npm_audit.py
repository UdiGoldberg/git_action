from subprocess import Popen, PIPE
from pathlib import Path
import tempfile
import os.path
import shutil
import json


class NpmAuditChecker:

    RISK_SEVERITIES = ['high', 'critical']
    RISK_KEYWORDS = ['Injection']

    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.tmp_file = os.path.join(tempfile.mkdtemp(), 'npm_audit.json')
        self.audit_json = None
        self.success = None

    def save_audit_file(self):
        with open(self.tmp_file, 'w') as f:
            p = Popen(['npm', 'audit', '-json', '--prefix', self.project_path], stdout=f, stderr=PIPE)
        stdout, stderr = p.communicate()
        if stderr:
            raise Exception(f'Failed to run npm audit on {self.project_path}')
        with open(self.tmp_file, 'r') as f:
            self.audit_json = json.load(f)
            print('JSON FILE:')
            print(self.audit_json)

    def search_for_issues(self):
        for vuln_name, vuln_data in self.audit_json['vulnerabilities'].items():
            if vuln_data['severity'] in NpmAuditChecker.RISK_SEVERITIES:
                self.success = False
                return
        # for advisor_id, advisor_data in self.audit_json['advisories'].items():
        #     if advisor_data['severity'] in NpmAuditChecker.RISK_SEVERITIES:
        #         self.success = False
        #         return
        #     for keyword in NpmAuditChecker.RISK_KEYWORDS:
        #         if keyword in advisor_data['title']:
        #             self.success = False
        #             return
        self.success = True

    def remove_temp_file(self):
        shutil.rmtree(os.path.dirname(self.tmp_file))

    def run(self):
        self.save_audit_file()
        self.search_for_issues()
        if self.success:
            self.remove_temp_file()
        return self.success


if __name__ == '__main__':
    path = Path(os.environ.get("INPUT_PATH"))
    checker = NpmAuditChecker(path)
    success = checker.run()
    if success:
        exit(0)
    else:
        exit(-1)
