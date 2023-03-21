#!/usr/bin/env python3
# Author: THA-CERT //LGO
from cortexutils.analyzer import Analyzer
import json
import re
from hashlib import sha256
from api import thehive

class LeakFileHash(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param("file", None, "File parameter is missing.")
        self.filename = self.get_param("filename", None, "Filename is missing.")

        self.file_extensions = self.get_param("file_extensions")
        if self.file_extensions is None or self.file_extensions is [None]:
            self.file_extensions = ["zip"]

        self.api_key = self.get_param("config.API_key", None)


    def run(self):
        # Checking connection to LDAP
        Analyzer.run(self)

        # Prepare report variable
        data = {}

        # Get domains hash from file content
        f_content = self.get_file_content()
        domains_list = self.get_domains_sorted_list(f_content)
        domains_list_hash = get_sha256(domains_list)

        data["list"] = domains_list
        data["hash"] = domains_list_hash

        # If API key is set, search for matching artifacts
        if self.api_key:
            cases = thehive.TheHiveApi(self.api_key).list_cases_from_artifact_data(domains_list_hash)
            if int(self._input["message"]) in cases.keys(): del cases[int(self._input["message"])]
            if len(cases) > 0: data["cases"] = cases

        self.report(data)


    def summary(self, raw):
        taxonomies = []
        namespace = "Leak"
        predicate = "Hash"
        # stats_field = ""
        # results_field = ""

        if raw.get("cases"):
            taxonomies.append(self.build_taxonomy("suspicious", namespace, predicate, str(len(raw.get("cases"))) + "_match"))
        elif raw.get("error"):
            taxonomies.append(self.build_taxonomy("malicious", namespace, predicate, str(len(raw.get("cases"))) + "Error_no_DN_detected"))
        else:
            taxonomies.append(self.build_taxonomy("safe", namespace, predicate, "No_match"))

        return {"taxonomies": taxonomies}


    def artifacts(self, raw):
        artifacts = []
        tags=["from_file:" + self.filename]
        # Import domains' hash as an Observable
        if raw.get("hash", None):
            tags.append("domains_hash")
            tags.append("leak_compare")
            tags.append("autoImport:true") # To auto import Observable
            artifacts.append(self.build_artifact('hash', raw["hash"], tags = tags))

        return artifacts


    def operations(self, raw):
        operations = []

        # Add domains' hash as a tag
        if raw.get("hash", None):
            operations.append(self.build_operation('AddTagToArtifact', tag = "domains_hash:" + str(raw["hash"])))

        return operations


    def get_file_content(self):
        f = open(self.filepath, "r", encoding="utf-8")
        f_content = str(f.read().replace("\n", " ").replace("\\n", " "))

        return f_content


    def get_domains_sorted_list(self, content):
        # Basic Regex to catch domains. May be improved
        domains = sorted(set(re.findall("[^\"\\s][a-zA-Z0-9-\\.]+\\.[a-zA-Z]{2,6}[\"\\s$]", content)))
        # Prepare array to return
        unique_sorted_domains = []

        for domain in domains:
            domain = domain.replace("\"", "").replace(" ", "") # Deleted extra space no special char around domain
            if domain.split(".")[-1].lower() in self.file_extensions: continue
            unique_sorted_domains.append(domain)

        return unique_sorted_domains


def get_sha256(data):
    return sha256(str(data).encode('utf-8')).hexdigest()


if __name__ == "__main__":
    LeakFileHash().run()