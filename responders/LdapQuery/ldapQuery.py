#!/usr/bin/env python3
# Author: @cyber_pescadito, modified by THA-CERT //LGO
import json
from cortexutils.responder import Responder
from re import search
from ldap3 import Server, Connection, SIMPLE, SYNC, SUBTREE, ALL
import requests # TheHive4py could be use in the future, but still in Beta version for now...
import datetime # Temporary, use to track execution time

class LdapQuery(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.execution_time = [] # Temporary, use to track execution time
        self.execution_time.append(str(datetime.datetime.now()) + ": Start Init Responder") # Temporary, use to track execution time
        ldap_address = self.get_param(
            "config.LDAP_address", None, "ldap_address is missing"
        )
        ldap_port = self.get_param("config.LDAP_port", None, "ldap_port is missing")
        ldap_port = int(ldap_port)

        if not self.get_case_data():
            exit("Fatal Error: couldn't get case's artifacts")

        username = self.get_param("config.LDAP_username", None, "username is missing")
        password = self.get_param("config.LDAP_password", None, "password is missing")
        self.base_dn = self.get_param("config.base_DN", None, "base_dn is missing")

        # Set mail field name and filters
        self.mail_search_field = self.get_param("config.mail_search_field", None, "mail_search_field is missing")
        self.mail_filter = self.get_param("config.mail_search_filter", None, "Mail domain name filter domains is missing")

        # Set uid field name and filters
        self.uid_search_field = self.get_param("config.uid_search_field", None, "uid_search_field is missing")
        uid_filter = self.get_param("config.uid_search_filter")
        if uid_filter is None or uid_filter == ['']:
            self.uid_filter = None
        else:
            self.uid_filter = uid_filter

        # Set attributes name and output
        self.attributes = []
        self.attributes_output = []
        for att in self.get_param("config.attributes", None, "Missing attributes list to report"):
            self.attributes.append(att.split(':')[0])
            self.attributes_output.append(att.split(':')[-1])

        try:
            s = Server(
                ldap_address,
                port=ldap_port,
                get_info=ALL,
                use_ssl=True if ldap_port == 636 else False,
            )
            self.connection = Connection(
                s,
                auto_bind=True,
                client_strategy=SYNC,
                user=username,
                password=password,
                authentication=SIMPLE,
                check_names=True,
            )
        except Exception as e:
            self.error("Error during LDAP connection: %s" % e)

        self.execution_time.append(str(datetime.datetime.now()) + ": End Init Responder") # Temporary, use to track execution time



    def run(self):
        self.execution_time.append(str(datetime.datetime.now()) + ": Start Run") # Temporary, use to track execution time
        # Checking connection to LDAP
        Responder.run(self)

        for artifact in self.artifacts:
            # Prepare query for data type is mail
            if artifact.get("dataType") == "mail":

                # Filter on email address to query on
                domain = artifact.get("data").split('@')[-1]
                if domain not in self.mail_filter:
                    artifact.get("tags").append("ldap_filtered")
                    self.update_artifact_tags(artifact)
                    continue

                # Set query
                q = "(|"
                for field in self.mail_search_field:
                    q += "({}={})".format(field, artifact.get("data"))
                q += ")"

            # Prepare query for data type is username
            elif artifact.get("dataType") == "username":
                try:
                    # Check if uid filter apply
                    if self.uid_filter is not None:
                        username = artifact.get("data")

                        # Filter on username to query on
                        to_filter = True
                        for pattern in self.uid_filter:
                            if search(pattern, username) is not None:
                                to_filter = False

                        if to_filter:
                            artifact.get("tags").append("ldap_filtered")
                            self.update_artifact_tags(artifact)
                            continue
                except:
                    pass

                # Set query
                q = "({}={})".format(self.uid_search_field, artifact.get("data"))

            else:
                continue

            try:
                self.execution_time.append(str(datetime.datetime.now()) + ": Request LDAP") # Temporary, use to track execution time
                self.connection.search(self.base_dn, q, SUBTREE, attributes=self.attributes)
                responses = self.connection.response
                self.execution_time.append(str(datetime.datetime.now()) + ": Response LDAP") # Temporary, use to track execution time

                if responses:
                    # Set loop_prefix in case of multiple uid are returned
                    loop_prefix = ""
                    loop = 0
                    for response in responses:
                        if loop > 0: loop_prefix = "(" + str(loop) + ")"

                        dict_response = response.get("attributes", None)
                        if dict_response:
                            for att in dict_response.keys():
                                # Skip empty attributes
                                if dict_response[att] == "" or \
                                   dict_response[att] == [] or \
                                   dict_response[att] is None: continue

                                # Define tag's prefix
                                try: prefix = self.attributes_output[self.attributes.index(att)] + loop_prefix
                                except: prefix = att + loop_prefix

                                # Processing depends of returned data type (list or str)
                                value = ""
                                if isinstance(dict_response[att], list):
                                    for i in range(len(dict_response[att])):
                                        if i == 0: value += str(dict_response[att][i])
                                        else: value += ", " + str(dict_response[att][i])
                                else:
                                    value = str(dict_response[att])

                                artifact.get("tags").append(prefix + ":" + value)

                        loop += 1 # Used to set loop_prefix

                    artifact.get("tags").append("ldap_ok")
                else:
                    artifact.get("tags").append("ldap_no_result")
                    self.update_artifact_tags(artifact)

            except Exception as e:
                self.error("LDAP connection error: " + str(e))
            self.update_artifact_tags(artifact)

        self.connection.unbind()

        self.execution_time.append(str(datetime.datetime.now()) + ": End Run") # Temporary, use to track execution time
        self.report({"message": "LDAP queries done.", "logs" : self.execution_time})


    def operations(self, raw):
        operations = []
        operations.append(self.build_operation("AddTagToCase", tag="ldap_ok"))

        return operations


    def get_case_data(self):
        self.execution_time.append(str(datetime.datetime.now()) + ": Start get case data") # Temporary, use to track execution time
        self.case_id = self.get_data().get("_id", None)
        self.case_number = self.get_data().get("caseId", None)

        if self.case_id is None or self.case_number is None:
            exit("Fatal Error: unable to identify Case id or number.")
        if not self.get_case_artifacts():
            exit("Fatal Error: unable to get case observables.")

        self.execution_time.append(str(datetime.datetime.now()) + ": End get case data") # Temporary, use to track execution time
        return True


    def get_case_artifacts(self): # Through API request to TheHive
        self.execution_time.append(str(datetime.datetime.now()) + ": Start get artifacts") # Temporary, use to track execution time
        url = self.get_param("config.API_url", None, "api_url is missing") + "/api/case/artifact/_search"

        proxies = {"http": "", "https": ""}

        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": "Bearer " +  self.get_param("config.API_key", None, "api_key is missing")
        }

        params = {
            "query": {
                "_parent": {
                    "_type": "case",
                    "_query": {
                        "_id": self.case_id
                    }
                }
            },
            "range": "all"
        }

        self.execution_time.append(str(datetime.datetime.now()) + ": Send API request") # Temporary, use to track execution time
        r = requests.post(url, headers = headers, json = params, proxies=proxies) #, verify = config.SSL_VERIFY)
        self.execution_time.append(str(datetime.datetime.now()) + ": API response") # Temporary, use to track execution time

        if r.status_code != 200:
            exit("Fatal Error: API request failed with code " + str(r.status_code) + ". Response from server is:\n" + str(r.content))

        self.artifacts = []

        for artifact in json.loads(r.content):
            if artifact.get("dataType", None) not in ["mail", "username"]: continue

            a = {}
            a["id"] = artifact.get("id", None)
            a["dataType"] = artifact.get("dataType", None)
            a["data"] = artifact.get("data", None)
            a["tags"] = artifact.get("tags", [])

            self.artifacts.append(a)

        self.execution_time.append(str(datetime.datetime.now()) + ": End get artifacts") # Temporary, use to track execution time
        return True


    def update_artifact_tags(self, artifact): # Through API request to TheHive
        self.execution_time.append(str(datetime.datetime.now()) + ": Start update artifacts") # Temporary, use to track execution time
        url = self.get_param("config.API_url", None, "api_url is missing") + "/api/v0/case/artifact/" + artifact.get("id")

        proxies = {"http": "", "https": ""}
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": "Bearer " +  self.get_param("config.API_key", None, "api_key is missing")
        }
        params = {"tags": artifact.get("tags")}

        self.execution_time.append(str(datetime.datetime.now()) + ": Send API request") # Temporary, use to track execution time
        r = requests.patch(url, headers = headers, json = params, proxies=proxies) #, verify = config.SSL_VERIFY)
        self.execution_time.append(str(datetime.datetime.now()) + ": API response") # Temporary, use to track execution time

        if r.status_code != 200:
            print("Fatal Error: API request failed with code " + str(r.status_code) + ". Response from server is:\n" + str(r.content))
            return False

        self.execution_time.append(str(datetime.datetime.now()) + ": End update artifacts") # Temporary, use to track execution time
        return True


if __name__ == "__main__":
    LdapQuery().run()
