#!/usr/bin/env python3
# Author: @cyber_pescadito, modified by THA-CERT //LGO
import json
from re import search
from ldap3 import Server, Connection, SIMPLE, SYNC, SUBTREE, ALL
from cortexutils.analyzer import Analyzer

class LdapQuery(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        ldap_address = self.get_param(
            "config.LDAP_address", None, "ldap_address is missing"
        )
        ldap_port = self.get_param("config.LDAP_port", None, "ldap_port is missing")
        ldap_port = int(ldap_port)

        username = self.get_param("config.LDAP_username", None, "username is missing")
        password = self.get_param("config.LDAP_password", None, "password is missing")
        self.base_dn = self.get_param("config.base_DN", None, "base_dn is missing")
        self.attributes = self.get_param("config.attributes", None, "Missing attributes list to report")

        # Set search fileds and filters, related to artifact's type
        if self.data_type == "mail":
            self.search_fields = self.get_param("config.mail_search_fields", None, "mail_search_fields is missing")
            self.filters = self.get_param("config.mail_search_filter")
        else:
            self.search_fields = self.get_param("config.uid_search_fields", None, "uid_search_fields is missing")
            self.filters = self.get_param("config.uid_search_filter")

        # Set attributes to observables
        self.attributes_to_artifacts = []
        self.attributes_to_artifacts_types = []
        if self.get_param("config.attributes_to_artifacts"): # Check if param is set (optional)
            for att_to_extract in self.get_param("config.attributes_to_artifacts"):
                if not isinstance(att_to_extract, str): # Pass None value (in case of bad settings)
                    continue
                parsed = att_to_extract.split(':')
                if len(parsed) != 2: continue
                self.attributes_to_artifacts.append(parsed[0])
                self.attributes_to_artifacts_types.append(parsed[1])

        # Set attributes to tags
        self.attributes_to_tags = []
        self.attributes_to_tags_prefix = []
        if self.get_param("config.attributes_to_tags"): # Check if param is set (optional)
            for att_to_extract in self.get_param("config.attributes_to_tags"):
                if not isinstance(att_to_extract, str): # Pass None value (in case of bad settings)
                    continue
                self.attributes_to_tags.append(att_to_extract.split(':')[0])
                self.attributes_to_tags_prefix.append(att_to_extract.split(':')[-1])

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


    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "LDAP"
        predicate = "Query"

        # Summary for filtered results
        if raw.get("filtered", None):
            taxonomies.append(self.build_taxonomy("suspicious", namespace, predicate, "filtered"))
            return {"taxonomies": taxonomies}
        # Summary for empty results
        if raw.get("results", None) == []:
            taxonomies.append(self.build_taxonomy("malicious", namespace, predicate, "no_result"))
            return {"taxonomies": taxonomies}

        # Find a value to return in value attribute of taxonomies object
        values = []
        for user in raw["results"]:
            if user.get("cn", None):
                if user["cn"] not in values: values.append(user["cn"]) 
            elif user.get("mail", None):
                if user["mail"] not in values: values.append(user["mail"]) 
            elif user.get("uid", None):
                if user["uid"] not in values: values.append(user["uid"]) 
            else:
                values.append("success")

        for value in values:
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


    def run(self):
        Analyzer.run(self)

        # Filter check
        if self.filters: # Check if filters are set
            ## Set variables
            to_filter = True
            data_to_check = self.get_param("data", None, "Data is missing")
            if self.data_type == "mail":
                data_to_check = data_to_check.split('@')[-1] # get email address' domain name
            ## Iterate on filter list
            for pattern in self.filters:
                if isinstance(pattern, str) and search(pattern, data_to_check) is not None: # If match is found: not filtered
                    to_filter = False
            ## Filter action
            if to_filter:
                if self.data_type == "mail":
                    message = "Observable value has been filtered, because domain name is not matching whitelist"
                else:
                    message = "Observable value has been filtered, because data is not matching whitelist"
                # Return filter info
                self.report({"filtered": {
                    "message": message,
                    "data": self.get_param("data", None, "Data is missing"),
                    "data_type": self.data_type,
                    "whitelist": self.filters
                    }})

                return

        try:
            # Set query
            data = self.get_param("data", None, "Data is missing")
            q = "(|"
            for field in self.search_fields:
                q += "({}={})".format(field, data)
            q += ")"

            # Send LDAP request
            self.connection.search(self.base_dn, q, SUBTREE, attributes=self.attributes)
            responses = self.connection.response

            users = []
            if responses:
                for response in responses:
                    dict_response = response.get("attributes", None)
                    user = {}
                    if dict_response:
                        for att in dict_response.keys():
                            # Skip empty attributes
                            if dict_response[att] == "" or \
                               dict_response[att] == [] or \
                               dict_response[att] is None: continue

                            # Processing depends of returned data type (list or str). More to add in the future?
                            value = ""
                            if isinstance(dict_response[att], list):
                                for i in range(len(dict_response[att])):
                                    if i == 0: value += str(dict_response[att][i])
                                    else: value += ", " + str(dict_response[att][i])
                            else:
                                value = str(dict_response[att])

                            user[att] = value
                        users.append(user)

            self.connection.unbind()

            self.report({"results": users})
        except Exception as e:
            self.error(str(e))


    def artifacts(self, raw):
        artifacts = []

        for user in raw.get("results", []):
            tags = []
            tags.append("from:" + self.get_param("data")) # Add source data tag
            # First loop to get tags to add
            for att in user.keys():
                if att in self.attributes_to_tags:
                    index = self.attributes_to_tags.index(att)
                    tags.append(self.attributes_to_tags_prefix[index] + ":" + str(user.get(att, None)))

            # Second loop to create artifacts
            for att in user.keys():
                # Skip self value
                if user.get(att, "") == self.get_param("data", None, "Data is missing"):
                    continue
                # Add artifacts
                if att in self.attributes_to_artifacts:
                    index = self.attributes_to_artifacts.index(att)
                    artifacts.append(self.build_artifact(self.attributes_to_artifacts_types[index], user.get(att, None), tags=tags))

        return artifacts


    # Testing tag addition, waiting for debug (from StrangeBee?)
    def operations(self, raw):
        operations = []

        # Tags for filtered results
        if raw.get("filtered", None):
            operations.append(self.build_operation('AddTagToArtifact', tag="ldap_filtered"))
            return operations

        # Set loop_prefix in case of multiple uid are returned
        loop_prefix = ""
        loop = 0
        for user in raw.get("results", []):
            if loop > 0: loop_prefix = "(" + str(loop) + ")"
            for att in user.keys():
                if att in self.attributes_to_tags:
                    index = self.attributes_to_tags.index(att)
                    operations.append(self.build_operation('AddTagToArtifact', tag=self.attributes_to_tags_prefix[index] + loop_prefix + ":" + str(user.get(att, None))))
            loop += 1

        # Add result tag
        if len(raw.get("results", [])) > 0:
            operations.append(self.build_operation('AddTagToArtifact', tag="ldap_ok"))
        else:
            operations.append(self.build_operation('AddTagToArtifact', tag="ldap_no_result"))

        return operations


if __name__ == "__main__":
    LdapQuery().run()
