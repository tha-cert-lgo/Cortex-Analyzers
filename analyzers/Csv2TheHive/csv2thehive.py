#!/usr/bin/env python3
# Author: Lenaic GOUDOUT
from cortexutils.analyzer import Analyzer
import json
import csv

class Csv2TheHive(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.filepath = self.get_param("file", None, "File parameter is missing.")
        self.filename = self.get_param("filename", None, "Filename is missing.")

        self.mail_mapping = self.get_param("config.mail_mapping")
        if self.mail_mapping is None or self.mail_mapping is [None]: self.mail_mapping = []

        self.username_mapping = self.get_param("config.username_mapping")
        if self.username_mapping is None or self.username_mapping is [None]: self.username_mapping = []

        self.to_sanitize = self.get_param("config.to_sanitize")
        if self.to_sanitize is None or self.to_sanitize is [None]: self.to_sanitize = []



        if not self.get_csv_delimiter(self.filepath):
            exit("[ERROR] Error while searching for csv delimiter. File is probably not csv file.")
        # Todo: get file's tags to add them to new artifacts


    def run(self):
        Analyzer.run(self)

        file_content = []
        raw = {"sanitized": []}


        with open(self.filepath, 'r', newline='') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=self.csv_delimiter, quotechar=self.csv_quotechar)

            headers = next(csvreader)
            columns_to_sanitize = [] # To identify sensitive columns, in order to sanitze it.
            for i in range(len(headers)):
                if headers[i].lower() in self.to_sanitize:
                    columns_to_sanitize.append(i)
                    raw["sanitized"].append(headers[i].lower())

            # Create data for report
            data = {}
            row_number = 0
            for row in csvreader:
                data_row = {}
                for i in range(len(headers)):
                    if row[i] is None or row[i] == "":
                        continue
                    elif i in columns_to_sanitize: # To sanitize data
                        data_row[headers[i]] = sanitize(row[i])
                    else:
                        data_row[headers[i]] = row[i]

                data[row_number] = data_row
                row_number += 1

        raw["data"] = data

        # Todo: lead a reflexion to build a proper report if needed
        self.report(raw)


    # def summary(self, raw):
    #     taxonomies = []
    #     namespace = ""
    #     predicate = ""
    #     stats_field = ""
    #     results_field = ""

    #     taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

    #     return {"taxonomies": taxonomies}


    def artifacts(self, raw):
        artifacts = []

        for i in range(len(raw["data"])):
            tags = ['from:' + self.filename, 'row:' + str(i)]
            for key in raw["data"][i]: # Iterate to prepare tags
                tags.append(key.lower() + ":" + raw["data"][i][key])

            for key in raw["data"][i]: # Iterate to extract artifacts
                if key in self.mail_mapping: # Create artifact of type mail
                    tags.remove(key.lower() + ":" + raw["data"][i][key])
                    artifacts.append(self.build_artifact('mail', raw["data"][i][key], tags=tags + ['autoImport:true'])) # ['autoImport:true'] imports mail directly as observables
                elif key in self.username_mapping: # Create artifact of type mail
                    tags.remove(key.lower() + ":" + raw["data"][i][key])
                    artifacts.append(self.build_artifact('username', raw["data"][i][key], tags=tags))

        return artifacts


    def operations(self, raw):
        operations = []

        for col in raw["sanitized"]:
            operations.append(self.build_operation("AddTagToArtifact", tag=str(col) + ":sanitized"))

        return operations


    def get_csv_delimiter(self, file_path):
        f = open(file_path, 'r', newline='')

        try:
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(f.readline())

            self.csv_delimiter = dialect.delimiter
            self.csv_quotechar = dialect.quotechar
        except:
            f.close()
            return False

        f.close()
        return True


def sanitize(string):
    sanitized = ""
    for i in range(len(string)):
        if i < 2: sanitized += string[i]
        else: sanitized += "*"

    return sanitized


if __name__ == "__main__":
    Csv2TheHive().run()
