#!/usr/bin/env python3

import json
import requests


class TheHiveApi:
	def __init__(self, api_key):
		self.api_url = "http://thehive:9000"
		self.api_v0_uri = "/api/v0"
		self.api_v1_uri = "/api/v1"
		self.api_header = {
			"Content-Type": "application/json; charset=utf-8",
			"Authorization": "Bearer " + api_key
		}
		self.proxies = {"http": "", "https": ""}


    # Generic functions, trying to match API documentation
	def query_api(self, query):
		url = self.api_url + self.api_v1_uri + "/query"

		r = requests.post(url, headers = self.api_header, json = query, proxies = self.proxies)

		if r.status_code != 200:
			exit("Fatal Error: API request failed with code " + str(r.status_code) + ". Response from server is:\n" + str(r.content))

		return json.loads(r.content)


	# More specific function, using API
	def list_cases_from_artifact_data(self, artifact_data):
		query = {
			"query": [
				{
					"_name": "listObservable",
				},
				{
					"_name": "filter",
					"_eq": {
						"_field": "data",
						"_value": artifact_data
					}
				},
				{
					"_name":"page",
					"from": 0,
					"to": 30,
					"extraData":["links"]
				},
			]
		}

		r = self.query_api(query)

		cases = {}
		# Init cases list
		for artifact in r:
			artifact_case = artifact.get("extraData", {}).get("links", {}).get("case", None)
			if artifact_case:
				case = {k: v for k, v in artifact_case.items() if k in ["_id", "number", "title", "description"]}
				case["artifacts"] = []
				cases[case["number"]] = case

		# Populate cases with artifacts details
		for artifact in r:
			artifact_case_number = artifact.get("extraData", {}).get("links", {}).get("case", {}).get("number", None)
			if artifact_case_number in cases.keys():
				cases[artifact_case_number]["artifacts"].append({k: v for k, v in artifact.items() if k in ["_id", "dataType", "data", "tags"]})

		return cases


