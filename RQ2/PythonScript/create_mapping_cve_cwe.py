from git import Repo
import git
from pathlib import Path
import json
import re
import requests as req
import csv
import argparse


def read_csv(path):
    with open(path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        cve_list = []
        commit_list = []
        project_list = []
        for row in csv_reader:
            #print(f'\t{row[0]} works in the {row[1]} department, and was born in {row[2]}.')
            line_count += 1
            cve_list.append(row[0])
            project_list.append(row[1])
            commit_list.append(row[2])
    return cve_list, project_list, commit_list


def write_list(cve, cwe, filename):
    textfile = open(filename, "w")
    for idx, element in enumerate(cwe):
        textfile.write(cve[idx] + "," + element + "\n")
    textfile.close()


def create_output_dir():
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, r"OutputMappingCWE")
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)


def run(apikey):

    create_output_dir()
    cve_list, project_list, commit_list = read_csv("./vulas_db_msr2019_release.csv")

    url_root = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
    url_suffix = "?addOns=dictionary?CpesapiKey="+apikey
    cwe_list = []
    print(len(cve_list))

    for idx, el in enumerate(cve_list):
        url = url_root + el + url_suffix
        resp = req.get(url)
        print(resp.text)
        response_data = json.loads(resp.text)
        print(url)
        try:
            result = response_data.get('result').get('CVE_Items')[0].get('cve').get('problemtype').get('problemtype_data')[0].get('description')[0].get('value')
            cwe_list.append(result)
            print(result)
            print(idx)
        except:
            cwe_list.append("None")
        #print(resp.text) # Printing response
    write_list(cve_list, cwe_list, ".\\OutputMappingCWE\\mapping_cve_cwe.csv")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process.')

    parser.add_argument('--apikey', dest='apikey',
                        help='--apikey Inserire l apikey per effettuare le chiamate al sito del nist: https://nvd.nist.gov/developers/request-an-api-key',
                        required=True)


    args = parser.parse_args()

    run(args.apikey)
