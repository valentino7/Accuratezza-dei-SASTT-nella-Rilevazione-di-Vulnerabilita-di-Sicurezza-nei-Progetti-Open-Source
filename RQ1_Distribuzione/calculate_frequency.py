from pathlib import Path
import json
import re
import requests as req
import os
import matplotlib.pyplot as plt
import numpy as np
import csv
import statistics
import seaborn as sns
import pandas as pd

def create_output_dir(str):
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, str)
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)

def read_vulas(path, sep):
    with open(path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=sep)
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


def read_mapping(path):
    with open(path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        cve_list = []
        cwe_list = []
        for row in csv_reader:
            #print(f'\t{row[0]} works in the {row[1]} department, and was born in {row[2]}.')
            line_count += 1
            cve_list.append(row[0])
            cwe_list.append(row[1])
    return cve_list, cwe_list


def write_dict(d, filename):
    with open(filename, 'w', newline='') as csvfile:
        #writer = csv.DictWriter(csvfile, fieldnames = ['CWE', 'Project Name', 'Frequency'])
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['CWE', 'Project Name', 'Frequency', 'Owner'])
        for k, v in d.items():
            csvwriter.writerow([k.split(",")[0], k.split("/")[-1], str(v), k.split("/")[3]])


def calculate_freq(l, filename, stat_path):
    l_key = list(set(l))

    result = {}
    for key in l_key:
        value = 0
        for c in l:

            if key == c:
                value += 1
        result[key] = value

    write_dict(result, filename)
    print(result.values())
    print("Mediana: "+str(statistics.median(result.values())))

    count = 0
    for v in result.values():
        if v == 1:
            count += 1

    with open(stat_path, 'w') as f:
        f.write("FREQUENZE: ")
        for key, value in result.items():
            f.write('%s' % (value))
            f.write(' ')
        f.write('\n')

        f.write("Mediana: "+str(statistics.median(result.values())))
        f.write('\n')

        f.write("Numero di volte in cui compare la mediana : " + str(count))
        f.write('\n')

        f.write("Media: "+str(statistics.mean(result.values())))
        f.write('\n')

        f.write("Moda: "+str(statistics.mode(result.values())))
        f.write('\n')

        f.write("Varianza: "+str(statistics.variance(result.values())))
        f.write('\n')
    f.close()


cve_list, project_list, commit_list = read_vulas("./Input_no_filtered/vulas_db_msr2019_release.csv",",")
cve_list_filter, project_list_filter, commit_list_filter = read_vulas("./Input_filtered/vulas_db_without_invalid_cve.csv", ";")
cve_map_filter, cwe_map_filter = read_mapping("./Input_filtered/mapping_cve_cwe.csv")
cve_map, cwe_map = read_mapping("./Input_no_filtered/mapping_cve_cwe.csv")


for i, cve in enumerate(cve_list):
    for i2, cve_m in enumerate(cve_map):
        if cve == cve_m:
            cve_list[i] = cwe_map[i2]

l = []

for i, c in enumerate(cve_list):
    l.append(cve_list[i]+","+project_list[i])

l1 = []
for i,c in enumerate(cve_list):
    l1.append(cve_list[i])

create_output_dir("Output_no_filtered")
calculate_freq(l, "./Output_no_filtered/RQ1_no_filtered_freq_cwe_project.csv", "./Output_no_filtered/RQ1_stats_no_filtered.txt")


for i, cve in enumerate(cve_list_filter):
    for i2, cve_m in enumerate(cve_map_filter):
        if cve == cve_m:
            cve_list_filter[i] = cwe_map_filter[i2]

l_filter = []

for i, c in enumerate(cve_list_filter):
    l_filter.append(cve_list_filter[i]+","+project_list_filter[i])

l1_filter = []
for i,c in enumerate(cve_list_filter):
    l1_filter.append(cve_list_filter[i])


create_output_dir("Output_filtered")
calculate_freq(l_filter, "./Output_filtered/RQ1_filtered_freq_cwe_project.csv", "./Output_filtered/RQ1_stats_filtered.txt")

