import csv
import sys
import argparse
import os


def read_csv(path):
    with open(path, mode='r') as file:
        # reading the CSV file
        csvFile = csv.reader(file)
        # [['CWE-ID', 'Project Name', 'Method-ID', 'Fix Commit', 'Badness', 'Tool-ID', 'Tool result', 'Size'], ['CWE-200', 'tomcat', 'java/org/apache/jasper/JspC.java$initServletContext', '05c84ff8304a69a30b251f207a7b93c2c882564d', 'false', 'pmd', '459', '29'], ['CWE-200', 'tomcat', 'java/org/apache/jasper/JspC.java$setArgs', '05c84ff8304a69a30b251f207a7b93c2c882564d', 'false', 'pmd', 'LiteralsFirstInComparisons', '110'], [
        list_of_csv = list(csvFile)
        return list_of_csv[1:]

def filter_method(sastt_list, metrics):
    #['File', 'CWE-113$undertow$HttpResponseConduit.java$2c4037efe0782cd63885cc0ec981d7da5a2bcd57$bad.java', 'CWE-113$undertow$HttpResponseConduit.java$2c4037efe0782cd63885cc0ec981d7da5a2bcd57$bad.java', '35', '1', '32', '2', '7', '', '', '', '', '1', '1', '13', '20', '', '20', '19', '13', '20', '', '4', '5', '0', '11', '', '804', '48', '698', '125', '512', '78', '', '396', '522', '124', '423', '', '64', '', '7', '', '', '0', '11', '148']
    method_list = []
    for line in metrics:
        kind = line[0]
        if "Method" in kind:
            method_list.append(line)

    print(len(method_list))

    #for line in method_list:
    for sastt_line in sastt_list:
        print(sastt_line)
        exit(1)

def leggi_file_eam(path_file_eam):
    #print(path_file_eam)

    with open(path_file_eam, mode='r') as file:
        # reading the CSV file
        csvFile = csv.reader(file)
        # [['CWE-ID', 'Project Name', 'Method-ID', 'Fix Commit', 'Badness', 'Tool-ID', 'Tool result', 'Size'], ['CWE-200', 'tomcat', 'java/org/apache/jasper/JspC.java$initServletContext', '05c84ff8304a69a30b251f207a7b93c2c882564d', 'false', 'pmd', '459', '29'], ['CWE-200', 'tomcat', 'java/org/apache/jasper/JspC.java$setArgs', '05c84ff8304a69a30b251f207a7b93c2c882564d', 'false', 'pmd', 'LiteralsFirstInComparisons', '110'], [
        list_of_csv = list(csvFile)
    return list_of_csv[1:]

def get_commit_id(fix_commit):
    with open("mappingFixCommitParentCommit.csv", mode='r') as file:
        # reading the CSV file
        csvFile = csv.reader(file)
        # [['CWE-ID', 'Project Name', 'Method-ID', 'Fix Commit', 'Badness', 'Tool-ID', 'Tool result', 'Size'], ['CWE-200', 'tomcat', 'java/org/apache/jasper/JspC.java$initServletContext', '05c84ff8304a69a30b251f207a7b93c2c882564d', 'false', 'pmd', '459', '29'], ['CWE-200', 'tomcat', 'java/org/apache/jasper/JspC.java$setArgs', '05c84ff8304a69a30b251f207a7b93c2c882564d', 'false', 'pmd', 'LiteralsFirstInComparisons', '110'], [
        list_commits = list(csvFile)
    found = False
    for elem in list_commits:
        if fix_commit in elem[0]:
            found = True
            return elem[1]
    if found == False:
        print(fix_commit)
        exit(1)

def write_result(res):
    with open('union_result.csv', 'w') as file:
        for row in res:
            file.write(row+"\n")


def create_files():
    # Lettura files
    res = []
    metrics_oss = read_csv("OSS_result.csv")
    metrics_jts = read_csv("JTS_result.csv")
    cwes = ["CWE-78", "CWE-327", "CWE-319", "CWE-613", "CWE-89", "CWE-113", "CWE-190", "CWE-601", "CWE-400"]


    for o in metrics_oss:
        cwe = o[0].split(",")[0]
        for c in cwes:
            if cwe==c:
                str_res = "OSS,"+o[0]
                print(str_res)
                res.append(str_res)

    for j, metrics_line in enumerate(metrics_jts):
        cwe = "CWE-"+metrics_jts[j][0].split(",")[0].split("CWE")[1]
        str_res = "JTS,"+cwe+","+",".join(metrics_jts[j][0].split(",")[1:])
        if cwe not in cwe:
            print(cwe)
        res.append(str_res)
    write_result(res)

if __name__ == "__main__":
    '''parser = argparse.ArgumentParser(description='Process.')

    parser.add_argument('--inputPMD', dest='inputPMD',
                        help='--inputPMD path del file PMD risultante dallo script CreateFinalDataset.java',
                        required=True)

    parser.add_argument('--inputSNYK', dest='inputSNYK',
                        help='--inputSNYK path del file SNYK risultante dallo script CreateFinalDataset.java',
                        required=True)

    parser.add_argument('--inputVCG', dest='inputVCG',
                        help='--inputVCG path del file VCG risultante dallo script CreateFinalDataset.java',
                        required=True)

    args = parser.parse_args()'''
    #create_files(args.inputPMD, args.inputSNYK, args.inputVCG)
    create_files()