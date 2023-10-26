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



def read_cwe_list(path):
    f = open(path, "r")
    s = f.read()
    l = s.split()
    return l


def write_file_eam(path, l):
    print(path)
    with open(path, 'w', newline='') as csvfile:
        #writer = csv.DictWriter(csvfile, fieldnames = ['CWE', 'Project Name', 'Frequency'])
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['filename', 'project_name','size', 'prediction', 'actual'])
        for el in l:
            csvwriter.writerow([el['filename'], el['project_name'],el['size'], el['expected'], el['actual']])


def get_cwe_list(l):
    cwes = []
    for elem in l:
        # [CWE-ID,"Project Name","Method-ID","Fix Commit","Badness","Tool-ID","Tool result","Size","TP","TN","FP","FN"]
        cwes.append(elem[0])
    print(len(cwes))
    s = set(cwes)
    print(len(list(s)))
    return list(s)


def run(cwes, tool_elements, tool_id):
    for c in cwes:
        result = []
        found = False
        for elem in tool_elements:
            if elem[0] == c and (elem[8] == "True" or elem[9] == "True" or elem[10] == "True" or elem[11] == "True"):
                found = True
                d = {}
                d["filename"] = elem[0] + "$" + elem[2] + "$" + elem[3] + "$" + elem[4]
                d["size"] = elem[7]
                d["project_name"] = elem[1]
                """
                TP: 1.0, Yes
                TN: 0.0, No
                FP: 1.0, No
                FN: 0.0, Yes"""
                if elem[8] == "True":
                    d["expected"] = 1.0
                    d["actual"] = "yes"
                elif elem[9] == "True":
                    d["expected"] = 0.0
                    d["actual"] = "no"
                elif elem[10] == "True":
                    d["expected"] = 1.0
                    d["actual"] = "no"
                elif elem[11] == "True":
                    d["expected"] = 0.0
                    d["actual"] = "yes"
                result.append(d)
        if found:
            # write file name = cwe_tool.csv -> filename - size - prediction - actual
            write_file_eam(".\\EAM\\"+c+"_"+tool_id+".csv", result)

def create_output_dir():
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, r"EAM")
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)


def create_files(pmd_path, snyk_path, vcg_path):
    create_output_dir()
    # Lettura files
    l_pmd = read_csv(pmd_path)
    l_snyk = read_csv(snyk_path)
    l_vcg = read_csv(vcg_path)

    pmd_cwes = get_cwe_list(l_pmd)
    vcg_cwes = get_cwe_list(l_vcg)
    snyk_cwes = get_cwe_list(l_snyk)

    run(vcg_cwes, l_vcg, "vcg")
    run(snyk_cwes, l_snyk, "snyk")
    run(pmd_cwes, l_pmd, "pmd")

def create_files_pmd(snyk_path):
    create_output_dir()
    # Lettura files
    l_pmd = read_csv(snyk_path)

    pmd_cwes = get_cwe_list(l_pmd)


    run(pmd_cwes, l_pmd, "snyk")


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
    create_files("PMD.csv", "SNYK.csv", "VCG.csv")
