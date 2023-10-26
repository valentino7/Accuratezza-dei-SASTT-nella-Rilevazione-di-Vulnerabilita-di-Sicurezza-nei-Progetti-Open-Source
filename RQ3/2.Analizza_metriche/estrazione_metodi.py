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
        print(list_of_csv[0][27:])
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
    with open("OSS_result.csv", 'w', newline='') as csvfile:
        # writer = csv.DictWriter(csvfile, fieldnames = ['CWE', 'Project Name', 'Frequency'])
        #
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['CWE-ID', 'METHOD-ID','BADNESS', 'CountLine', 'actual','AvgCountLine','AvgCountLineBlank','AvgCountLineCode','AvgCountLineComment','AvgCyclomatic','CountClassBase','CountClassCoupled','CountClassCoupledModified','CountClassDerived','CountDeclClass','CountDeclClassMethod','CountDeclClassVariable','CountDeclExecutableUnit','CountDeclFile','CountDeclFunction','CountDeclInstanceMethod','CountDeclInstanceVariable','CountDeclMethod','CountDeclMethodAll','CountDeclMethodDefault','CountDeclMethodPrivate','CountDeclMethodProtected','CountDeclMethodPublic','CountInput','CountLineBlank','CountLineCode','CountLineCodeDecl','CountLineCodeExe','CountLineComment','CountOutput','CountSemicolon','CountStmt','CountStmtDecl','CountStmtExe','Cyclomatic','MaxCyclomatic','MaxInheritanceTree','MaxNesting','PercentLackOfCohesion','PercentLackOfCohesionModified','RatioCommentToCode','SumCyclomatic'])
        for el in res:
            csvwriter.writerow([el])


def create_files():
    # Lettura files
    metrics = read_csv("metrics_oss2.csv")
    #['File', 'CWE-113$undertow$HttpResponseConduit.java$2c4037efe0782cd63885cc0ec981d7da5a2bcd57$bad.java', 'CWE-113$undertow$HttpResponseConduit.java$2c4037efe0782cd63885cc0ec981d7da5a2bcd57$bad.java', '35', '1', '32', '2', '7', '', '', '', '', '1', '1', '13', '20', '', '20', '19', '13', '20', '', '4', '5', '0', '11', '', '804', '48', '698', '125', '512', '78', '', '396', '522', '124', '423', '', '64', '', '7', '', '', '0', '11', '148']
    method_list = []
    for line in metrics:
        kind = line[0]
        if "Method" in kind or "Constructor" in kind:
            method_list.append(line)
    print(len(method_list))

    # Leggi lista dei file EAM
    eam_dir = os.listdir("EAM")
    c = 0
    idx = 0
    d = {}
    result = []
    for elem in eam_dir:
        idx =idx+1
        file_eam = leggi_file_eam("EAM\\" + elem)
        # Sfoglio le righe del file eam esempio:
        # ['CWE-113_core/src/main/java/io/undertow/server/protocol/http/HttpResponseConduit.java$writeString_85d4478e598105fe94ac152d3e11e388374e8b8_false','PROJECT NAME', '11', '0.0', 'no']

        for line in file_eam:
            elements = line[0].split("$")

            cwe_id = elements[0]

            path_file_java = elements[1]

            class_name = path_file_java.split("/")[len(path_file_java.split("/")) - 1].replace(".java","")

            path_file_java = path_file_java.replace(class_name,"").replace(".java","").replace("/","")

            method_id = elements[2]

            fix_commit_id = elements[3]
            badness = elements[4]

            project_name = line[1]

            if badness == "true":
                commit = get_commit_id(fix_commit_id)
            else:
                commit = fix_commit_id

            if badness == "true":
                badness = "bad"
            else:
                badness = "good"


            nome_file = cwe_id + "$" + project_name + "$" + path_file_java +"$"+class_name + "$" + commit + "$" + badness + ".java"


            found = False
            for method_line in method_list:
                metrics_method_name = method_line[1].split(".")[len(method_line[1].split("."))-1]



                if metrics_method_name == method_id and nome_file == method_line[2]:
                    print("////////-TROVATO K-------------")
                    print(method_line[1].split(".")[len(method_line[1].split("."))-1])
                    print(method_line)
                    print("---------TROVATO K-------------")
                    found = True
                    string_res = cwe_id + "," +  method_line[1] + "," + badness + "," + method_line[27] + "," + ','.join(method_line[3:27]) + "," + ','.join(method_line[28:])
                    result.append(string_res)

            if found == False:
                print("nome classe")
                print(elem)
                print(fix_commit_id)
                print(nome_file)
                print(method_id)
                print("indice delle cartelle")
                print(idx)
                tmp = []
                tmp.append(elem)
                tmp.append(fix_commit_id)
                tmp.append(nome_file)
                tmp.append(method_id)
                d[str(c)] = tmp
                print("false")
                print("--------------------------")
                c = c + 1

    print(c)
    print(d)
    write_result(result)



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