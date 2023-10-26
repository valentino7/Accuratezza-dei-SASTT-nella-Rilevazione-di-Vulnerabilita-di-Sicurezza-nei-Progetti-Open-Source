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


def read_csv_juliet(path):

    try:
        stopword = open(path, "r")
        lines = stopword.read().split('\n')
        for i,e in enumerate(lines):
            lines[i] = lines[i].strip()
        #print(lines)

        return lines
    except Exception as e:
        print(e)

def write_result(res):
    with open("result.csv", 'w', newline='') as csvfile:
        # writer = csv.DictWriter(csvfile, fieldnames = ['CWE', 'Project Name', 'Frequency'])
        #
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['CWE-ID', 'METHOD-ID','BADNESS', 'CountLine', 'actual','AvgCountLine','AvgCountLineBlank','AvgCountLineCode','AvgCountLineComment','AvgCyclomatic','CountClassBase','CountClassCoupled','CountClassCoupledModified','CountClassDerived','CountDeclClass','CountDeclClassMethod','CountDeclClassVariable','CountDeclExecutableUnit','CountDeclFile','CountDeclFunction','CountDeclInstanceMethod','CountDeclInstanceVariable','CountDeclMethod','CountDeclMethodAll','CountDeclMethodDefault','CountDeclMethodPrivate','CountDeclMethodProtected','CountDeclMethodPublic','CountInput','CountLineBlank','CountLineCode','CountLineCodeDecl','CountLineCodeExe','CountLineComment','CountOutput','CountSemicolon','CountStmt','CountStmtDecl','CountStmtExe','Cyclomatic','MaxCyclomatic','MaxInheritanceTree','MaxNesting','PercentLackOfCohesion','PercentLackOfCohesionModified','RatioCommentToCode','SumCyclomatic'])
        for el in res:
            csvwriter.writerow([el])


def create_files():
    # Lettura files
    metrics = read_csv("metrics_juliet.csv")

    #['File', 'CWE-113$undertow$HttpResponseConduit.java$2c4037efe0782cd63885cc0ec981d7da5a2bcd57$bad.java', 'CWE-113$undertow$HttpResponseConduit.java$2c4037efe0782cd63885cc0ec981d7da5a2bcd57$bad.java', '35', '1', '32', '2', '7', '', '', '', '', '1', '1', '13', '20', '', '20', '19', '13', '20', '', '4', '5', '0', '11', '', '804', '48', '698', '125', '512', '78', '', '396', '522', '124', '423', '', '64', '', '7', '', '', '0', '11', '148']
    method_list = []
    for line in metrics:
        kind = line[0]
        if "Method" in kind or "Constructor" in kind:
            method_list.append(line)


    #get_list_cwe_EAM()
    # Leggi lista dei file EAM
    eam_dir = os.listdir("EAM_con_nome_progetto")
    cwes = []

    for elem in eam_dir:
        cwes.append(elem.split("_")[0].replace("-",""))
    print(len(cwes))
    print(len(set(cwes)))
    unique_cwes = list(set(cwes))


    l = read_csv_juliet("cwe_juliet.txt")
    for i,u in enumerate(l):
        l[i] = l[i].replace("-","")
    #{'CWE601', 'CWE190', 'CWE319', 'CWE113', 'CWE613', 'CWE89', 'CWE78', 'CWE327', 'CWE400'}
    common=['CWE601', 'CWE190', 'CWE319', 'CWE113', 'CWE613', 'CWE89', 'CWE78', 'CWE327', 'CWE400']
    print(set(l) & set(unique_cwes))
    result = []
    for method in method_list:
        # filtro su cwe
        try:
            cwe_juliet = method[1].split("_")[0].split("CWE")[1]
            cwe_juliet= "CWE"+cwe_juliet
            for c in unique_cwes:
                if cwe_juliet == c:
                    if "bad" in method[1]:
                        string_res = cwe_juliet + "," + method[1] + "," + "bad" + "," + method[
                            27] + "," + ','.join(
                            method[3:27]) + "," + ','.join(method[28:])
                    if "good" in method[1]:
                        string_res = cwe_juliet + "," + method[1] + "," + "good" + "," + method[
                            27] + "," + ','.join(
                            method[3:27]) + "," + ','.join(method[28:])
                    result.append(string_res)
        except:
            #print(method[1])
            continue
        """print(cwe_juliet)
        for c in cwes:
            if cwe_juliet==c:
                string_res = cwe_id + "," + method_line[1] + "," + badness + "," + method_line[27] + "," + ','.join(method_line[3:27]) + "," + ','.join(method_line[28:])
                result.append(string_res)
        exit(1)
            # estrarre cwe
        #creare stringa di output
        """


    write_result(result)



if __name__ == "__main__":

    #create_files(args.inputPMD, args.inputSNYK, args.inputVCG)
    create_files()