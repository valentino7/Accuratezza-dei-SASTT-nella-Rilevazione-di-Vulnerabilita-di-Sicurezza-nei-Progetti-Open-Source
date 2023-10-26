import shutil
import os
import csv


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

def main():

    # Leggi lista dei file EAM
    eam_dir = os.listdir("F:\Valentino\FamilyTree\RISULTATI\RQ3\EAM_con_nome_progetto")
    for elem in eam_dir:
        file_eam = leggi_file_eam("F:\Valentino\FamilyTree\RISULTATI\RQ3\EAM_con_nome_progetto\\"+elem)

        # Sfoglio le righe del file eam esempio:
        # ['CWE-113_core/src/main/java/io/undertow/server/protocol/http/HttpResponseConduit.java$writeString_85d4478e598105fe94ac152d3e11e388374e8b8_false','PROJECT NAME', '11', '0.0', 'no']

        for line in file_eam:

            elements = line[0].split("$")
            cwe_id = elements[0]
            print(elements)
            fix_commit_id = elements[3]
            badness = elements[4]
            #print(elements)

            path_file_java = elements[1]
            print(path_file_java)

            class_name = path_file_java.split("/")[len(path_file_java.split("/"))-1]
            print(class_name)
            #print(fix_commit_id)
            #print(badness)

            project_name = line[1]
            #path_file_java = '/'.join(path_file_java)

            #print(path_file_java)
            #print(project_name)


            # Spostamento del file nella directory appena creata
            if badness == "true":
                commit = get_commit_id(fix_commit_id)
            else:
                commit = fix_commit_id

            if badness == "true":
                badness = "bad"
            else:
                badness = "good"

            nome_file = cwe_id + "$" + project_name + "$" + class_name + "$" + commit + "$" + badness + ".java"

            # Creazione directory CWE-ID che conterrà i files
            try:
                os.mkdir("F:\\Valentino\\eam_java_files\\"+ badness + "\\" + cwe_id)
            except :
                print("creato")

            try:
                shutil.copyfile("F:\\Valentino\\Progetti_da_buildare_2\\"+project_name+commit+"\\"+ path_file_java, "F:\\Valentino\\eam_java_files\\"+badness+"\\"+cwe_id+ "\\" +nome_file)
                print("Spostato: "+ "F:\\Valentino\\Progetti_da_buildare_2\\"+project_name+commit+"\\"+ path_file_java)
            except:
                print("_-------------------------------------_")
                print("F:\\Valentino\\Progetti_da_buildare_2\\"+project_name+commit+"\\"+ path_file_java)
                print("_-------------------------------------_")
                print("F:\\Valentino\\eam_java_files\\" + cwe_id + "\\" + nome_file)
                print("_-------------------------------------_")
                print(cwe_id)
                exit(1)



if __name__ == "__main__":
    #main()
    main()