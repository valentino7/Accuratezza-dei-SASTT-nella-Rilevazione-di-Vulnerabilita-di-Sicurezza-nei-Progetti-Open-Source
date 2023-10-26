import csv
import os
import sys
from git import Repo
import git


def compile_project(cmd):
    rc = os.system(cmd)
    if rc != 0:
        if cmd == 'mvn compile':
            print("command: "+ cmd)
            rc = os.system('ant compile')
            if rc != 0:
                sys.exit(1)
            return
        elif cmd == 'ant compile':
            print("command: " + cmd)
            rc = os.system('mvn compile')
            if rc != 0:
                sys.exit(1)
            return
        sys.exit(1)


def open_excel(name):
    l = []
    commits = []
    with open(name, mode='r') as file:
        # reading the CSV file
        csvFile = csv.reader(file, delimiter=';')
        # displaying the contents of the CSV file
        for lines in csvFile:
            d = {}
            d[lines[0]] = lines[1]
            l.append(d)
            commits.append(lines[2])
        return l, commits


def clone_project(url, filename):
    if not os.path.exists(filename):
        os.mkdir(filename)
    if len(os.listdir(filename)) == 0:
        try:
            Repo.clone_from(url, filename)
        except:
            print(filename)
            print("errore")


def create_output_dir():
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, r"Repositories")
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)



def download_p():
    name = "./filter_vulas_db.csv"
    create_output_dir()
    l, commits = open_excel(name)

    i = 0
    for element in l:
        #os.chdir("spring-webflow")
        project_url = list(element.values())[0]
        filename = project_url.split("/")[-1]

        print(project_url)
        print(filename)

        clone_project(project_url, ".\\Repositories\\" +filename)

        i=i+1


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    download_p()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/