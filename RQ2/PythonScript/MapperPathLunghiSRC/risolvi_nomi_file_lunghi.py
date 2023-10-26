import shutil
import csv
import os, os.path
import shutil

def read_csv(path):
    with open(path, mode='r') as file:
        # reading the CSV file
        csvFile = csv.reader(file)
        # "CWE-ID","Project-Name","Method-ID","Fix Commit","Parent Commit","Badness","Tool-ID","Size","Start","End"
        list_of_csv = list(csvFile)
        return list_of_csv[1:]


def write_f(path, res):
    with open("MAP.csv", 'w', newline='') as csvfile:
        # writer = csv.DictWriter(csvfile, fieldnames = ['CWE', 'Project Name', 'Frequency'])
        #
        csvwriter = csv.writer(csvfile)
        for el in res:
            csvwriter.writerow([el])




"""
STANRDA USATO:
- senza .java nella classe
- commit reale 
CWE-20$activemq$activemq-clientsrcmainjavaorgapacheactivemq$ActiveMQConnection$338a74dfa42a7b19d39adecacfa5f626a050e807
"""
def main():


    #########################################CONFRONTO INTERMEDIATE CON SOURCE COPIATI#############################

    # Leggi lista dei file SRC

    # Obiettivo-> cwe$classe$commit
    root_src = "src"
    eam_dir = os.listdir(root_src)

    # Controllo se nel nome del file non esistono altri simboli dollaro
    for elem in eam_dir:
        files = os.listdir(root_src + "\\" + elem)
        # bad $ 4faaca9353e5e3f963c7a674b3ac6a0bd1c3757e $ connectorshttp11srcjavaorgapachecoyotehttp11 $ Http11AprProcessor
        for i, file in enumerate(files):
            if len(file.split("$"))>4:
                print(elem)
                print(file)
                exit(1)

    print("---------------------------\n-----------------------\nNon sono presenti simboli ulteriori al dollaro\n--------------------------------\n--------------------------")
    count = 0
    # Sdoppia cartelle
    for elem in eam_dir:
        if "_" in elem:
            cwes = elem.split("_")
            for cwe in cwes:
                if not os.path.exists(root_src+"\\"+cwe):
                    os.makedirs(root_src+"\\"+cwe)
                # copia file nelle cartelle sdoppiate
                files = os.listdir(root_src + "\\" + elem)
                # bad $ 4faaca9353e5e3f963c7a674b3ac6a0bd1c3757e $ connectorshttp11srcjavaorgapachecoyotehttp11 $ Http11AprProcessor
                for i, file in enumerate(files):
                    shutil.copyfile(
                        root_src+"\\"+elem+"\\"+file,
                        root_src+"\\"+cwe+"\\"+file)
    for elem in eam_dir:
        if "_" in elem:
            shutil.rmtree(root_src + "\\" + elem)


    """
    # Elimina file duplicati
    file_da_eliminare = []
    for elem in eam_dir:
        files = os.listdir(root_src + "\\" + elem)
        # bad $ 4faaca9353e5e3f963c7a674b3ac6a0bd1c3757e $ connectorshttp11srcjavaorgapachecoyotehttp11 $ Http11AprProcessor
        for i, file in enumerate(files):
            file_da_eliminare.append(file)

            #os.remove(root_src + "\\" + elem+"\\"+file)
    """
    ## TODO RIMUOVI CARTELLA CON CWE DUP

    # Rinomina i file
    eam_dir = os.listdir(root_src)
    map = []
    for elem in eam_dir:
        files_spostati_list = []

        files = os.listdir(root_src+"\\"+elem)
        #bad $ 4faaca9353e5e3f963c7a674b3ac6a0bd1c3757e $ connectorshttp11srcjavaorgapachecoyotehttp11 $ Http11AprProcessor
        for i, file in enumerate(files):
            #str = elem  + "$" +  file.split("_")[0] + "$" + file.split("_")[1] + "$" +file.split("_")[2].replace(".java","")
            #str = elem + "$" + file.split("$")[0] + "$" + file.split("$")[1] + "$" + file.split("$")[3]

            new_filename = file.split("$")[0] + "$" + file.split("$")[1] +"$"+ str(i) +"$" + file.split("$")[3]
            files_spostati_list.append(file)
            print(elem+"$"+str(i)+","+file.split("$")[2])
            map.append(elem+"\\"+str(i)+","+file.split("$")[2])
            os.rename("src\\"+elem+"\\"+file, "src\\"+elem+"\\"+new_filename)
    write_f("mappa_path.csv", map)




if __name__ == "__main__":
    main()