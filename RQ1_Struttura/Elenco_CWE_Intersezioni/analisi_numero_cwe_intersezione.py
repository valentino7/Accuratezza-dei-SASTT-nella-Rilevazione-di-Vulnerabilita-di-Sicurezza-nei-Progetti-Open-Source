import csv
import sys
from numpy import loadtxt
import os


def read_l1(path):
    try:
        stopword = open(path, "r")
        lines = stopword.read().split('\n')
        for i, e in enumerate(lines):
            lines[i] = lines[i].strip()
        # print(lines)

        return lines
    except Exception as e:
        print(e)


def read_f(path):
    res = []
    with open(path, 'r') as file:
        righe = file.readlines()  # Ottieni una lista di righe
        for riga in righe:
            res.append(riga.replace("\n", ""))
    # print(res)
    return res


def read_dir(path):
    res = []
    list_cwe = os.listdir(path)

    for elem in list_cwe:
        res.append(elem.split("_")[0])

    return list(set(res))


def write_file(path, l):
    print(path)
    with open(path, 'w', newline='') as csvfile:
        # writer = csv.DictWriter(csvfile, fieldnames = ['CWE', 'Project Name', 'Frequency'])
        csvwriter = csv.writer(csvfile)
        for el in l:
            csvwriter.writerow([el])


def prova():
    # ANALISI RQ1 DATASET - RESEARCH - JULIET
    juliet = read_l1("cwe_juliet.txt")
    research = read_l1("cwe_mitre.txt")
    sastt_intersezione_dataset = read_l1("CWE_RILEVATI_INTERSEZIONE_DATASET.txt")

    # Juliet intersezione Research
    res = list(set(juliet) & set(research))
    print(len(res))
    write_file("Juliet_intersezione_Research.txt", res)

    # Juliet intersezione sastt
    res1 = list(set(juliet) & set(sastt_intersezione_dataset))
    print(len(res1))
    write_file("Juliet_intersezione_sastt.txt", res1)

    # sastt research
    res2 = list(set(research) & set(sastt_intersezione_dataset))
    print(len(res2))
    write_file("sastt_intersezione_research.txt", res2)

    # sastt research juliet
    res3 = list(set(research) & (set(sastt_intersezione_dataset) & set(juliet)))
    print(len(res3))
    write_file("sastt_intersezione_research_inter_juliet.txt", res3)


if __name__ == "__main__":
    # main()
    prova()