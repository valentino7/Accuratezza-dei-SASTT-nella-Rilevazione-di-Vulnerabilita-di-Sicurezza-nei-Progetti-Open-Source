# RQ2


## PREREQUISITI:

- Python>= 3.7
- Networkx lib >= 2.8.5
- Graphviz lib


## Directory di Input

File di Input:
- research_1000.xml, contiene tutti i CWE della vista MITRE-RESEARCH con le relazioni tra loro,
- cwe_juliet.txt, contiene tutti i CWE di JTS,
- Juliet_intersezione_sastt.txt, contiene tutti i CWE di intersezione tra JTS e i CWE Expected dei SASTT nel nostro OSS,
- CWE_RILEVATI_INTERSEZIONE_DATASET.txt, CWE rilevati dai SASTT in OSS.

Lo script genera alberi utilizzando i CWE come nodi e le relazioni come archi.
Lo studio sul file research_1000.xml ci ha rivelato che non esiste un unico CWE padre per tutti i CWE. Quindi sono stati prodotti un numero di alberi
pari al numero di CWE genitori. Poi per visualizzare meglio il risultato è stato generato un singolo albero con una radice fittizia Root che interconnette 
le radici di tutti gli alberi.


## Directory di Output
Le directory di Output:
- `Output_Research` : Strutture relative ai CWE della vista MITRE-RESEARCH,
- `Output_Research_JTS` : Strutture relative ai CWE della vista MITRE-RESEARCH e CWE di JTS,
- `Output_Research_Vulas` : Strutture relative ai CWE della vista MITRE-RESEARCH e CWE rilevati nel dataset OSS,
- `Output_Research_Vulas_JTS` : Strutture relative ai CWE della vista MITRE-RESEARCH e CWE rilevati dai SASTT nel dataset OSS intersezione CWE di JTS .

Le directory contengono all'interno le seguenti sotto directory:
- `output_alberi`
- `output_betwenness`
- `output_degree`
- `output_level`
- `output_max_height`
- `output_min_ver_cover`
- `output_png`

Tutti i files all'interno delle cartelle sono nominati con il nome della radice dell'albero a cui fanno riferimento.
`output_alberi` contiene la rappresentazione degli alberi in formato testuale ".dot" e grafica ".pdf" mentre `output_png` contiene la rappresentazione grafica degli alberi in formato ".png".
La directory `output_level` contiene l'elenco dei nodi per ogni livello di ogni albero.

## Esecuzione script

`python Analizer_CWE_Structure `






  
