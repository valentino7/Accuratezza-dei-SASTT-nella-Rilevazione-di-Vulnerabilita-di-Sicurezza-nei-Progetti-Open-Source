# RQ3

## Prerequisiti
 - Python>= 3.7

## Alberatura
- RQ3/1.Creazione_cartella_file_EAM: lo script Python `sposta_file_java_eam.py` presente all'interno della directory, riceve in input la directory contenente i progetti Java,
  legge successivamente il path dei file java da riunire nei file EAM e sposta tali file nella directory di output: `eam_java_files`.
- RQ3/2.Analizza_metriche: `estrazione_metodi.py` questo script estrae da `metrics_oss2.csv` (che contiene le metriche per tutti i metodi Java delle classi organizzate al punto precedente)
  i soli metodi Java toccati dalle fix commit rispetto alle parent commit nei 31 CWE rilevati dai SASTT, file di output prodotto: `OSS_result.csv`.
  `Analisi Juliet/analisi_juliet.py` estrae `metrics_juliet.csv` i soli metodi che si riferiscono ai CWE rilevati dai SASTT, file di output: `JTS_result.csv`.
  `RQ3_FinalRes/unisci_file.py` e `RQ3_FinalRes/rimuovi_colonne_ininformative.py` raccoglie i due file di output precedenti e li unisce in unico file inserendo una prima colonna Type: `OSS` o `JTS`.
  output: `RQ3_FinalRes/Result_RQ3.csv`.
- Risultati Confronto: viene analizzato `RQ3_FinalRes/Result_RQ3.csv` e vengono prodotti i grafici del confronto tra OSS e JTS
