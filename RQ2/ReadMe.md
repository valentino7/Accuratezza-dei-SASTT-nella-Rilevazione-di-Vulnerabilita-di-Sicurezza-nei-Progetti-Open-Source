# RQ2

## Prerequisiti
 - Python>= 3.7
 - Libreria gitPython con git installato sul sistema:
   
   	`pip install GitPython`
 - JDK >= 8
 - Maven3
 - Richiedere apikey al nist: `https://nvd.nist.gov/developers/request-an-api-key`
 - Installazione di Snyk, Pmd, Vcg, git e Wls

## Alberatura
Nella directory RQ2/PythonScript sono presenti gli script in python:

- create_mapping_cve_cwe.py
- download_project.py
- /CreateEAMfiles/create_EAM_files.py
- /MapperPathLunghiSRC/risolvi_nomi_file_lunghi.py

Directory di Output per gli script python:

- RQ2/PythonScript/CreateEAMfilesEAM/EAM
- RQ2/PythonScript/OutputMappingCWE
- RQ2/PythonScript/Repositories


Directory contenente l'eseguibile per PMD e [Snyk](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) :

- RQ2/plugins

Vcg è scaricabile a questo [URL](https://sourceforge.net/projects/visualcodegrepp/)

Progetto in Java:

- RQ2JavaProject
  	- `src/main/java/controller`: Classi Java da eseguire
  	- `src/main/java/entity`: Classi Java contenente le entità utilizzate
  	- `src/main/java/resources`: Directory di Input e Output
  	- `src/main/java/common`: Classi Java utilizzate in comune
  	- `src/main/java/IO`: Classi Java per lettura e scrittura su files
  	- `src/main/java/utils`: Classi Java conenenti le costanti utilizzate nel progetto e i file Lexer per parsare i metodi Java
  	  

## Processo

### Fase 1

Il seguente script effettua il download dei progetti creando la cartella Repositories nel path dove è presente questo script:

**Input**
 - `filter_vulas_db.csv`: formato dalle triple [CWE;Project Name;Frequency;Owner]. Questo file va inserito nel path allo stesso livello dell'eseguibile. Questo file viene creato filtrando dal dataset di input (`vulas_db_msr2019_release.csv`) tutti quei i progetti che non hanno un repository url valido mantenendo però i CVE invalidi, ossia quei CVE che vengono mappati sui seguenti 3 CWE: NVD-CWE-noinfo, NVD-CWE-Other, None.

**Output**
- `Repositories`: Directory che conterrà i progetti scaricati. Creare la directory Repositories se non esistesse.
  
**Script**
- `download_project.py`

**Run**
- `python download_project.py`  


&nbsp;


### Fase 2

**Progetto Java**

Il seguente progetto Java è presente nella directory: `./RQ2JavaProject`. 

Tutti i path di Input e Output sono contenuti nel file `src/main/java/utils/Constants.java`.


Questo script prende in input i progetti scaricati nella Fase 1 e genera nella directory `src/main/java/resources/ProgettiFixParentCommit` due ulteriori directory per ogni progetto letto:

	- una directory per il progetto riferente alla fix commit 
 	- una directory per il progetto riferente alla parent commit.

**Input**
-  `Constants.PATH_PROJECT_REPOSITORIES`: directory contenente i progetti scaricati. vA RIEMPITA CON IL Repositories CREATO IN output NEL punto precedente. `src/main/java/resources/Repositories`. Creare manualmente la directory Repositories se non esistesse.

**Output**
-  `Constants.PATH_PROJECT_ROOT`: directory contenente il risultato della seguente classe Java. Contiene i progetti fix e parent commit. Creare questa directory manualmente se non esistesse.

**Classe Java**
-  `src/main/java/controller/CreateFixParentDir.java`

	
&nbsp;


### Fase 3

Il seguente script in Python crea un file csv di mapping da cve a cwe creando la cartella `OutputMappingCWE` nel path dove è presente questo script.

**Prerequisiti**
 - Apikey del nist

**Input**
 - `vulas_db_msr2019_release.csv`: dataset iniziale da inserire allo stesso livello dell'eseguibile. Contiene le triple [CWE;Project Name;Frequency;Owner]. 


**Script**
- `RQ2/PythonScript/create_mapping_cve_cwe.py`

**Run**
- `python create_mapping_cve_cwe.py`


NB:
il file di output `filter_mapping_cve_cwe` è il risulato di ulteriori manipolazioni, ovvero la cancellazione dei 3 CWE invalidi: NVD-CWE-Other, None.


&nbsp;


### Fase 4
La seguente classe Java genera l'Intermediate Result e le cartelle contenenti i file Java toccati dalle commit nella directory.

**Input**
- `Constants.PATH_VULAS_DB`: dataset di input dopo aver filtrato i CWE invalidi e i progetti non aventi un repository url valido;
- `Constants.FILTER_PATH_MAPPING_CVE`: file filter_mapping_cve_cwe creato nella fase precedente;
- `Constants.PATH_PROJECT_REPOSITORIES`: directory contenente i progetti scaricati nella fase 1;
- `Constants.PATH_PROJECT_ROOT`: directory contenente i progetti divisi per fix e parent commit.

**Output**
- `Constants.JAVA_SRC`: contenente le classi java da includere nei tool divise per sotto directory rinominate con il CWE_ID;
- `Constants.INTERMEDIATE_PATH_RESULT`: risultato di questa fase

**Classe Java**
- `src/main/java/controller/FillMethodInfoCommit.java`


&nbsp;

### Fase 5a ANALISI SASTT

Il seguente script in Python mappa i path contenuti nei nomi dei file java nella directory `Constants.JAVA_SRC` creata al punto precedente. 


**Input**
 -`Constants.JAVA_SRC`

**Output**
 -`Constants.JAVA_SRC`: con nomi file modificati;
 - `/MapperPathLunghiSRC/risolvi_nomi_file_lunghi.py/MAP_path.csv` : file di mapping per ritrovare il path al quale un file appartiene.

**Script**
- `/MapperPathLunghiSRC/risolvi_nomi_file_lunghi.py`

**Run**
- `python risolvi_nomi_file_lunghi.py`


&nbsp;

### Fase 5b ANALISI SASTT
La seguente classe Java consente di avviare PMD. I PATH da cambiare per essere puntati nel proprio file system sono:
- `Constants.BIN_TOOLS`: directory plugins contenente il bin di PMD;
- `Constants.JAVA_SRC_RUNNER_TOOLS`: directory src contente i file java da analizzare suddivisi nella fase precedente;
- `Constants.PMD_PATH_REPORT_RESULT_MNT`: directory contenente i file di output;

**Prerequisiti**
- Powershell;
- WSL;
- Modificare il path assoluto di Constants.BIN_TOOLS per farla puntare a "/Pacchetto di replicabilità/plugins" dove è presente il contenuto: "/pmd-bin-6.44.0/bin" .


**Input**
- `Constants.BIN_TOOLS`: directory plugins contenente il bin di PMD;
- `Constants.JAVA_SRC_RUNNER_TOOLS`: directory src contente i file java da analizzare suddivisi nella fase precedente;

**Output**
- `Constants.PMD_PATH_REPORT_RESULT_MNT`: directory contentente i report prodotti da PMD in formato XML.

**Classe Java**
- `src/main/java/controller/RunnerTools.java`



&nbsp;

### Fase 5c ANALISI SASTT
In questa fase viene prodotto il risultato analizzando la cartella dei file Java `Constants.BIN_TOOLS` con VisualCodeGrepper. Quindi installare il SASTT ed eseguirlo impostando il linguaggio Java sulla directory appena menzionata, `Constants.BIN_TOOLS`.
Il report prodotto deve essere inserito nel seuente path: `Constants.REPORT_RESULTS/vcg/`


&nbsp;

### Fase 5d ANALISI SASTT
Questa classe Java serve per creare un file di mapping tra la fix commit e la parent commit (fix e bad commit),
che verrà successivamente utilizzato da snyk per velocizzare il recupero delle commit.


**Input**
- `Constants.PATH_VULAS_DB`: dataset iniziale dal quale ricavare la fix commit;
- `Constants.PATH_PROJECT_REPOSITORIES`: directory contenente i progetti Java da cui ricavare la parent commit;

**Output**
- `Constants.MAPPING_FIX_PARENT_COMMIT`: file di mapping prodotto.

**Classe Java**
- `src/main/java/controller/CreateMappingParentSonCommit.java`


&nbsp;

### Fase 5e ANALISI SASTT
Questa classe Java esegue il SASTT Snyk utilizzando Powershell.
Snyk viene avviato sugli interi progetti passati in input.

**Prerequisiti**
- Installare Powershell;
- Installare WSL;
- Installare eseguibile "snyk-win.exe" presente in "/RQ2/plugins".

**Input**
- `Constants.PATH_VULAS_DB`: dataset iniziale vulas;
- `Constants.MAPPING_FIX_PARENT_COMMIT`: file di mapping creato nella fase precedente.

**Output**
- `Constants.REPORT_RESULTS/snyk`: directory di output contenente i report di Snyk

**Classe Java**
- `src/main/java/controller/RunSnykCommand.java`



&nbsp;

### Fase 6 
Classe Java che parsa il contenuto dei report generati precedentemente.

**Input**
-`Constants.REPORT_RESULTS/pmd`: reports di PMD;
-`Constants.REPORT_RESULTS/snyk`: reports di Snyk;
-`Constants.REPORT_RESULTS/vcg`: reports di VCG;
-`Constants.MAPPING_CWE_PMD`: file di mapping rule-key su CWE di PMD;
-`Constants.MAPPING_CWE_SNYK`: file di mapping rule-key su CWE di SNYK.

**Output**
-`Constants.PATH_VCG_PARSING_REPORT`: file di output parsato per VCG;
-`Constants.PATH_PMD_PARSING_REPORT`: file di output parsato per PMD;
-`Constants.PATH_SNYK_PARSING_REPORT`: file di output parsato per Snyk.

**Classe Java**
- `src/main/java/controller/ParsingTool.java`



&nbsp;
### Fase 7
Questa classe Java crea il risultato finale confrontando l'Intermediate result che contiene i valori Actual dei CWE con i report parsati che contenono i valori Expectedi dei CWE. Vengono confrontati i metodi delle classi analizzate.

**Input**
-`Constants.INTERMEDIATE_PATH_RESULT`: itermediate result;
-`Constants.PATH_SNYK_PARSING_REPORT`: parsing fase precedente per Snyk;
-`Constants.PATH_VCG_PARSING_REPORT`: parsing fase precedente per VCG;
-`Constants.PATH_PMD_PARSING_REPORT`: parsing fase precedente per PMD;
-`Constants.MAPPING_CWE_PMD`: file di mapping rule-key su CWE di PMD.
-`Constants.MAPPING_CWE_SNYK`: file di mapping rule-key su CWE di SNYK.


**Output**
-`PATH_FINAL_RESULT/resultPMD.csv`: file di output finale per PMD;
-`PATH_FINAL_RESULT/resultVCG.csv`: file di output finale per VCG;
-`PATH_FINAL_RESULT/resultSNYK.csv`: file di output finale per Snyk.

**Classe Java**
- `src/main/java/controller/CreateFinalDataset.java`


&nbsp;

### Fase 8
Il seguente script produce in output i file EAM. 

**Prerequisiti**
 - file di input da inserire allo stesso livello dell'eseguibile, contiene le informazioni risultanti dal tool PMD: 
 - file di input da inserire allo stesso livello dell'eseguibile, contiene le informazioni risultanti dal tool SNYK: 
 - file di input da inserire allo stesso livello dell'eseguibile, contiene le informazioni risultanti dal tool VCG: 

**Input**
-`PATH_FINAL_RESULT/resultPMD.csv`: file di output finale per PMD;
-`PATH_FINAL_RESULT/resultVCG.csv`: file di output finale per VCG;
-`PATH_FINAL_RESULT/resultSNYK.csv`: file di output finale per Snyk.

**Script**
- `/CreateEAMfiles/create_EAM_files.py`

**Run**
-  `python create_EAM_files.py `
