# RQ1_Distribuzione

## Prerequisiti
 - Python>= 3.7

## Alberatura delle directory
### Directory di Input

- `Input_no_filtered` questa directory contiene i seguenti files
  
  	- `mapping_cve_cwe.csv`: risultato del mapping tra i CVE e i CWE, formato dalle Coppie [CVE, CWE]
  	- `vulas_db_msr2019_release.csv`: dataset di input composto dalle triple [cve, repository_url, commit, class]

&nbsp;
- `Input_filtered` questa directory contiene i seguenti files:
  	- `mapping_cve_cwe.csv`: risultato del mapping tra i CVE e i CWE, formato dalle Coppie [CVE, CWE]
  	- `vulas_db_without_invalid_cve.csv`: generato filtrando dal dataset di input (`vulas_db_msr2019_release.csv`) tutti quei i progetti che non hanno un repository url 						    valido. 
	
&nbsp;

### Directory di Output
- `Output_filtered` questa directory contiene i seguenti due files:
	- `RQ1_filtered_freq_cwe_project.csv`: contiene le triple [CWE;Project Name;Frequency;Owner]. 
	- `RQ1_stats_filtered.txt`: contiene le seguenti metriche riferenti al file precedente:
		- Mediana
		- Numero di volte in cui compare la mediana
		- Media
 		- Moda
		- Varianza
&nbsp;
- `Output_no_filtered` questa directory contiene i seguenti files:
	- `RQ1_no_filtered_freq_cwe_project.csv`: [CWE;Project Name;Frequency;Owner]. 
	- `RQ1_stats_no_filtered.txt`: contenente le metriche descritte per la directory precedente(Output_filtered)




## Esecuzione scripts

1. Per creare il file mapping_cve_cwe.csv eseguire il seguente script. In input passare l'API Key richiedibile sul sito del [Nist.](https://nvd.nist.gov/developers/request-an-api-key).

Comando:

	`python create_mapping_cve_cwe.py --apikey [API Key]`

&nbsp;

2. Il seguente script prende i dati dalle cartelle di Input e produce i risultati nelle cartelle di Output. Le frequenze ottenute nei files `RQ1_filtered_freq_cwe_project.csv` e `RQ1_no_filtered_freq_cwe_project.csv` contano il numero di coppie univoche [CWE;Project Name] utilizzando come input rispettivamente `vulas_db_without_invalid_cve.csv` e 
`vulas_db_msr2019_release.csv`.

Comando:

	`python calculate_frequency.py`

  


